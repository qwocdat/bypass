/**
 * DIGITALSMOD Link Bypass — Backend
 * Node.js + Express
 *
 * Nhiệm vụ:
 * - Nhận URL từ frontend qua POST /api/bypass
 * - Kiểm tra URL (chỉ HTTP/HTTPS, chặn SSRF: localhost, private IP, metadata IP)
 * - Gửi HTTP request có timeout + giới hạn kích thước response
 * - Theo dõi redirect chain (manual redirect)
 * - Trả về URL đích nếu xác định được
 * - Nếu gặp cơ chế xác minh (JS challenge, cookie, captcha...) → báo rõ không thể bypass
 *
 * LƯU Ý: Backend này KHÔNG giải CAPTCHA, KHÔNG đánh cắp cookie/session,
 * KHÔNG giả lập kết quả. Nó chỉ thực hiện các bước HTTP hợp lệ.
 *
 * v2.1 — Production-ready (Fixed Domain Matching & Base64 Extractor):
 * - Helmet security headers, CORS whitelist, rate limiting
 * - Toàn bộ tham số cấu hình qua biến môi trường (.env)
 * - Structured JSON logging, request IDs
 * - Graceful shutdown, health/readiness endpoints
 * - Handler registry vẫn dễ mở rộng thêm shortener khác
 */

require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');
const dns = require('dns').promises;
const net = require('net');

const app = express();
const PORT = parseInt(process.env.PORT || '3000', 10);

/* =========================================================
 * CẤU HÌNH (đọc từ biến môi trường, có giá trị mặc định)
 * ========================================================= */
const CONFIG = {
  REQUEST_TIMEOUT_MS: parseInt(process.env.REQUEST_TIMEOUT_MS || '12000', 10),
  MAX_REDIRECTS: parseInt(process.env.MAX_REDIRECTS || '8', 10),
  MAX_RESPONSE_BYTES: parseInt(process.env.MAX_RESPONSE_BYTES || String(512 * 1024), 10),
  USER_AGENT:
    process.env.USER_AGENT ||
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
      '(KHTML, like Gecko) Chrome/122.0 Safari/537.36',
  ALLOWED_PROTOCOLS: ['http:', 'https:'],
  ALLOWED_ORIGINS: (process.env.ALLOWED_ORIGINS || '*')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),
  RATE_LIMIT_WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10),
  RATE_LIMIT_MAX: parseInt(process.env.RATE_LIMIT_MAX || '30', 10),
  TRUST_PROXY: process.env.TRUST_PROXY === 'true',
};

if (CONFIG.TRUST_PROXY) app.set('trust proxy', 1);

/* =========================================================
 * MIDDLEWARE
 * ========================================================= */
app.use(helmet());
app.use(
  cors({
    origin: CONFIG.ALLOWED_ORIGINS.includes('*') ? true : CONFIG.ALLOWED_ORIGINS,
    credentials: true,
  })
);
app.use(express.json({ limit: '16kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Request ID + structured access log
app.use((req, res, next) => {
  req.id = crypto.randomUUID();
  const start = Date.now();
  res.on('finish', () => {
    console.log(
      JSON.stringify({
        ts: new Date().toISOString(),
        id: req.id,
        method: req.method,
        path: req.path,
        status: res.statusCode,
        ms: Date.now() - start,
      })
    );
  });
  next();
});

const bypassLimiter = rateLimit({
  windowMs: CONFIG.RATE_LIMIT_WINDOW_MS,
  max: CONFIG.RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, reason: 'Quá nhiều yêu cầu, vui lòng thử lại sau.' },
});

/* =========================================================
 * DANH SÁCH SHORTENER HỖ TRỢ
 * Link4m hỗ trợ linh hoạt các TLD thông qua Regex
 * ========================================================= */
const SUPPORTED_HOSTS = {
  'link4m.com': 'link4m',
  'link4m.net': 'link4m',
  'link4m.co': 'link4m',
  'link4m.org': 'link4m',
  'www.link4m.com': 'link4m',
  'www.link4m.net': 'link4m',
  'www.link4m.co': 'link4m',
  'www.link4m.org': 'link4m',
};

// FIX 1: Regex bắt chuẩn mọi subdomain & TLD của Link4m
const LINK4M_HOST_REGEX = /(^|\.)link4m\.(com|net|co|org)$/i;

/* =========================================================
 * SSRF PROTECTION
 * ========================================================= */
function isPrivateIPv4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(Number.isNaN)) return true;
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

function isPrivateIPv6(ip) {
  const lower = ip.toLowerCase();
  if (lower === '::1') return true;
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
  if (lower.startsWith('fe80')) return true;
  if (lower.startsWith('::ffff:')) return isPrivateIPv4(lower.substring(7));
  return false;
}

async function assertSafeHostname(hostname) {
  if (net.isIP(hostname)) {
    const isV4 = net.isIPv4(hostname);
    if (isV4 && isPrivateIPv4(hostname)) throw new Error('Chặn địa chỉ IP nội bộ');
    if (!isV4 && isPrivateIPv6(hostname)) throw new Error('Chặn địa chỉ IPv6 nội bộ');
    return;
  }
  const records = await dns.lookup(hostname, { all: true });
  for (const rec of records) {
    if (rec.family === 4 && isPrivateIPv4(rec.address)) {
      throw new Error('Hostname phân giải về IP nội bộ');
    }
    if (rec.family === 6 && isPrivateIPv6(rec.address)) {
      throw new Error('Hostname phân giải về IPv6 nội bộ');
    }
  }
}

/* =========================================================
 * VALIDATE URL
 * ========================================================= */
function validateUrl(raw) {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 2048) {
    throw new Error('URL không hợp lệ hoặc quá dài');
  }
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error('Không parse được URL');
  }
  if (!CONFIG.ALLOWED_PROTOCOLS.includes(parsed.protocol)) {
    throw new Error('Chỉ chấp nhận http/https');
  }
  return parsed;
}

/* =========================================================
 * FETCH CÓ TIMEOUT + GIỚI HẠN RESPONSE
 * ========================================================= */
async function safeFetch(url, { method = 'GET', redirect = 'manual' } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CONFIG.REQUEST_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method,
      redirect,
      signal: controller.signal,
      headers: {
        'User-Agent': CONFIG.USER_AGENT,
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
      },
    });

    let body = '';
    const reader = res.body && res.body.getReader ? res.body.getReader() : null;
    if (reader) {
      const decoder = new TextDecoder('utf-8', { fatal: false });
      let received = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.length;
        body += decoder.decode(value, { stream: true });
        if (received >= CONFIG.MAX_RESPONSE_BYTES) {
          try {
            await reader.cancel();
          } catch {
            /* ignore */
          }
          break;
        }
      }
      body += decoder.decode();
    } else {
      body = await res.text();
      if (body.length > CONFIG.MAX_RESPONSE_BYTES) {
        body = body.slice(0, CONFIG.MAX_RESPONSE_BYTES);
      }
    }

    return {
      status: res.status,
      headers: Object.fromEntries(res.headers.entries()),
      body,
      finalUrl: res.url,
    };
  } finally {
    clearTimeout(timer);
  }
}

/* =========================================================
 * PHÂN TÍCH TRANG LINK4M (FIX 2: Thêm quét Base64 & Query Target)
 * ========================================================= */
function extractCandidateDestination(html, baseUrl) {
  if (!html || typeof html !== 'string') return null;

  const candidates = [];

  const metaMatch = html.match(
    /<meta[^>]+http-equiv=["']refresh["'][^>]+content=["'][^"']*url=([^"'\s>]+)/i
  );
  if (metaMatch) candidates.push(metaMatch[1]);

  const linkMatches = html.matchAll(
    /<link[^>]+rel=["'](?:canonical|alternate)["'][^>]+href=["']([^"']+)["']/gi
  );
  for (const m of linkMatches) candidates.push(m[1]);

  const jsPatterns = [
    /(?:var|let|const)\s+(?:url|link|destination|target|redirect)\s*=\s*["']([^"']+)["']/gi,
    /["'](?:destination|target|redirect|url|link)["']\s*:\s*["']([^"']+)["']/gi,
    /window\.location(?:\.href)?\s*=\s*["']([^"']+)["']/gi,
    /location\.replace\(\s*["']([^"']+)["']\s*\)/gi,
  ];
  for (const re of jsPatterns) {
    for (const m of html.matchAll(re)) candidates.push(m[1]);
  }

  // Quét các chuỗi Base64 URL nhúng trực tiếp trong Javascript/HTML
  const base64Matches = html.matchAll(/aHR0cHM6Ly[a-zA-Z0-9+/=]+/g);
  for (const m of base64Matches) {
    try {
      const decoded = Buffer.from(m[0], 'base64').toString('utf-8');
      if (decoded.startsWith('http://') || decoded.startsWith('https://')) {
        candidates.push(decoded);
      }
    } catch {
      /* ignore */
    }
  }

  const anchorMatches = html.matchAll(/<a[^>]+href=["']([^"']+)["']/gi);
  for (const m of anchorMatches) candidates.push(m[1]);

  const base = new URL(baseUrl);
  for (const raw of candidates) {
    try {
      const u = new URL(raw, base);
      if (!CONFIG.ALLOWED_PROTOCOLS.includes(u.protocol)) continue;
      if (LINK4M_HOST_REGEX.test(u.hostname)) continue;
      if (/\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf)$/i.test(u.pathname)) continue;
      if (/google|gstatic|doubleclick|facebook|cloudflare/i.test(u.hostname)) continue;
      return u.toString();
    } catch {
      /* ignore */
    }
  }
  return null;
}

/* =========================================================
 * PHÁT HIỆN CƠ CHẾ XÁC MINH ("phát hiện trạng thái", KHÔNG bypass)
 * ========================================================= */
function detectVerification(html, headers, status) {
  const signals = [];
  const text = (html || '').toLowerCase();

  if (status === 403 || status === 429) {
    signals.push(`Server trả về HTTP ${status} (rate limit / forbidden)`);
  }
  if (headers['cf-mitigated'] || (headers['server'] || '').includes('cloudflare')) {
    if (text.includes('cf-challenge') || text.includes('just a moment')) {
      signals.push('Cloudflare challenge');
    }
  }
  if (text.includes('g-recaptcha') || text.includes('hcaptcha') || text.includes('turnstile')) {
    signals.push('CAPTCHA (reCAPTCHA/hCaptcha/Turnstile)');
  }
  if (text.includes('cf-chl-') || text.includes('__cf_chl')) {
    signals.push('Cloudflare JS challenge');
  }
  if (text.includes('please wait') && text.includes('redirect')) {
    signals.push('Trang "please wait" — cần JS đếm ngược');
  }
  if (text.includes('verify you are human') || text.includes('are you a robot')) {
    signals.push('Xác minh người dùng');
  }
  if (text.includes('adblock')) {
    signals.push('Yêu cầu tắt AdBlock');
  }
  if (headers['set-cookie'] && /__cf|session|token/i.test(headers['set-cookie'])) {
    signals.push('Server set cookie phiên (chỉ ghi nhận, không sử dụng)');
  }

  return signals;
}

/* =========================================================
 * LINK4M HANDLER
 * ========================================================= */
async function link4mHandler(parsedUrl, log) {
  const urlStr = parsedUrl.toString();
  log(`Handler: link4m — bắt đầu xử lý ${urlStr}`);

  const visited = new Set();
  let current = urlStr;

  for (let i = 0; i < CONFIG.MAX_REDIRECTS; i++) {
    if (visited.has(current)) {
      log('Phát hiện vòng lặp redirect');
      break;
    }
    visited.add(current);

    const u = new URL(current);
    await assertSafeHostname(u.hostname);

    log(`[${i + 1}] GET ${current}`);
    let res;
    try {
      res = await safeFetch(current, { method: 'GET', redirect: 'manual' });
    } catch (err) {
      log(`Lỗi request: ${err.message}`);
      return { success: false, reason: `Không thể kết nối: ${err.message}` };
    }
    log(`→ HTTP ${res.status}`);

    if ([301, 302, 303, 307, 308].includes(res.status) && res.headers.location) {
      let nextUrl;
      try {
        nextUrl = new URL(res.headers.location, current).toString();
      } catch {
        log('Location header không hợp lệ');
        break;
      }
      log(`→ Redirect: ${nextUrl}`);

      const nextHost = new URL(nextUrl).hostname.toLowerCase();
      if (!LINK4M_HOST_REGEX.test(nextHost)) {
        log(`✓ Redirect ra ngoài shortener → đích: ${nextUrl}`);
        return { success: true, destination: nextUrl };
      }
      current = nextUrl;
      continue;
    }

    const signals = detectVerification(res.body, res.headers, res.status);
    if (signals.length > 0) {
      log(`⚠ Phát hiện cơ chế xác minh: ${signals.join(' | ')}`);
    }

    const candidate = extractCandidateDestination(res.body, current);
    if (candidate) {
      log(`✓ Tìm thấy URL đích công khai trong HTML: ${candidate}`);
      return { success: true, destination: candidate };
    }

    if (signals.length > 0) {
      return {
        success: false,
        reason:
          'Link này yêu cầu xác minh phía máy chủ hoặc tương tác người dùng. ' +
          'Không thể xử lý tự động. Chi tiết: ' +
          signals.join('; '),
      };
    }
    return {
      success: false,
      reason:
        'Không tìm thấy URL đích công khai trong response. ' +
        'Trang có thể cần JavaScript/tương tác người dùng để hiển thị đích.',
    };
  }

  return { success: false, reason: 'Vượt quá số redirect tối đa hoặc không xác định được đích.' };
}

/* =========================================================
 * REGISTRY HANDLER
 * ========================================================= */
const HANDLERS = {
  link4m: link4mHandler,
};

/* =========================================================
 * ENDPOINT: POST /api/bypass
 * ========================================================= */
app.post('/api/bypass', bypassLimiter, async (req, res) => {
  const logs = [];
  const log = (msg) => {
    const line = `[${new Date().toISOString()}] ${msg}`;
    logs.push(line);
  };

  try {
    const { url } = req.body || {};
    log(`Nhận yêu cầu bypass: ${url}`);

    const parsed = validateUrl(url);
    log(`URL hợp lệ: ${parsed.toString()}`);

    const hostname = parsed.hostname.toLowerCase();
    
    // FIX 3: Tìm Handler theo Regex nếu không khớp cứng trong SUPPORTED_HOSTS
    let handlerKey = SUPPORTED_HOSTS[hostname] || SUPPORTED_HOSTS[hostname.replace(/^www\./, '')];
    if (!handlerKey && LINK4M_HOST_REGEX.test(hostname)) {
      handlerKey = 'link4m';
    }

    if (!handlerKey) {
      log(`Domain không được hỗ trợ: ${parsed.hostname}`);
      return res.status(400).json({
        success: false,
        reason: `Domain "${parsed.hostname}" chưa được hỗ trợ.`,
        logs,
      });
    }

    log(`Chọn handler: ${handlerKey}`);
    const handler = HANDLERS[handlerKey];
    if (!handler) {
      return res.status(500).json({ success: false, reason: `Handler "${handlerKey}" chưa được cài đặt`, logs });
    }

    const result = await handler(parsed, log);
    log(result.success ? `KẾT QUẢ: ${result.destination}` : `THẤT BẠI: ${result.reason}`);

    return res.json({ ...result, logs, requestId: req.id });
  } catch (err) {
    log(`LỖI: ${err.message}`);
    return res.status(400).json({ success: false, reason: err.message || 'Lỗi không xác định', logs, requestId: req.id });
  }
});

/* Health / readiness */
app.get('/api/health', (_req, res) => {
  res.json({ ok: true, uptimeSeconds: process.uptime(), hosts: Object.keys(SUPPORTED_HOSTS) });
});

app.get('/api/version', (_req, res) => {
  const pkg = require('./package.json');
  res.json({ name: pkg.name, version: pkg.version });
});

// 404 fallback cho API routes
app.use('/api', (_req, res) => {
  res.status(404).json({ success: false, reason: 'Không tìm thấy endpoint' });
});

if (require.main === module) {
  const server = app.listen(PORT, () => {
    console.log(`DIGITALSMOD Link Bypass đang chạy tại http://localhost:${PORT}`);
  });

  /* Graceful shutdown */
  function shutdown(signal) {
    console.log(`Nhận ${signal}, đang tắt server...`);
    server.close(() => {
      console.log('Server đã tắt.');
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10000).unref();
  }
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

module.exports = app;
