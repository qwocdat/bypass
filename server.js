/**
 * DIGITALSMOD Link Bypass — Backend (v2.2 Production)
 * Node.js + Express
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
 * CẤU HÌNH
 * ========================================================= */
const CONFIG = {
  REQUEST_TIMEOUT_MS: parseInt(process.env.REQUEST_TIMEOUT_MS || '12000', 10),
  MAX_REDIRECTS: parseInt(process.env.MAX_REDIRECTS || '8', 10),
  MAX_RESPONSE_BYTES: parseInt(process.env.MAX_RESPONSE_BYTES || String(512 * 1024), 10),
  USER_AGENT:
    process.env.USER_AGENT ||
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36',
  ALLOWED_PROTOCOLS: ['http:', 'https:'],
  RATE_LIMIT_WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10),
  RATE_LIMIT_MAX: parseInt(process.env.RATE_LIMIT_MAX || '30', 10),
  TRUST_PROXY: process.env.TRUST_PROXY === 'true',
};

if (CONFIG.TRUST_PROXY) app.set('trust proxy', 1);

/* =========================================================
 * MIDDLEWARE & CORS
 * ========================================================= */
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '16kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Request ID & Logging
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
 * REGEX & DOMAIN SUPPORT
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

const LINK4M_HOST_REGEX = /(^|\.)link4m\.(com|net|co|org)$/i;

/* =========================================================
 * SSRF PROTECTION
 * ========================================================= */
function isPrivateIPv4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(Number.isNaN)) return true;
  const [a, b] = parts;
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

function isPrivateIPv6(ip) {
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('fe80')) return true;
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
 * VALIDATION & FETCH
 * ========================================================= */
function validateUrl(raw) {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 2048) {
    throw new Error('URL không hợp lệ hoặc quá dài');
  }
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error('Định dạng URL không hợp lệ (cần bao gồm https://)');
  }
  if (!CONFIG.ALLOWED_PROTOCOLS.includes(parsed.protocol)) {
    throw new Error('Chỉ chấp nhận giao thức http hoặc https');
  }
  return parsed;
}

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
          try { await reader.cancel(); } catch { /* ignore */ }
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
 * EXTRACTION & DETECTION
 * ========================================================= */
function extractCandidateDestination(html, baseUrl) {
  if (!html || typeof html !== 'string') return null;

  const candidates = [];

  const metaMatch = html.match(/<meta[^>]+http-equiv=["']refresh["'][^>]+content=["'][^"']*url=([^"'\s>]+)/i);
  if (metaMatch) candidates.push(metaMatch[1]);

  const jsPatterns = [
    /(?:var|let|const)\s+(?:url|link|destination|target|redirect)\s*=\s*["']([^"']+)["']/gi,
    /["'](?:destination|target|redirect|url|link)["']\s*:\s*["']([^"']+)["']/gi,
    /window\.location(?:\.href)?\s*=\s*["']([^"']+)["']/gi,
    /location\.replace\(\s*["']([^"']+)["']\s*\)/gi,
  ];
  for (const re of jsPatterns) {
    for (const m of html.matchAll(re)) candidates.push(m[1]);
  }

  const base64Matches = html.matchAll(/aHR0cHM6Ly[a-zA-Z0-9+/=]+/g);
  for (const m of base64Matches) {
    try {
      const decoded = Buffer.from(m[0], 'base64').toString('utf-8');
      if (decoded.startsWith('http://') || decoded.startsWith('https://')) {
        candidates.push(decoded);
      }
    } catch { /* ignore */ }
  }

  const base = new URL(baseUrl);
  for (const raw of candidates) {
    try {
      const u = new URL(raw, base);
      if (!CONFIG.ALLOWED_PROTOCOLS.includes(u.protocol)) continue;
      if (LINK4M_HOST_REGEX.test(u.hostname)) continue;
      if (/\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf)$/i.test(u.pathname)) continue;
      if (/google|gstatic|doubleclick|facebook|cloudflare/i.test(u.hostname)) continue;
      return u.toString();
    } catch { /* ignore */ }
  }
  return null;
}

function detectVerification(html, headers, status) {
  const signals = [];
  const text = (html || '').toLowerCase();

  if (status === 403 || status === 429) signals.push(`HTTP ${status} (Forbidden/Rate Limit)`);
  if (headers['cf-mitigated'] || (headers['server'] || '').includes('cloudflare')) {
    if (text.includes('cf-challenge') || text.includes('just a moment')) signals.push('Cloudflare Challenge');
  }
  if (text.includes('g-recaptcha') || text.includes('hcaptcha') || text.includes('turnstile')) {
    signals.push('CAPTCHA / Turnstile Verification');
  }
  if (text.includes('cf-chl-') || text.includes('__cf_chl')) signals.push('Cloudflare JS Challenge');
  if (text.includes('please wait') && text.includes('redirect')) signals.push('Trang chờ đếm ngược JS');
  if (text.includes('verify you are human') || text.includes('are you a robot')) signals.push('Xác minh người dùng');

  return signals;
}

/* =========================================================
 * LINK4M HANDLER
 * ========================================================= */
async function link4mHandler(parsedUrl, log) {
  const urlStr = parsedUrl.toString();
  log(`Bắt đầu phân tích link4m: ${urlStr}`);

  const visited = new Set();
  let current = urlStr;

  for (let i = 0; i < CONFIG.MAX_REDIRECTS; i++) {
    if (visited.has(current)) {
      log('Cảnh báo: Phát hiện vòng lặp Redirect.');
      break;
    }
    visited.add(current);

    const u = new URL(current);
    await assertSafeHostname(u.hostname);

    log(`[Bước ${i + 1}] Request GET -> ${current}`);
    let res;
    try {
      res = await safeFetch(current, { method: 'GET', redirect: 'manual' });
    } catch (err) {
      log(`Lỗi kết nối HTTP: ${err.message}`);
      return { success: false, reason: `Không thể truy cập máy chủ: ${err.message}` };
    }
    log(`[Bước ${i + 1}] Mã phản hồi: HTTP ${res.status}`);

    if ([301, 302, 303, 307, 308].includes(res.status) && res.headers.location) {
      let nextUrl;
      try {
        nextUrl = new URL(res.headers.location, current).toString();
      } catch {
        log('Lỗi: Header Location không hợp lệ');
        break;
      }
      log(`[Bước ${i + 1}] Nhận Redirect -> ${nextUrl}`);

      const nextHost = new URL(nextUrl).hostname.toLowerCase();
      if (!LINK4M_HOST_REGEX.test(nextHost)) {
        log(`Thành công: Redirect ra ngoài shortener -> ${nextUrl}`);
        return { success: true, destination: nextUrl };
      }
      current = nextUrl;
      continue;
    }

    const signals = detectVerification(res.body, res.headers, res.status);
    if (signals.length > 0) {
      log(`Phát hiện bảo vệ: ${signals.join(' | ')}`);
    }

    const candidate = extractCandidateDestination(res.body, current);
    if (candidate) {
      log(`Thành công: Tìm thấy URL gốc -> ${candidate}`);
      return { success: true, destination: candidate };
    }

    if (signals.length > 0) {
      return {
        success: false,
        reason: `Link yêu cầu xác minh máy chủ/người dùng: ${signals.join('; ')}. Không thể xử lý tự động.`,
      };
    }

    return {
      success: false,
      reason: 'Không tìm thấy URL đích công khai trong phản hồi HTML. Trang yêu cầu JavaScript/xác minh động.',
    };
  }

  return { success: false, reason: 'Vượt quá số lượt Redirect cho phép mà không xác định được link gốc.' };
}

/* =========================================================
 * ENDPOINTS
 * ========================================================= */
const HANDLERS = { link4m: link4mHandler };

app.post('/api/bypass', bypassLimiter, async (req, res) => {
  const logs = [];
  const log = (msg) => logs.push(`[${new Date().toLocaleTimeString()}] ${msg}`);

  try {
    const { url } = req.body || {};
    if (!url) {
      log('Lỗi: Dữ liệu URL đầu vào rỗng.');
      return res.status(400).json({ success: false, reason: 'Vui lòng nhập URL cần xử lý.', logs, requestId: req.id });
    }

    log(`Nhận yêu cầu: ${url}`);
    const parsed = validateUrl(url);

    const hostname = parsed.hostname.toLowerCase();
    let handlerKey = SUPPORTED_HOSTS[hostname] || SUPPORTED_HOSTS[hostname.replace(/^www\./, '')];
    if (!handlerKey && LINK4M_HOST_REGEX.test(hostname)) {
      handlerKey = 'link4m';
    }

    if (!handlerKey) {
      log(`Tên miền "${parsed.hostname}" chưa được hỗ trợ.`);
      return res.status(400).json({
        success: false,
        reason: `Domain "${parsed.hostname}" chưa được hỗ trợ.`,
        logs,
        requestId: req.id,
      });
    }

    const handler = HANDLERS[handlerKey];
    const result = await handler(parsed, log);
    log(result.success ? `XỬ LÝ HOÀN TẤT: ${result.destination}` : `KẾT QUẢ: ${result.reason}`);

    return res.json({ ...result, logs, requestId: req.id });
  } catch (err) {
    log(`LỖI HỆ THỐNG: ${err.message}`);
    return res.status(400).json({ success: false, reason: err.message || 'Lỗi không xác định', logs, requestId: req.id });
  }
});

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, uptimeSeconds: process.uptime(), hosts: Object.keys(SUPPORTED_HOSTS) });
});

app.use('/api', (_req, res) => {
  res.status(404).json({ success: false, reason: 'Endpoint API không tồn tại.' });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`DIGITALSMOD Backend running at http://localhost:${PORT}`);
  });
}

module.exports = app;
