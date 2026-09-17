# link-bypass

Backend Node.js/Express theo dõi redirect chain của các trang rút gọn link
(hiện hỗ trợ **link4m**: `.com`, `.net`, `.co`, `.org`) và trả về URL đích nếu
trang công khai nó qua redirect HTTP hoặc trong HTML (`meta refresh`,
`<link rel="canonical">`, biến JS, thẻ `<a>`...).

**Giới hạn có chủ đích:** không giải CAPTCHA, không chạy JavaScript của trang
đích, không đánh cắp cookie/session, không giả lập kết quả. Nếu trang yêu cầu
xác minh (Cloudflare challenge, CAPTCHA, "please wait" đếm ngược...), API trả
về `success: false` kèm lý do cụ thể.

## Tính năng

- Chống SSRF: chặn localhost, IP private (RFC1918), link-local, CGNAT, IP
  metadata cloud (169.254.169.254), cả khi hostname phân giải gián tiếp qua DNS.
- Timeout + giới hạn kích thước response cho mỗi request ra ngoài.
- Theo dõi redirect chain thủ công (`redirect: 'manual'`), tối đa N hop.
- Rate limit theo IP trên endpoint `/api/bypass`.
- Helmet (security headers) + CORS whitelist theo biến môi trường.
- Structured JSON access log, request ID theo mỗi request.
- Frontend tối giản (`public/index.html`) — không bắt buộc, có thể bỏ qua và
  chỉ gọi API trực tiếp.
- Kiến trúc handler theo registry (`HANDLERS`), dễ thêm shortener khác.

## Chạy local

```bash
npm install
cp .env.example .env   # chỉnh nếu cần
npm start               # hoặc: npm run dev (auto-reload)
```

Mở `http://localhost:3000` để dùng UI, hoặc gọi trực tiếp:

```bash
curl -X POST http://localhost:3000/api/bypass \
  -H "Content-Type: application/json" \
  -d '{"url":"https://link4m.com/xxxxx"}'
```

Response mẫu:

```json
{
  "success": true,
  "destination": "https://example.com/real-target",
  "logs": ["[2026-01-01T00:00:00.000Z] Nhận yêu cầu bypass: ...", "..."],
  "requestId": "..."
}
```

Nếu không xác định được đích:

```json
{
  "success": false,
  "reason": "Link này yêu cầu xác minh phía máy chủ hoặc tương tác người dùng...",
  "logs": ["..."]
}
```

## Biến môi trường

Xem `.env.example` — tất cả có giá trị mặc định hợp lý, không bắt buộc phải
đặt gì để chạy local.

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `PORT` | `3000` | Cổng server |
| `REQUEST_TIMEOUT_MS` | `12000` | Timeout mỗi request ra ngoài |
| `MAX_REDIRECTS` | `8` | Số hop redirect tối đa |
| `MAX_RESPONSE_BYTES` | `524288` | Giới hạn đọc response body |
| `ALLOWED_ORIGINS` | `*` | Danh sách origin CORS, phân tách bằng `,` |
| `RATE_LIMIT_WINDOW_MS` | `60000` | Cửa sổ rate limit |
| `RATE_LIMIT_MAX` | `30` | Số request tối đa/cửa sổ/IP |
| `TRUST_PROXY` | `false` | Đặt `true` khi chạy sau reverse proxy |

## Test

```bash
npm test
```

Dùng `node --test`, không cần dependency thêm. Test bao gồm health check,
validate URL, và domain không được hỗ trợ. Test không phụ thuộc mạng thật.

## Deploy

### GitHub — quy trình chung

```bash
git init
git add .
git commit -m "link-bypass v2.0"
git branch -M main
git remote add origin https://github.com/<your-username>/link-bypass.git
git push -u origin main
```

`.github/workflows/ci.yml` sẽ tự chạy `npm ci && npm test` trên Node 18 và 20
ở mỗi push/PR vào `main`.

### Render / Railway / Fly.io (PaaS, khuyên dùng)

1. Kết nối repo GitHub với dịch vụ.
2. Build command: `npm install` — Start command: `npm start`.
3. Đặt biến môi trường từ `.env.example` trong dashboard (tối thiểu không cần
   sửa gì, mặc định đã chạy được).
4. Nếu dịch vụ chạy sau load balancer/proxy (hầu hết PaaS đều vậy), đặt
   `TRUST_PROXY=true` để rate limit đọc đúng IP client.

### Docker

```bash
docker build -t link-bypass .
docker run -p 3000:3000 --env-file .env link-bypass
```

Hoặc với `docker-compose`:

```yaml
services:
  link-bypass:
    build: .
    ports:
      - "3000:3000"
    env_file: .env
    restart: unless-stopped
```

### VPS thủ công (systemd)

```ini
# /etc/systemd/system/link-bypass.service
[Unit]
Description=link-bypass
After=network.target

[Service]
WorkingDirectory=/opt/link-bypass
ExecStart=/usr/bin/node server.js
EnvironmentFile=/opt/link-bypass/.env
Restart=always
User=www-data

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now link-bypass
```

Đặt Nginx/Caddy làm reverse proxy phía trước để có TLS; nhớ set
`TRUST_PROXY=true`.

## Mở rộng thêm shortener khác

1. Thêm domain vào `SUPPORTED_HOSTS` (map sang một `handlerKey`).
2. Viết hàm handler theo chữ ký `async function xHandler(parsedUrl, log)`
   trả về `{ success, destination }` hoặc `{ success: false, reason }`.
3. Đăng ký handler trong `HANDLERS`.

Giữ nguyên nguyên tắc: chỉ đọc những gì server công khai qua HTTP/HTML, không
giả lập trình duyệt đầy đủ, không giải captcha, không chiếm cookie người dùng.

## Giấy phép

MIT — xem `LICENSE`.
