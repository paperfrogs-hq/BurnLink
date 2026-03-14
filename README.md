# BurnLink

[![GitHub](https://img.shields.io/badge/GitHub-BurnLink-blue?logo=github)](https://github.com/Joy-Majumder/BurnLink)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Live](https://img.shields.io/badge/Live-burnlink.page-brightgreen)](https://burnlink.page)

BurnLink is an open-source, privacy-first file sharing platform with browser-side end-to-end encryption. Files are encrypted in your browser before ever leaving your device, and permanently deleted after the first download.

> Originally started in 2024 — now actively maintained and in production.

---

## Features

- **Browser-Side E2E Encryption** — Files are encrypted client-side using AES-256-GCM before upload. The server never sees plaintext.
- **Two Sharing Modes**
  - **Password-protected** — Recipient enters a password to decrypt
  - **Link-key** — Decryption key is embedded in the URL fragment (never sent to server)
- **One-Time Links** — Files are permanently destroyed after the first successful download
- **View-Once Mode** — File is viewable for 60 seconds, then burned regardless of download
- **Brute-Force Protection** — 10-minute lockout after 3 failed password attempts
- **Up to 1 GB** file size support
- **Presigned URLs** — Direct client-to-storage transfers via Cloudflare R2
- **Clean, minimal UI** — Responsive design, one-click link copy

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Node.js + Express |
| Templating | EJS |
| File Storage | Cloudflare R2 (S3-compatible) |
| Database / Metadata | Supabase (PostgreSQL) |
| Deployment | Netlify (Serverless Functions) |
| Encryption | Web Crypto API (AES-256-GCM, PBKDF2) |

---

## How It Works

1. **Upload** — Select a file and optionally set a password
2. **Encrypt** — File is encrypted entirely in your browser
3. **Store** — Encrypted payload is uploaded to Cloudflare R2; metadata goes to Supabase
4. **Share** — You get a one-time shareable link
5. **Download** — Recipient decrypts in their browser, then the file and link are permanently destroyed

---

## Security

- All encryption happens in the browser — the server never handles unencrypted data
- AES-256-GCM encryption with PBKDF2 key derivation (210,000 iterations)
- One-time download links prevent replay attacks
- View-once mode enforces a timed destruction window
- Content Security Policy (CSP) with per-request nonces
- `x-powered-by` header disabled
- Open source — fully auditable

---

## License

MIT © [Joy G. Majumdar](https://github.com/Joy-Majumder)

---

## Contributing

Contributions are welcome. Feel free to open issues and pull requests.

## Support

For issues or questions, [open an issue](https://github.com/Joy-Majumder/BurnLink/issues) on GitHub.

---

BurnLink is a product of [Paperfrogs/Open](https://paperfrogs.dev) — an infrastructure-first studio building research-driven, production-ready tools.
