# BurnLink

[![GitHub](https://img.shields.io/badge/GitHub-BurnLink-blue?logo=github)](https://github.com/paperfrogs-hq/BurnLink)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Live](https://img.shields.io/badge/Live-burnlink.page-brightgreen)](https://burnlink.page)
[![Changelog](https://img.shields.io/badge/Changelog-View-informational)](https://burnlink.page/changelog)
[![Roadmap](https://img.shields.io/badge/Roadmap-Planned-blue)](https://burnlink.page/roadmap)

BurnLink is an **open-source, privacy-first file sharing platform** with browser-side end-to-end encryption. Files are encrypted in your browser before ever leaving your device, and permanently deleted after the first download.

> **v1.1.1 – April 2026** | Now in production with improved sharing UX and self-hosting support.

---

## Table of Contents

- [Why BurnLink?](#why-burnlink)
- [Features](#features)
- [How It Works](#how-it-works)
- [Security Model](#security-model)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
- [Self-Hosting](#self-hosting)
- [Contributing](#contributing)
- [Support](#support)

---

## Why BurnLink?

**For Users:** Stop worrying about file sharing security. With browser-side encryption and one-time access, you control exactly how your files are delivered and destroyed.

**For Teams:** Deploy BurnLink on your own infrastructure for private, encrypted file sharing without corporate intermediaries. Your data stays yours.

**For Developers:** Open source, auditable, and built with modern web standards. Fork it, understand it, modify it.

---

## Features

### 🔒 Security First
- **Browser-Side E2E Encryption** — Files are encrypted client-side using AES-256-GCM before upload. The server never sees plaintext data.
- **Two Sharing Modes**
  - **Password-protected** — Recipient enters a password to decrypt the file
  - **Link-key** — Decryption key is embedded in the URL fragment (never sent to server)
- **One-Time Links** — Files are permanently destroyed after the first successful download
- **Brute-Force Protection** — 10-minute lockout after 3 failed password attempts
- **View-Once Mode** — File is viewable for 60 seconds, then burned regardless of download status

### 🎯 Developer-Friendly
- **Up to 1 GB** file size support (configurable)
- **Presigned URLs** — Direct client-to-storage transfers via Cloudflare R2
- **RESTful API** — Clean endpoints for upload, link management, and metadata
- **Rate Limiting** — Built-in protection against abuse and attacks

### 📱 User Experience
- **Clean, Minimal UI** — Responsive design across all devices
- **Drag-and-Drop** — Simple file upload with progress tracking
- **QR Codes** — Generate QR codes for instant link sharing
- **Copy-to-Clipboard** — One-click link sharing with toast feedback
- **Mobile-Responsive** — Works seamlessly on phones, tablets, and desktops

---

## How It Works

```
1. Upload          → You select a file and optionally set a password
2. Encrypt         → File is encrypted entirely in your browser (AES-256-GCM)
3. Store           → Encrypted payload goes to Cloudflare R2; metadata to Supabase
4. Share           → You get a one-time shareable link with unique token
5. Download        → Recipient decrypts in their browser, file is permanently destroyed
```

**Data Flow Diagram:**
```
User Browser                  BurnLink Server               Storage
   │                               │                           │
   ├─ Encrypt File ──────────────►│                           │
   │                               │─ Store Encrypted Data ──►│ Cloudflare R2
   │                               │─ Store Metadata ────────► Supabase
   │                               │
   │ Generate Link ◄──────────────│
   │   & Token                    │
   │
   └─ Share Link                  │
         (with recipient)          │
              │                    │
              └─ Recipient ──────►│ Verify Token & Burn Link
                  Downloads       │─ Delete Metadata
                                  │
                               ┌──┴─► Delete Encrypted File
```

---

## Security Model

### What We Protect
- **File Confidentiality** — Encrypted end-to-end; server cannot read plaintext
- **Access Control** — One-time tokens prevent unauthorized access
- **Integrity** — AES-256-GCM includes authentication (AEAD cipher)
- **Replay Protection** — Links burn after first access; tokens become invalid

### Encryption Details
- **Algorithm** — AES-256-GCM (Authenticated Encryption with Associated Data)
- **Key Derivation** — PBKDF2 with 210,000 iterations
- **Password Salt** — Randomly generated per upload
- **Nonce** — Unique per encryption operation

### What We Don't Protect
- **Metadata** — We store encrypted file size, MIME type, and upload timestamp
- **Access Patterns** — We can see when files are downloaded (no analytics, just logs)
- **Log Data** — Server logs include IP addresses for security auditing

### Best Practices
1. **Always use passwords** for sensitive files
2. **Share links securely** — Use Signal, WhatsApp, or in-person
3. **Verify identities** — Confirm the recipient before sharing
4. **Review public pages** — Check our [Security Policy](https://burnlink.page/security-policy) for full details

---

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Frontend** | Vanilla JS + HTML/CSS | No tracking, minimal dependencies |
| **Backend** | Node.js + Express | Lightweight, production-ready |
| **Templating** | EJS | Dynamic server-side rendering |
| **Database** | Supabase (PostgreSQL) | Metadata storage, user sessions |
| **Storage** | Cloudflare R2 | S3-compatible, encrypted files |
| **Encryption** | Web Crypto API | Native browser crypto (AES-256-GCM) |
| **Deployment** | Netlify Functions | Serverless, auto-scaling |

---

## Getting Started

### Prerequisites
- **Node.js** 18+ and npm/yarn
- **Supabase account** (free tier works)
- **Cloudflare R2 account** (free tier works)

### Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/paperfrogs-hq/BurnLink.git
   cd BurnLink
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables** (copy `.env.example` to `.env`)
   ```bash
   cp .env.example .env
   ```
   Fill in your Supabase and Cloudflare credentials.

4. **Start the development server**
   ```bash
   npm run dev
   ```
   Open `http://localhost:3000` in your browser.

5. **Run tests** (optional)
   ```bash
   npm test
   ```

### Environment Variables

See [SELFHOST.md](./SELFHOST.md) for detailed setup instructions and all available environment variables.

---

## Self-Hosting

Want to run BurnLink on your own infrastructure? We support early adopters with a dedicated self-hosting guide.

**See [SELFHOST.md](./SELFHOST.md)** for complete instructions on:
- Local setup and configuration
- Deployment to Netlify, Vercel, or your own server
- Database and storage configuration
- Running in production
- Troubleshooting common issues

---

## Contributing

We welcome contributions! Whether it's bug fixes, features, or documentation:

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/your-feature`)
3. **Commit your changes** with clear messages
4. **Push to your fork** and open a pull request

For significant changes, please open an issue first to discuss your approach.

---

## Support

### Getting Help
- **Issues & Bugs** — [Open an issue](https://github.com/paperfrogs-hq/BurnLink/issues)
- **Feature Requests** — [Request a feature](https://burnlink.page/roadmap)
- **Security Issues** — [Report privately](./SECURITY.md)
- **Questions** — [Email us](mailto:hello@paperfrogs.dev?subject=BurnLink%20Question)

### Find Out What's Next
- **Changelog** — [View release history](https://burnlink.page/changelog)
- **Roadmap** — [See planned features](https://burnlink.page/roadmap)

---

## License

BurnLink is released under the **MIT License**. See [LICENSE](./LICENSE) for details.

---

## About

BurnLink is a product of **[Paperfrogs](https://paperfrogs.dev)** — an infrastructure-first studio building research-driven, production-ready tools for privacy, security, and developer experience.

**Questions about the project?** Email [hello@paperfrogs.dev](mailto:hello@paperfrogs.dev).
