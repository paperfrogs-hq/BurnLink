# BurnLink

[![GitHub](https://img.shields.io/badge/GitHub-BurnLink-blue?logo=github)](https://github.com/Joy-Majumder/BurnLink)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Live](https://img.shields.io/badge/Live-burnlink.page-brightgreen)](https://burnlink.page)

Secure, self-destructing file sharing for sensitive documents, credentials, and confidential data. Built with client-side encryption, zero-knowledge architecture, and **fully open source** for community audit and self-hosting.

**Version 1.2.0** — May 2026 | [MIT License](./LICENSE)

---

## Table of Contents

- [Why BurnLink](#why-burnlink)
- [Features](#features)
- [Security](#security)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [Support](#support)
- [License](#license)

## Why BurnLink

Most file sharing services store your files on their servers—sometimes permanently, often without end-to-end encryption. BurnLink operates on a different principle:

### Zero-Knowledge by Design
- **Files never exist unencrypted** — Encryption happens in your browser before upload
- **Server sees only encrypted data** — Even administrators cannot access file contents
- **No accounts required** — Share directly without creating profiles
- **Automatic deletion** — Files burn after the first download

### Transparency You Control
- **100% open source** — Full code available on GitHub for review and audit
- **Community-driven** — Contributions welcome from developers worldwide
- **No proprietary code** — Exactly what you see is what runs
- **Self-host anytime** — Deploy on your own infrastructure with no restrictions
- **No vendor lock-in** — Export data, switch servers, modify as needed

### Practical Security
- **Single-use links** — Each share link works only once
- **Password protection** — Optional additional layer
- **Expiration options** — Files auto-delete after 15 days
- **View-once mode** — Recipients have 60 seconds to access before deletion
- **Rate limiting and brute-force protection** — Built-in defense against attacks

### Use Cases
- Sharing credentials and API keys with team members
- Sending sensitive documents to clients or partners
- Exchanging confidential information securely
- Temporary file sharing with guaranteed cleanup
- Internal tools requiring high trust and auditability

### How BurnLink Compares

| Feature | BurnLink | WeTransfer | Google Drive | Email |
|---------|----------|-----------|-------------|-------|
| Client-side encryption | ✓ | ✗ | ✗ | ✗ |
| Zero-knowledge | ✓ | ✗ | ✗ | ✗ |
| Auto-delete on view | ✓ | ✗ | ✗ | ✗ |
| Single-use links | ✓ | ✗ | ✗ | ✗ |
| Open source | ✓ | ✗ | ✗ | ✗ |
| Self-hostable | ✓ | ✗ | ✓ | ✓ |
| No accounts needed | ✓ | ✓ | ✗ | ✓ |
| End-to-end encrypted | ✓ | ✗ | ✓* | ✗ |

*Google Drive requires specific configuration

---

## Features

### Sharing
- **No account required** — Share immediately
- **Single-use links** — Files deleted after first access
- **Batch uploads** — Share multiple files with one link
- **Password protection** — Add optional security layer
- **Custom expiration** — Auto-delete after 15 days or user-defined period
- **View-once mode** — Recipients have 60 seconds before automatic deletion

### Security & Privacy
- **Client-side encryption** — AES-256-GCM encryption in your browser
- **Zero-knowledge architecture** — Server cannot access file contents
- **One-time tokens** — Each link is valid only once
- **Brute-force protection** — Failed access attempts trigger 10-minute lockout
- **CSRF protection** — Protection against cross-site attacks
- **No tracking** — No analytics or telemetry

### Technical
- **Up to 1GB files** — Configurable per deployment
- **Multiple access modes** — Password-protected or URL-fragment key
- **Rate limiting** — Per-endpoint protection
- **Fast transfers** — Direct browser-to-storage uploads
- **Mobile friendly** — Works on all devices

---

## Architecture

### How It Works

**Sharing a file:**
1. Select file in browser
2. Encrypt file with AES-256-GCM (key from password or generated)
3. Upload encrypted file to storage
4. Generate single-use share link
5. Send link to recipient

**Accessing a file:**
1. Recipient opens share link
2. Server verifies link is valid and unused
3. Browser downloads and decrypts file
4. File is automatically deleted from storage
5. Link becomes invalid for future access

### Design Principles

- **Encryption first** — Nothing is ever stored unencrypted on the server
- **Minimal metadata** — Only store what's necessary (size, type, timestamps)
- **Fail secure** — All access defaults to denied unless explicitly verified
- **Audit transparency** — All code is open source and reviewable
- **Deployment flexibility** — Run as managed service or self-hosted

---

## Security

### Encryption

- **Algorithm:** AES-256-GCM (Authenticated Encryption with Associated Data)
- **Key derivation:** 
  - Password mode: PBKDF2 with 210,000 iterations and random salt
  - Link-key mode: Generated client-side and embedded in URL fragment
- **Random IV:** Generated for each encryption operation
- **Authenticated:** GCM provides integrity verification

### What Is Encrypted
- File content (always encrypted before leaving your browser)
- File contents are never accessible to the server

### What Is Not Encrypted
- File size, MIME type, timestamps (stored for operation)
- Upload and access metadata (for logging and debugging)
- Access patterns (when files were downloaded)

### Important Limitations

**This is not a zero-knowledge system for the server.** The server operator can:
- See file size and type
- Observe upload and download timestamps
- See access patterns and IP addresses (for rate limiting)
- Access metadata about shared files

**For maximum security:**
- Use password protection for sensitive files
- Only share links through trusted channels
- Delete links after use
- Consider the server operator as part of your threat model

**Self-hosting:** When you self-host BurnLink, you control the entire system and can implement additional security measures.

### Additional Protections

- **One-time tokens:** Each share link is valid for only one access
- **Brute-force defense:** 3 failed decryption attempts trigger 10-minute lockout
- **Rate limiting:** Prevents abuse of upload and access endpoints
- **Session security:** CSRF protection on state-changing operations
- **Automatic cleanup:** Files are deleted from storage after access or expiration

---

## Deployment

BurnLink can be deployed in multiple ways:

- **Use the public service** — Visit [burnlink.page](https://burnlink.page)
- **Self-host on your infrastructure** — Full source code provided
- **Deploy to cloud platforms** — Netlify, Vercel, or traditional VPS

For self-hosting details and deployment instructions, see the repository's technical documentation.

---

## Contributing

Contributions are welcome. To contribute:

1. Fork the repository on GitHub
2. Create a feature branch for your changes
3. Submit a pull request with clear commit messages
4. For security issues, see [SECURITY.md](./SECURITY.md)

---

## Support

For questions or issues:

- **Bug reports:** [GitHub Issues](https://github.com/Joy-Majumder/BurnLink/issues)
- **Security concerns:** See [SECURITY.md](./SECURITY.md)
- **Email:** hello@paperfrogs.dev

---

## License

BurnLink is licensed under the MIT License. See [LICENSE](./LICENSE) for details.
