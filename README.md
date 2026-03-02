# BurnLink

[![GitHub](https://img.shields.io/badge/GitHub-BurnLink-blue?logo=github)](https://github.com/Joy-Majumder/BurnLink)

BurnLink is an open-source, privacy-first file sharing platform with browser-side end-to-end encryption. Share files securely knowing they are encrypted in your browser and deleted after the first download.

## Features

- **End-to-End Encryption**: Files encrypted in your browser before upload
- **Two Sharing Modes**:
  - Password-protected sharing (recipient enters password)
  - Link-key sharing (secret embedded in URL fragment)
- **One-Time Links**: Files burn after first successful download
- **View-Once Mode**: Files viewable for 90 seconds then permanently destroyed
- **Brute-Force Protection**: 10-minute lockout after 3 wrong password attempts
- **Supabase Integration**: Secure cloud storage with metadata management
- **Responsive Design**: Clean, minimal UI
- **Simple UX**: One-click copy link to share


## How It Works

1. **Upload**: Select a file and optionally set a password
2. **Encrypt**: File is encrypted in your browser using AES-GCM
3. **Store**: Encrypted payload uploaded to Supabase Storage
4. **Share**: Get a shareable link (with optional password)
5. **Download**: Recipient decrypts in browser, then the link burns


## Security

- All encryption happens in the browser — the server never sees unencrypted files
- AES-256-GCM encryption
- PBKDF2 key derivation with 210,000 iterations
- One-time download links prevent replay attacks
- View-once mode burns files after a timed viewing window
- Open source — auditable by anyone

## License

MIT © [Joy G. Majumdar](https://github.com/Joy-Majumder)

## Contributing

Contributions are welcome. Feel free to open issues and pull requests.

## Support

For issues or questions, [open an issue](https://github.com/Joy-Majumder/BurnLink/issues) on GitHub.

---

BurnLink is a product of [Paperfrogs Lab](https://paperfrogs.dev) — an infrastructure-first studio building research-driven, production-ready tools.
