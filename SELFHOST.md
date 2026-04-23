# Self-Hosting BurnLink

This guide walks through deploying BurnLink on your own infrastructure for private, encrypted file sharing.

---

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Local Setup](#local-setup)
- [Environment Variables](#environment-variables)
- [Database Setup](#database-setup)
- [Storage Configuration](#storage-configuration)
- [Deployment Options](#deployment-options)
- [Running in Production](#running-in-production)
- [Troubleshooting](#troubleshooting)
- [Support](#support)

---

## Overview

BurnLink is designed to be self-hostable. You control your data, your encryption keys, and your deployment.

### What You Get
- **Full source code** — Review and modify any aspect
- **Privacy control** — No external analytics, logs stay local
- **Scalability** — Deploy to your own servers or serverless platforms
- **Security** — End-to-end encryption means servers see no plaintext

### What You Need
- A way to run Node.js (local, Docker, VPS, etc.)
- A Supabase instance for metadata storage
- A Cloudflare R2 bucket (or S3-compatible storage) for encrypted files
- A domain and basic DevOps knowledge

---

## Prerequisites

### System Requirements
- **Node.js** 18.0+ and npm or yarn
- **PostgreSQL** (via Supabase or self-hosted)
- **S3-compatible storage** (Cloudflare R2, AWS S3, DigitalOcean Spaces, etc.)
- **Git** for cloning the repository

### Accounts Needed
1. **Supabase** — Free tier available at [supabase.com](https://supabase.com)
2. **Cloudflare R2** — Free tier available at [cloudflare.com/r2](https://cloudflare.com/r2)
3. **(Optional) Deployment platform** — Netlify, Vercel, Railway, etc.

---

## Local Setup

### 1. Clone the Repository

```bash
git clone https://github.com/paperfrogs-hq/BurnLink.git
cd BurnLink
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Create Environment File

```bash
cp .env.example .env
```

Edit `.env` with your configuration (see [Environment Variables](#environment-variables) below).

### 4. Set Up the Database

```bash
npm run setup-db
```

This creates the required tables in your Supabase database.

### 5. Start Development Server

```bash
npm run dev
```

Navigate to `http://localhost:3000`. You should see the BurnLink upload interface.

---

## Environment Variables

Create a `.env` file in the project root. Here's the complete reference:

```bash
# App Configuration
NODE_ENV=development                    # development | production
PORT=3000                               # Local port
PUBLIC_BASE_URL=http://localhost:3000   # Your public URL (with domain in production)

# Supabase (Database & Authentication)
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Cloudflare R2 (or S3-compatible storage)
R2_ACCOUNT_ID=your-account-id
R2_ACCESS_KEY_ID=your-access-key
R2_SECRET_ACCESS_KEY=your-secret-key
R2_BUCKET_NAME=burnlink-files
R2_REGION=us-east-1                     # For S3 compatibility
R2_ENDPOINT=https://your-bucket.r2.example.com  # Custom endpoint (optional)

# Security & Rate Limiting
RATE_LIMIT_WINDOW=15                    # Minutes (default: 15)
RATE_LIMIT_MAX_REQUESTS=30              # Requests per window
MAX_FILE_SIZE=1073741824                # Bytes (default: 1GB)

# Optional: Analytics & Monitoring
UMAMI_WEBSITE_ID=your-umami-id          # For privacy-respecting analytics (optional)
CLOUDFLARE_BEACON_TOKEN=your-beacon-token  # Cloudflare Insights (optional)

# Optional: Email Notifications (future feature)
# SMTP_HOST=smtp.example.com
# SMTP_PORT=587
# SMTP_USER=your-email@example.com
# SMTP_PASS=your-password
```

### Environment Variable Explanations

**Supabase Keys:**
- Get these from your Supabase project dashboard → Settings → API
- `SUPABASE_ANON_KEY` is used client-side (safe to expose)
- `SUPABASE_SERVICE_ROLE_KEY` is server-side only (keep secret)

**Cloudflare R2:**
- Create an API token in your Cloudflare dashboard
- `R2_ACCOUNT_ID` is your Cloudflare account number
- The bucket name is what you create in R2 console

**Rate Limiting:**
- Adjust to prevent abuse on your deployment
- Higher `RATE_LIMIT_MAX_REQUESTS` allows more uploads per window

---

## Database Setup

### Using Supabase (Recommended for Self-Hosting)

1. **Create a free Supabase account** at [supabase.com](https://supabase.com)

2. **Create a new project**
   - Choose a region close to your users
   - Set a strong database password

3. **Get your credentials**
   - Go to Settings → API
   - Copy `SUPABASE_URL` and `SUPABASE_ANON_KEY`
   - Copy `SUPABASE_SERVICE_ROLE_KEY` (keep this secret)

4. **Set up tables**
   
   Run this in the Supabase SQL editor:

   ```sql
   -- Files table
   CREATE TABLE IF NOT EXISTS files (
     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
     token VARCHAR(255) UNIQUE NOT NULL,
     filename VARCHAR(255) NOT NULL,
     mime_type VARCHAR(100),
     size_bytes BIGINT,
     encrypted_key_salt VARCHAR(255) NOT NULL,
     password_protected BOOLEAN DEFAULT FALSE,
     created_at TIMESTAMP DEFAULT NOW(),
     expires_at TIMESTAMP,
     burned_at TIMESTAMP,
     s3_key VARCHAR(512) NOT NULL
   );

   -- Create indexes for performance
   CREATE INDEX idx_files_token ON files(token);
   CREATE INDEX idx_files_expires_at ON files(expires_at);
   CREATE INDEX idx_files_burned_at ON files(burned_at);

   -- Rate limiting table
   CREATE TABLE IF NOT EXISTS rate_limits (
     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
     ip_address VARCHAR(45) NOT NULL,
     endpoint VARCHAR(255) NOT NULL,
     request_count INTEGER DEFAULT 1,
     window_start TIMESTAMP DEFAULT NOW(),
     UNIQUE(ip_address, endpoint, window_start)
   );
   ```

5. **Verify connection**
   ```bash
   npm run test-db
   ```

### Using Self-Hosted PostgreSQL

If you prefer full control:

```bash
# Install PostgreSQL locally or on a VPS
# Then create a database
createdb burnlink

# Update .env
DATABASE_URL=postgresql://user:password@localhost/burnlink

# Run migrations
npm run migrate
```

---

## Storage Configuration

### Cloudflare R2 (Recommended)

1. **Create an R2 bucket**
   - Go to Cloudflare dashboard → R2
   - Create a new bucket (e.g., `burnlink-files`)
   - Note the bucket name

2. **Generate API token**
   - Settings → API Tokens
   - Create a new token with R2 permissions
   - Copy credentials to `.env`

3. **Set CORS (if uploading from browser)**
   - Go to bucket settings
   - Add CORS rule:
     ```json
     {
       "AllowedOrigins": ["https://your-domain.com"],
       "AllowedMethods": ["PUT", "POST", "GET"],
       "AllowedHeaders": ["*"]
     }
     ```

4. **Test connectivity**
   ```bash
   npm run test-r2
   ```

### AWS S3

If using AWS S3 instead of R2:

```bash
# Install AWS SDK (already included)
npm install aws-sdk

# Update .env
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-key
AWS_SECRET_ACCESS_KEY=your-secret
S3_BUCKET=your-bucket-name
S3_ENDPOINT=https://s3.amazonaws.com  # For standard S3
```

### DigitalOcean Spaces

S3-compatible, works with the same configuration as R2:

```bash
# Update .env
R2_ENDPOINT=https://your-space.nyc3.digitaloceanspaces.com
R2_ACCESS_KEY_ID=your-key
R2_SECRET_ACCESS_KEY=your-secret
R2_BUCKET_NAME=your-space-name
```

---

## Deployment Options

### Option 1: Netlify (Easiest)

1. **Push to GitHub**
   ```bash
   git remote add origin https://github.com/your-username/burnlink.git
   git push -u origin main
   ```

2. **Connect to Netlify**
   - Go to [netlify.com](https://netlify.com)
   - Click "New site from Git"
   - Select your BurnLink repository
   - Build command: `npm run build`
   - Publish directory: `public`

3. **Set environment variables**
   - In Netlify dashboard → Site settings → Build & deploy → Environment
   - Add all variables from `.env`

4. **Deploy**
   - Netlify automatically deploys on push
   - Your site is live at `your-site.netlify.app`

### Option 2: Vercel

1. **Push to GitHub**
   ```bash
   git push origin main
   ```

2. **Import to Vercel**
   - Go to [vercel.com](https://vercel.com)
   - Click "New Project"
   - Import your GitHub repository
   - Framework: Node.js
   - Root directory: ./

3. **Environment Variables**
   - Add all `.env` variables in Project Settings → Environment Variables

4. **Deploy**
   ```bash
   vercel
   ```

### Option 3: Docker (Self-Hosted VPS)

1. **Create Dockerfile** (included in repo)
   ```dockerfile
   FROM node:18-alpine
   WORKDIR /app
   COPY package*.json ./
   RUN npm install --production
   COPY . .
   EXPOSE 3000
   CMD ["npm", "start"]
   ```

2. **Build and run**
   ```bash
   docker build -t burnlink .
   docker run -p 3000:3000 --env-file .env burnlink
   ```

3. **Deploy with Docker Compose**
   ```yaml
   version: '3.8'
   services:
     burnlink:
       build: .
       ports:
         - "3000:3000"
       environment:
         - NODE_ENV=production
         - SUPABASE_URL=${SUPABASE_URL}
         - R2_BUCKET_NAME=${R2_BUCKET_NAME}
       volumes:
         - ./logs:/app/logs
   ```

   Run with:
   ```bash
   docker-compose up -d
   ```

### Option 4: VPS (DigitalOcean, Linode, AWS EC2)

1. **Provision a Linux server**
   - Ubuntu 22.04 LTS recommended
   - Minimum 1GB RAM, 1 vCPU

2. **SSH into the server**
   ```bash
   ssh root@your-server-ip
   ```

3. **Install Node.js and npm**
   ```bash
   curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
   sudo apt-get install -y nodejs
   ```

4. **Clone and setup BurnLink**
   ```bash
   git clone https://github.com/paperfrogs-hq/BurnLink.git
   cd BurnLink
   npm install
   cp .env.example .env
   # Edit .env with your credentials
   nano .env
   ```

5. **Set up systemd service**
   ```bash
   sudo nano /etc/systemd/system/burnlink.service
   ```

   Add:
   ```ini
   [Unit]
   Description=BurnLink File Sharing
   After=network.target

   [Service]
   Type=simple
   User=www-data
   WorkingDirectory=/var/www/burnlink
   ExecStart=/usr/bin/node /var/www/burnlink/server.js
   Restart=always
   RestartSec=10

   [Install]
   WantedBy=multi-user.target
   ```

   Enable and start:
   ```bash
   sudo systemctl enable burnlink
   sudo systemctl start burnlink
   sudo systemctl status burnlink
   ```

6. **Set up Nginx reverse proxy**
   ```bash
   sudo apt-get install nginx
   sudo nano /etc/nginx/sites-available/burnlink
   ```

   Add:
   ```nginx
   server {
       listen 80;
       server_name your-domain.com www.your-domain.com;

       location / {
           proxy_pass http://localhost:3000;
           proxy_http_version 1.1;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection 'upgrade';
           proxy_set_header Host $host;
           proxy_cache_bypass $http_upgrade;
       }
   }
   ```

   Enable and test:
   ```bash
   sudo ln -s /etc/nginx/sites-available/burnlink /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl restart nginx
   ```

7. **Set up SSL with Let's Encrypt**
   ```bash
   sudo apt-get install certbot python3-certbot-nginx
   sudo certbot --nginx -d your-domain.com
   ```

---

## Running in Production

### Security Checklist

- [ ] Use HTTPS only (SSL/TLS certificate installed)
- [ ] Set `NODE_ENV=production`
- [ ] Keep `SUPABASE_SERVICE_ROLE_KEY` secret (server-side only)
- [ ] Use strong, randomly generated environment variables
- [ ] Enable rate limiting to prevent abuse
- [ ] Set up monitoring and logging
- [ ] Regularly update Node.js and dependencies
- [ ] Configure CSP headers properly
- [ ] Enable CORS only for your domain

### Environment Variables for Production

```bash
NODE_ENV=production
PORT=3000
PUBLIC_BASE_URL=https://your-domain.com

# Database
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=...
SUPABASE_SERVICE_ROLE_KEY=...  # Keep secret!

# Storage
R2_ACCOUNT_ID=...
R2_ACCESS_KEY_ID=...
R2_SECRET_ACCESS_KEY=...       # Keep secret!
R2_BUCKET_NAME=burnlink-files
R2_ENDPOINT=https://your-bucket.r2.example.com

# Rate Limiting
RATE_LIMIT_WINDOW=15
RATE_LIMIT_MAX_REQUESTS=30

# Optional
UMAMI_WEBSITE_ID=...
```

### Monitoring

Monitor your deployment with:

```bash
# Check logs
pm2 logs burnlink

# Monitor performance
pm2 monit

# View CPU/memory usage
free -h
df -h
```

---

## Troubleshooting

### Issue: Database connection fails

**Error:** `FATAL: Ident authentication failed for user "postgres"`

**Solution:**
1. Check `SUPABASE_URL` and keys are correct
2. Verify firewall allows outbound connections to Supabase
3. Test with:
   ```bash
   npm run test-db
   ```

### Issue: Files not uploading to R2

**Error:** `NoSuchBucket` or `InvalidAccessKeyId`

**Solution:**
1. Verify bucket name in `.env`
2. Check R2 API token has correct permissions
3. Verify CORS configuration on bucket
4. Test with:
   ```bash
   npm run test-r2
   ```

### Issue: Deployment fails on Netlify

**Error:** `Function invocation failed: Error: ENOENT: no such file or directory`

**Solution:**
1. Ensure `netlify.toml` exists in root
2. Check build command runs successfully locally
3. Verify all environment variables are set in Netlify dashboard
4. Check deployment logs for specific error

### Issue: CORS errors in browser

**Error:** `Access to XMLHttpRequest has been blocked by CORS policy`

**Solution:**
1. Add your domain to R2 bucket CORS settings
2. Check `PUBLIC_BASE_URL` matches your actual domain
3. Verify headers in response:
   ```bash
   curl -H "Origin: https://your-domain.com" -v https://your-r2-bucket.r2.example.com
   ```

### Issue: High memory usage

**Solution:**
1. Configure Node.js heap limit:
   ```bash
   export NODE_OPTIONS="--max-old-space-size=512"
   npm start
   ```
2. Enable file streaming for large uploads
3. Monitor with `top` or cloud provider dashboard

---

## Support

Running into issues? We're here to help:

- **GitHub Issues** — [Report bugs](https://github.com/paperfrogs-hq/BurnLink/issues)
- **Email** — [hello@paperfrogs.dev](mailto:hello@paperfrogs.dev)
- **Security Issues** — [See SECURITY.md](./SECURITY.md)

---

## Next Steps

After deployment:

1. ✅ Verify encryption works (upload a test file)
2. ✅ Test one-time link burning (download and verify link is destroyed)
3. ✅ Set up monitoring and alerting
4. ✅ Configure backups for your Supabase database
5. ✅ Document your deployment for future reference

Welcome to private, encrypted file sharing! 🔥
