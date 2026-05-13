const crypto = require("crypto");
const helmet = require("helmet");
const validator = require("validator");

/**
 * Security logging - tracks security events for audit trails
 */
const securityLog = {
  events: [],
  
  log(event, details = {}) {
    const entry = {
      timestamp: new Date().toISOString(),
      event,
      ...details,
    };
    this.events.push(entry);
    // Keep last 1000 events in memory; in production, stream to external log
    if (this.events.length > 1000) {
      this.events.shift();
    }
    if (process.env.SECURITY_DEBUG === "true") {
      console.log(`[SECURITY] ${event}:`, details);
    }
  },
  
  getEvents(count = 100) {
    return this.events.slice(-count);
  },
};

/**
 * Request ID middleware - adds unique identifier to each request for tracing
 */
function requestIdMiddleware(req, res, next) {
  req.id = crypto.randomUUID();
  res.setHeader("X-Request-ID", req.id);
  next();
}

/**
 * Helmet security headers configuration
 */
function getHelmetConfig() {
  const r2CspOrigin = process.env.R2_ACCOUNT_ID
    ? `https://*.r2.cloudflarestorage.com`
    : null;

  return helmet({
    contentSecurityPolicy: false, // We handle CSP separately with nonce
    crossOriginEmbedderPolicy: false, // We handle COEP separately
    crossOriginOpenerPolicy: {
      policy: "same-origin",
    },
    crossOriginResourcePolicy: {
      policy: "same-origin",
    },
    expectCT: {
      maxAge: 86400,
      enforce: true,
    },
    dnsPrefetchControl: {
      allow: false,
    },
    frameguard: {
      action: "deny",
    },
    hidePoweredBy: true,
    hsts: {
      maxAge: 63072000, // 2 years
      includeSubDomains: true,
      preload: true,
    },
    ieNoOpen: true,
    noSniff: true,
    permittedCrossDomainPolicies: {
      permittedPolicies: "none",
    },
    referrerPolicy: {
      policy: "no-referrer",
    },
    xssFilter: false, // CSP is better
  });
}

/**
 * Enhanced CSP middleware with nonce support
 */
function cspMiddleware(req, res, next) {
  const nonce = crypto.randomBytes(16).toString("base64");
  res.locals.cspNonce = nonce;

  const r2CspOrigin = process.env.R2_ACCOUNT_ID
    ? `https://*.r2.cloudflarestorage.com`
    : null;

  const cspHeader = [
    "default-src 'none'",
    `script-src 'self' 'nonce-${nonce}' https://cloud.umami.is https://challenges.cloudflare.com https://static.cloudflareinsights.com`,
    "style-src 'unsafe-inline' https://fonts.googleapis.com https://challenges.cloudflare.com",
    "img-src 'self' blob: data: https://api.producthunt.com",
    "media-src 'self' blob:",
    "font-src 'self' https://fonts.gstatic.com",
    `connect-src 'self' https://cloud.umami.is https://api-gateway.umami.dev https://challenges.cloudflare.com${r2CspOrigin ? " " + r2CspOrigin : ""}`,
    "frame-src blob: https://challenges.cloudflare.com",
    "form-action 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "upgrade-insecure-requests",
  ].join("; ");

  res.setHeader("Content-Security-Policy", cspHeader);
  // Report-only CSP for violations
  res.setHeader("Content-Security-Policy-Report-Only", cspHeader + "; report-uri /api/csp-report");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()");

  next();
}

/**
 * CSP violation reporting endpoint
 */
function cspReportHandler(req, res) {
  if (!req.body) return res.status(204).end();
  
  const violation = req.body["csp-report"];
  if (violation) {
    securityLog.log("CSP_VIOLATION", {
      violatedDirective: violation["violated-directive"],
      blockedUri: violation["blocked-uri"],
      sourceFile: violation["source-file"],
      lineNumber: violation["line-number"],
      originalPolicy: violation["original-policy"],
    });
  }
  res.status(204).end();
}

/**
 * Strict input validation helpers
 */
const validators = {
  /**
   * Validate UUID format
   */
  isValidUUID(str) {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(str);
  },

  /**
   * Validate storage path format (prevents path traversal)
   */
  isValidStoragePath(str) {
    return /^\d{4}-\d{2}-\d{2}\/[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}-[\w.\-]+$/i.test(str);
  },

  /**
   * Validate link key format
   */
  isValidLinkKey(str) {
    return /^[A-Za-z0-9_-]{43,88}$/.test(str);
  },

  /**
   * Validate file name (sanitize)
   */
  sanitizeFileName(name) {
    if (typeof name !== "string") return "file";
    return name
      .replace(/[^\w.\-]/g, "_")
      .slice(0, 255)
      .trim() || "file";
  },

  /**
   * Validate password - strengthened policy
   * Requires: 8+ characters, no spaces, mix of uppercase/lowercase/numbers/special OR 12+ any characters
   */
  validatePassword(password) {
    if (typeof password !== "string") return false;
    if (password.length < 8) return false; // Minimum 8 characters
    if (password.length > 255) return false;
    if (/\s/.test(password)) return false; // No whitespace
    
    // Allow strong passwords of 12+ chars (any composition)
    if (password.length >= 12) return true;
    
    // For 8-11 char passwords, require complexity
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\\,.<>?]/.test(password);
    const complexityCount = [hasUppercase, hasLowercase, hasNumber, hasSpecial].filter(Boolean).length;
    
    // Require at least 3 of 4 complexity types
    return complexityCount >= 3;
  },

  /**
   * Validate email
   */
  isValidEmail(email) {
    return validator.isEmail(email);
  },

  /**
   * Validate URL
   */
  isValidUrl(url) {
    try {
      const parsed = new URL(url);
      return parsed.protocol === "http:" || parsed.protocol === "https:";
    } catch {
      return false;
    }
  },

  /**
   * Escape HTML to prevent XSS
   */
  escapeHtml(str) {
    const map = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#039;",
    };
    return String(str).replace(/[&<>"']/g, (m) => map[m]);
  },

  /**
   * Validate IP address
   */
  isValidIp(ip) {
    return validator.isIP(ip);
  },
};

/**
 * Environment variable validation
 */
function validateEnvironment() {
  const errors = [];

  // Critical variables
  const critical = [
    "SUPABASE_URL",
    "SUPABASE_ANON_KEY",
    "SUPABASE_SERVICE_ROLE_KEY",
    "R2_ACCOUNT_ID",
    "R2_ACCESS_KEY_ID",
    "R2_SECRET_ACCESS_KEY",
    "R2_BUCKET_NAME",
  ];

  for (const varName of critical) {
    if (!process.env[varName]) {
      errors.push(`Missing critical environment variable: ${varName}`);
    }
  }

  // Warn about missing optional but recommended
  const recommended = [
    "TURNSTILE_SITE_KEY",
    "TURNSTILE_SECRET_KEY",
    "HEALTH_TOKEN",
    "CANONICAL_BASE_URL",
    "RATE_LIMIT_PER_IP",
    "RATE_LIMIT_WINDOW",
    "CSRF_TOKENS_ENABLED",
  ];

  for (const varName of recommended) {
    if (!process.env[varName] && process.env.NODE_ENV === "production") {
      console.warn(`⚠️  Recommended environment variable not set: ${varName}`);
    }
  }

  // Validate formats
  if (process.env.CANONICAL_BASE_URL) {
    try {
      new URL(process.env.CANONICAL_BASE_URL);
    } catch {
      errors.push(`Invalid CANONICAL_BASE_URL: ${process.env.CANONICAL_BASE_URL}`);
    }
  }

  if (process.env.MAX_UPLOAD_BYTES) {
    const bytes = Number(process.env.MAX_UPLOAD_BYTES);
    if (!Number.isFinite(bytes) || bytes <= 0) {
      errors.push(`Invalid MAX_UPLOAD_BYTES: ${process.env.MAX_UPLOAD_BYTES}`);
    }
  }

  if (process.env.PORT) {
    const port = Number(process.env.PORT);
    if (!Number.isFinite(port) || port < 1 || port > 65535) {
      errors.push(`Invalid PORT: ${process.env.PORT}`);
    }
  }

  if (errors.length > 0) {
    console.error("❌ Environment validation failed:");
    errors.forEach((err) => console.error(`  - ${err}`));
    if (process.env.NODE_ENV === "production") {
      process.exit(1);
    }
  }

  return errors.length === 0;
}

/**
 * Sanitize request logging (hide sensitive data)
 */
function sanitizeForLogging(obj) {
  if (!obj || typeof obj !== "object") return obj;

  const sanitized = { ...obj };
  const sensitiveKeys = [
    "password",
    "token",
    "secret",
    "key",
    "authorization",
    "cookie",
    "cf-turnstile-response",
    "cleanupToken",
    "linkKey",
  ];

  for (const key of Object.keys(sanitized)) {
    if (sensitiveKeys.some((sensitive) => key.toLowerCase().includes(sensitive))) {
      sanitized[key] = "[REDACTED]";
    }
  }

  return sanitized;
}

/**
 * Rate limit exceeded handler with logging
 */
function handleRateLimitExceeded(req, res, limit, window) {
  securityLog.log("RATE_LIMIT_EXCEEDED", {
    path: req.path,
    method: req.method,
    ip: req.ip,
    limit,
    window,
    requestId: req.id,
  });

  res.setHeader("Retry-After", String(Math.ceil(window / 1000)));
  
  if (req.path.startsWith("/api") || req.path.includes("/raw")) {
    res.status(429).json({ error: "Too many requests. Please slow down." });
  } else {
    res.status(429).send("Too many requests.");
  }
}

module.exports = {
  securityLog,
  requestIdMiddleware,
  getHelmetConfig,
  cspMiddleware,
  cspReportHandler,
  validators,
  validateEnvironment,
  sanitizeForLogging,
  handleRateLimitExceeded,
};
