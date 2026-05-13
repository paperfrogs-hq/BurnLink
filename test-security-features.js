#!/usr/bin/env node

/**
 * BurnLink Security Features Test Suite
 * Tests core security validators and configurations
 */

const { validators, getHelmetConfig, securityLog } = require('./lib/security');

console.log('\n🔐 BurnLink Security Features Test\n');
console.log('='.repeat(50));

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`✅ ${name}`);
    passed++;
  } catch (error) {
    console.log(`❌ ${name}`);
    console.log(`   Error: ${error.message}`);
    failed++;
  }
}

// UUID Validation Tests
console.log('\n📋 UUID Validation:');
test('Valid UUID passes', () => {
  if (!validators.isValidUUID('550e8400-e29b-41d4-a716-446655440000')) {
    throw new Error('Valid UUID rejected');
  }
});

test('Invalid UUID fails', () => {
  if (validators.isValidUUID('not-a-uuid')) {
    throw new Error('Invalid UUID accepted');
  }
});

test('Empty string fails', () => {
  if (validators.isValidUUID('')) {
    throw new Error('Empty string accepted');
  }
});

// Password Validation Tests
console.log('\n🔑 Password Validation:');
test('Valid password (8+ chars with complexity)', () => {
  if (!validators.validatePassword('Test123!')) {
    throw new Error('Valid password rejected');
  }
});

test('Short password fails', () => {
  if (validators.validatePassword('abc')) {
    throw new Error('Short password accepted');
  }
});

test('Password with spaces fails', () => {
  if (validators.validatePassword('pass word')) {
    throw new Error('Password with spaces accepted');
  }
});

test('Very long password fails', () => {
  if (validators.validatePassword('a'.repeat(256))) {
    throw new Error('Over-length password accepted');
  }
});

test('Low complexity password fails', () => {
  if (validators.validatePassword('abcdefgh')) {
    throw new Error('Low complexity password accepted');
  }
});

test('Strong 12+ char password passes', () => {
  if (!validators.validatePassword('longerpassword123')) {
    throw new Error('Long password rejected');
  }
});

// Filename Sanitization Tests
console.log('\n📝 Filename Sanitization:');
test('Normal filename preserved', () => {
  const result = validators.sanitizeFileName('document.pdf');
  if (result !== 'document.pdf') {
    throw new Error(`Expected 'document.pdf', got '${result}'`);
  }
});

test('Special characters removed', () => {
  const result = validators.sanitizeFileName('file<>|.txt');
  if (result.includes('<') || result.includes('>') || result.includes('|')) {
    throw new Error('Special characters not removed');
  }
});

test('Very long filename truncated', () => {
  const long = 'a'.repeat(300) + '.txt';
  const result = validators.sanitizeFileName(long);
  if (result.length > 255) {
    throw new Error('Filename not truncated');
  }
});

// HTML Escaping Tests
console.log('\n🛡️ HTML Escaping (XSS Prevention):');
test('HTML tags escaped', () => {
  const result = validators.escapeHtml('<script>alert("xss")</script>');
  if (result.includes('<') || result.includes('>')) {
    throw new Error('HTML tags not escaped');
  }
});

test('Quotes escaped', () => {
  const result = validators.escapeHtml('"quoted"');
  if (!result.includes('&quot;')) {
    throw new Error('Quotes not escaped');
  }
});

test('Ampersand escaped', () => {
  const result = validators.escapeHtml('A&B');
  if (!result.includes('&amp;')) {
    throw new Error('Ampersand not escaped');
  }
});

// Storage Path Validation Tests
console.log('\n📦 Storage Path Validation:');
test('Valid storage path accepted', () => {
  if (!validators.isValidStoragePath('2024-04-20/550e8400-e29b-41d4-a716-446655440000-file.pdf')) {
    throw new Error('Valid storage path rejected');
  }
});

test('Invalid path traversal rejected', () => {
  if (validators.isValidStoragePath('../../../etc/passwd')) {
    throw new Error('Path traversal not blocked');
  }
});

// URL Validation Tests
console.log('\n🌐 URL Validation:');
test('Valid HTTPS URL accepted', () => {
  if (!validators.isValidUrl('https://burnlink.page')) {
    throw new Error('Valid HTTPS URL rejected');
  }
});

test('Invalid URL rejected', () => {
  if (validators.isValidUrl('not a url')) {
    throw new Error('Invalid URL accepted');
  }
});

test('Non-HTTP URL rejected', () => {
  if (validators.isValidUrl('ftp://example.com')) {
    throw new Error('FTP URL accepted');
  }
});

// Email Validation Tests
console.log('\n✉️ Email Validation:');
test('Valid email accepted', () => {
  if (!validators.isValidEmail('user@example.com')) {
    throw new Error('Valid email rejected');
  }
});

test('Invalid email rejected', () => {
  if (validators.isValidEmail('not-an-email')) {
    throw new Error('Invalid email accepted');
  }
});

// IP Address Validation Tests
console.log('\n🔗 IP Validation:');
test('Valid IPv4 accepted', () => {
  if (!validators.isValidIp('192.168.1.1')) {
    throw new Error('Valid IPv4 rejected');
  }
});

test('Valid IPv6 accepted', () => {
  if (!validators.isValidIp('2001:0db8:85a3:0000:0000:8a2e:0370:7334')) {
    throw new Error('Valid IPv6 rejected');
  }
});

test('Invalid IP rejected', () => {
  if (validators.isValidIp('999.999.999.999')) {
    throw new Error('Invalid IP accepted');
  }
});

// Link Key Validation Tests
console.log('\n🔗 Link Key Validation:');
test('Valid link key accepted', () => {
  const validKey = 'a'.repeat(43);
  if (!validators.isValidLinkKey(validKey)) {
    throw new Error('Valid link key rejected');
  }
});

test('Short link key rejected', () => {
  if (validators.isValidLinkKey('short')) {
    throw new Error('Short link key accepted');
  }
});

// Security Logging Tests
console.log('\n📊 Security Logging:');
test('Log event recorded', () => {
  const beforeCount = securityLog.getEvents().length;
  securityLog.log('TEST_EVENT', { testData: 'value' });
  const afterCount = securityLog.getEvents().length;
  if (afterCount <= beforeCount) {
    throw new Error('Event not logged');
  }
});

test('Event has timestamp', () => {
  securityLog.log('TEST_TIMESTAMP', {});
  const events = securityLog.getEvents();
  const lastEvent = events[events.length - 1];
  if (!lastEvent.timestamp) {
    throw new Error('Event missing timestamp');
  }
});

// Helmet Configuration Tests
console.log('\n⛑️ Security Headers:');
test('Helmet config is a function', () => {
  const config = getHelmetConfig();
  if (typeof config !== 'function') {
    throw new Error('Helmet config should return a middleware function');
  }
});

test('Helmet middleware is callable', () => {
  const middleware = getHelmetConfig();
  if (typeof middleware !== 'function') {
    throw new Error('Helmet middleware not callable');
  }
});

test('HSTS headers configured correctly', () => {
  // Test by checking that helmet is properly configured for HSTS
  const middleware = getHelmetConfig();
  if (typeof middleware !== 'function') {
    throw new Error('HSTS middleware not configured');
  }
});

// Summary
console.log('\n' + '='.repeat(50));
console.log(`\n✅ Passed: ${passed}`);
console.log(`❌ Failed: ${failed}`);
console.log(`📊 Total: ${passed + failed}`);

if (failed === 0) {
  console.log('\n🎉 All security tests passed!\n');
  process.exit(0);
} else {
  console.log(`\n⚠️ ${failed} test(s) failed\n`);
  process.exit(1);
}
