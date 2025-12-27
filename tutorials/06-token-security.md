# Part 6: Token Security

Even with properly signed JWTs, tokens can be stolen through XSS attacks or network interception. In this part, we'll implement token fingerprinting following OWASP recommendations, build a secure cookie library, and learn defense-in-depth strategies.

---

## Table of Contents

1. [Token Fingerprinting](#1-token-fingerprinting)
2. [Cookie Security Deep Dive](#2-cookie-security-deep-dive)
3. [Building a Cookie Library](#3-building-a-cookie-library)

---

## 1. Token Fingerprinting

### The Token Theft Problem

Even with HTTPS and secure storage, tokens can be stolen:

| Attack Vector | Description |
|---------------|-------------|
| **XSS (Cross-Site Scripting)** | Malicious scripts read tokens from localStorage/memory |
| **Network Interception** | Man-in-the-middle on compromised networks |
| **Browser Extensions** | Malicious extensions access page data |
| **Malware** | Keyloggers and screen scrapers |

Once stolen, a JWT is valid until it expires — the attacker has full access.

### The OWASP Fingerprint Solution

OWASP recommends **binding tokens to the browser session** using a fingerprint:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Token Fingerprinting                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   1. Generate random fingerprint (32 bytes)                                  │
│                     │                                                        │
│                     ▼                                                        │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │              Raw Fingerprint: "a1b2c3d4e5f6..."                     │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                     │                                                        │
│         ┌───────────┴───────────┐                                           │
│         ▼                       ▼                                           │
│   ┌───────────────┐      ┌───────────────┐                                  │
│   │  SHA-256 Hash │      │   Raw Value   │                                  │
│   │               │      │               │                                  │
│   │  "x7y8z9..."  │      │ "a1b2c3d4..." │                                  │
│   └───────┬───────┘      └───────┬───────┘                                  │
│           │                      │                                          │
│           ▼                      ▼                                          │
│   ┌───────────────┐      ┌───────────────┐                                  │
│   │  JWT 'fpt'    │      │  HttpOnly     │                                  │
│   │   Claim       │      │   Cookie      │                                  │
│   │               │      │ __Secure-Fpt  │                                  │
│   └───────────────┘      └───────────────┘                                  │
│                                                                              │
│   Token without matching cookie = REJECTED                                   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Why This Works

1. **JWT is stolen** via XSS → Attacker has the token
2. **Cookie is HttpOnly** → JavaScript cannot access it
3. **Attacker uses token** → Request lacks fingerprint cookie
4. **Server validates** → Hash doesn't match, request rejected

The attacker would need both the token AND the HttpOnly cookie, which requires a more sophisticated attack.

### Implementation

```typescript
// src/fingerprint/generate.ts

import { getSubtle, getUniversalCrypto } from '../crypto/universal';
import { encode as base64urlEncode } from '../crypto/base64url';

/**
 * Fingerprint pair: raw value for cookie, hash for JWT
 */
export interface Fingerprint {
  raw: string;    // Store in HttpOnly cookie
  hash: string;   // Store in JWT 'fpt' claim
}

/**
 * Generate a cryptographically secure fingerprint
 * 
 * @param byteLength - Length of random data (default 32 bytes = 256 bits)
 * @returns Object with raw value and SHA-256 hash
 */
async function generateFingerprint(byteLength: number = 32): Promise<Fingerprint> {
  const crypto = getUniversalCrypto();
  const subtle = getSubtle();
  
  // 1. Generate random bytes
  const randomBytes = new Uint8Array(byteLength);
  crypto.getRandomValues(randomBytes);
  
  // 2. Encode as Base64URL for the raw value
  const raw = base64urlEncode(randomBytes);
  
  // 3. Hash with SHA-256 for the JWT claim
  const hashBuffer = await subtle.digest('SHA-256', randomBytes);
  const hash = base64urlEncode(new Uint8Array(hashBuffer));
  
  return { raw, hash };
}

export { generateFingerprint };
```

```typescript
// src/fingerprint/validate.ts

import { getSubtle } from '../crypto/universal';
import { encode as base64urlEncode, decode as base64urlDecode } from '../crypto/base64url';
import { timingSafeEqual } from '../crypto/timing';

/**
 * Validation result with detailed error information
 */
export interface ValidationResult {
  valid: boolean;
  error?: 'FINGERPRINT_MISSING' | 'FINGERPRINT_COOKIE_MISSING' | 'FINGERPRINT_MISMATCH';
}

/**
 * Validate a fingerprint from cookie against JWT hash
 * 
 * @param rawFingerprint - Raw fingerprint from HttpOnly cookie
 * @param jwtFingerprintHash - Hash from JWT 'fpt' claim
 * @returns Validation result
 */
async function validateFingerprint(
  rawFingerprint: string | null | undefined,
  jwtFingerprintHash: string | null | undefined
): Promise<ValidationResult> {
  // Check if fingerprint claim exists in JWT
  if (!jwtFingerprintHash) {
    return { valid: false, error: 'FINGERPRINT_MISSING' };
  }
  
  // Check if cookie was sent
  if (!rawFingerprint) {
    return { valid: false, error: 'FINGERPRINT_COOKIE_MISSING' };
  }
  
  try {
    const subtle = getSubtle();
    
    // Decode the raw fingerprint from Base64URL
    const rawBytes = base64urlDecode(rawFingerprint);
    
    // Hash it with SHA-256
    const hashBuffer = await subtle.digest('SHA-256', rawBytes);
    const computedHash = base64urlEncode(new Uint8Array(hashBuffer));
    
    // Compare using constant-time comparison
    const isMatch = timingSafeEqual(computedHash, jwtFingerprintHash);
    
    if (!isMatch) {
      return { valid: false, error: 'FINGERPRINT_MISMATCH' };
    }
    
    return { valid: true };
  } catch {
    return { valid: false, error: 'FINGERPRINT_MISMATCH' };
  }
}

export { validateFingerprint, ValidationResult };
```

```typescript
// src/fingerprint/index.ts

import { generateFingerprint, Fingerprint } from './generate';
import { validateFingerprint, ValidationResult } from './validate';
import { CookieHandler } from '../cookies/handler';

/**
 * Default cookie name for fingerprint
 * __Secure- prefix requires Secure attribute
 */
const FINGERPRINT_COOKIE_NAME = '__Secure-Fpt';

/**
 * Default JWT claim name for fingerprint hash
 */
const FINGERPRINT_CLAIM_NAME = 'fpt';

/**
 * Configuration for TokenFingerprinter
 */
export interface FingerprintConfig {
  cookieName?: string;
  claimName?: string;
  cookieMaxAge?: number;  // Seconds (default: session cookie)
  cookieDomain?: string;
  cookiePath?: string;
}

/**
 * High-level fingerprint manager
 * Handles creation and validation of token fingerprints
 */
class TokenFingerprinter {
  private cookieName: string;
  private claimName: string;
  private cookieHandler: CookieHandler;
  private cookieMaxAge?: number;
  private cookieDomain?: string;
  private cookiePath: string;
  
  constructor(config: FingerprintConfig = {}) {
    this.cookieName = config.cookieName ?? FINGERPRINT_COOKIE_NAME;
    this.claimName = config.claimName ?? FINGERPRINT_CLAIM_NAME;
    this.cookieMaxAge = config.cookieMaxAge;
    this.cookieDomain = config.cookieDomain;
    this.cookiePath = config.cookiePath ?? '/';
    this.cookieHandler = new CookieHandler();
  }
  
  /**
   * Create a new fingerprint for token creation
   * 
   * @returns Object with JWT claim and Set-Cookie header value
   */
  async create(): Promise<{
    claim: { [key: string]: string };
    cookie: string;
    raw: string;
  }> {
    const fingerprint = await generateFingerprint();
    
    // Create the Set-Cookie header value
    const cookie = this.cookieHandler.serialize(
      this.cookieName,
      fingerprint.raw,
      {
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
        path: this.cookiePath,
        domain: this.cookieDomain,
        maxAge: this.cookieMaxAge
      }
    );
    
    return {
      claim: { [this.claimName]: fingerprint.hash },
      cookie,
      raw: fingerprint.raw
    };
  }
  
  /**
   * Validate fingerprint during request verification
   * 
   * @param cookieHeader - Raw Cookie header from request
   * @param jwtPayload - Decoded JWT payload
   * @returns Validation result
   */
  async validate(
    cookieHeader: string | null | undefined,
    jwtPayload: { [key: string]: unknown }
  ): Promise<ValidationResult> {
    // Extract fingerprint from cookie header
    const cookies = this.cookieHandler.parse(cookieHeader ?? '');
    const rawFingerprint = cookies[this.cookieName];
    
    // Extract hash from JWT payload
    const jwtHash = jwtPayload[this.claimName] as string | undefined;
    
    return validateFingerprint(rawFingerprint, jwtHash);
  }
  
  /**
   * Create a cookie that clears the fingerprint
   */
  clearCookie(): string {
    return this.cookieHandler.serialize(
      this.cookieName,
      '',
      {
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
        path: this.cookiePath,
        domain: this.cookieDomain,
        maxAge: 0
      }
    );
  }
  
  /**
   * Get the claim name for JWT payload
   */
  getClaimName(): string {
    return this.claimName;
  }
  
  /**
   * Get the cookie name
   */
  getCookieName(): string {
    return this.cookieName;
  }
}

export {
  TokenFingerprinter,
  generateFingerprint,
  validateFingerprint,
  Fingerprint,
  ValidationResult,
  FINGERPRINT_COOKIE_NAME,
  FINGERPRINT_CLAIM_NAME
};
```

### Testing Fingerprinting

```typescript
async function testFingerprinting(): Promise<void> {
  console.log('Testing Token Fingerprinting...\n');
  
  const fingerprinter = new TokenFingerprinter();
  
  // Test creation
  console.log('Creating fingerprint...');
  const { claim, cookie, raw } = await fingerprinter.create();
  
  console.log('Claim:', claim);
  console.log('Cookie:', cookie.substring(0, 60) + '...');
  console.log('Raw (first 20 chars):', raw.substring(0, 20) + '...');
  
  // Simulate JWT payload
  const jwtPayload = { sub: 'user_123', ...claim };
  
  // Test valid fingerprint
  console.log('\nValidating correct fingerprint...');
  const validResult = await fingerprinter.validate(
    `${fingerprinter.getCookieName()}=${raw}`,
    jwtPayload
  );
  console.log('Result:', validResult.valid ? '✅ Valid' : '❌ Invalid');
  
  // Test missing cookie
  console.log('\nValidating without cookie...');
  const missingCookieResult = await fingerprinter.validate(
    '',
    jwtPayload
  );
  console.log('Result:', missingCookieResult.error === 'FINGERPRINT_COOKIE_MISSING' 
    ? '✅ Correctly rejected' : '❌ Wrong error');
  
  // Test wrong fingerprint
  console.log('\nValidating wrong fingerprint...');
  const wrongResult = await fingerprinter.validate(
    `${fingerprinter.getCookieName()}=wrongfingerprint`,
    jwtPayload
  );
  console.log('Result:', wrongResult.error === 'FINGERPRINT_MISMATCH' 
    ? '✅ Correctly rejected' : '❌ Wrong error');
  
  // Test missing claim
  console.log('\nValidating without JWT claim...');
  const missingClaimResult = await fingerprinter.validate(
    `${fingerprinter.getCookieName()}=${raw}`,
    { sub: 'user_123' }  // No fpt claim
  );
  console.log('Result:', missingClaimResult.error === 'FINGERPRINT_MISSING' 
    ? '✅ Correctly rejected' : '❌ Wrong error');
}

testFingerprinting();
```

### Exercise 6.1

1. Create `src/fingerprint/generate.ts` and `src/fingerprint/validate.ts`
2. Create `src/fingerprint/index.ts` with the TokenFingerprinter class
3. Test that a stolen token without the cookie is rejected
4. Verify that the hash in the JWT matches the hash of the cookie value

---

## 2. Cookie Security Deep Dive

### Cookie Attributes

Every security-sensitive cookie should have these attributes:

```typescript
Set-Cookie: __Secure-Fpt=abc123; 
  HttpOnly; 
  Secure; 
  SameSite=Strict; 
  Path=/; 
  Max-Age=86400
```

| Attribute | Purpose | Value |
|-----------|---------|-------|
| `HttpOnly` | Prevent JavaScript access | Always set for tokens |
| `Secure` | HTTPS only | Always set in production |
| `SameSite` | CSRF protection | `Strict` or `Lax` |
| `Path` | URL scope | Usually `/` |
| `Domain` | Domain scope | Omit for current domain only |
| `Max-Age` | Expiration in seconds | Token lifetime |
| `Expires` | Expiration date | Alternative to Max-Age |

### Cookie Prefixes

Modern browsers support security prefixes:

| Prefix | Requirements |
|--------|-------------|
| `__Secure-` | Must have `Secure` attribute |
| `__Host-` | Must have `Secure`, `Path=/`, no `Domain` |

```typescript
// ✅ Valid: Has Secure attribute
Set-Cookie: __Secure-Token=abc; Secure; HttpOnly

// ❌ Invalid: Missing Secure attribute
Set-Cookie: __Secure-Token=abc; HttpOnly

// ✅ Valid: Meets all __Host- requirements
Set-Cookie: __Host-Session=xyz; Secure; Path=/; HttpOnly

// ❌ Invalid: Has Domain attribute
Set-Cookie: __Host-Session=xyz; Secure; Path=/; Domain=example.com
```

### SameSite Explained

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SameSite Attribute                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   SameSite=Strict                                                            │
│   ───────────────                                                            │
│   Cookie ONLY sent for same-site requests                                    │
│   ✓ User clicks link on your site                                           │
│   ✗ User clicks link from email to your site                                │
│   ✗ User clicks link from other site to your site                           │
│   Best for: Sensitive operations (tokens, auth)                              │
│                                                                              │
│   SameSite=Lax (default in modern browsers)                                  │
│   ──────────────────────────────────────────                                 │
│   Cookie sent for same-site AND top-level navigations                        │
│   ✓ User clicks link on your site                                           │
│   ✓ User clicks link from email to your site (GET only)                     │
│   ✗ Form POST from other site                                               │
│   ✗ Fetch/XHR from other site                                               │
│   Best for: Session cookies where linking matters                            │
│                                                                              │
│   SameSite=None                                                              │
│   ───────────────                                                            │
│   Cookie sent for all requests (requires Secure)                             │
│   ⚠️ Only use for cross-site scenarios (embeds, widgets)                    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Our Cookie Strategy

```typescript
/**
 * Cookie usage in AuthSystem
 */

// 1. Fingerprint Cookie
// - Session lifetime (or matches access token)
// - Strict SameSite (always same-origin)
__Secure-Fpt=<raw-fingerprint>; HttpOnly; Secure; SameSite=Strict; Path=/

// 2. Refresh Token Cookie
// - Long lifetime (30 days)
// - Strict SameSite (only used for refresh endpoint)
// - Could use Lax if refresh can happen from navigation
__Secure-Ref=<refresh-token>; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=2592000
```

### Cookie Size Limits

| Browser | Per-Cookie Limit | Total Cookies per Domain |
|---------|------------------|--------------------------|
| Chrome | 4096 bytes | 180 cookies |
| Firefox | 4097 bytes | 150 cookies |
| Safari | 4096 bytes | 600 cookies |

Keep cookies small:
- Fingerprint: ~43 bytes (32 bytes Base64URL)
- Refresh token: ~64 bytes (48 bytes Base64URL)

---

## 3. Building a Cookie Library

### Cookie Serialization

```typescript
// src/cookies/serializer.ts

/**
 * Cookie options following security best practices
 */
export interface CookieOptions {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'Strict' | 'Lax' | 'None';
  path?: string;
  domain?: string;
  maxAge?: number;      // Seconds
  expires?: Date;
  partitioned?: boolean;  // CHIPS support
}

/**
 * Default options for secure cookies
 */
const DEFAULT_OPTIONS: CookieOptions = {
  httpOnly: true,
  secure: true,
  sameSite: 'Strict',
  path: '/'
};

/**
 * Characters not allowed in cookie names (RFC 6265)
 */
const INVALID_NAME_CHARS = /[()<>@,;:\\"/\[\]?={}\s\x00-\x1f\x7f]/;

/**
 * Validate cookie name
 */
function isValidCookieName(name: string): boolean {
  if (!name || typeof name !== 'string') {
    return false;
  }
  return !INVALID_NAME_CHARS.test(name) && name.length > 0;
}

/**
 * Serialize a cookie for Set-Cookie header
 * 
 * @param name - Cookie name
 * @param value - Cookie value
 * @param options - Cookie attributes
 * @returns Set-Cookie header value
 */
function serializeCookie(
  name: string,
  value: string,
  options: CookieOptions = {}
): string {
  // Validate name
  if (!isValidCookieName(name)) {
    throw new Error(`Invalid cookie name: ${name}`);
  }
  
  // Validate __Secure- prefix
  if (name.startsWith('__Secure-') && options.secure === false) {
    throw new Error('__Secure- cookies must have Secure attribute');
  }
  
  // Validate __Host- prefix
  if (name.startsWith('__Host-')) {
    if (options.secure === false) {
      throw new Error('__Host- cookies must have Secure attribute');
    }
    if (options.domain) {
      throw new Error('__Host- cookies must not have Domain attribute');
    }
    if (options.path && options.path !== '/') {
      throw new Error('__Host- cookies must have Path=/');
    }
  }
  
  // SameSite=None requires Secure
  if (options.sameSite === 'None' && options.secure === false) {
    throw new Error('SameSite=None requires Secure attribute');
  }
  
  const opts = { ...DEFAULT_OPTIONS, ...options };
  
  // Encode value
  const encodedValue = encodeURIComponent(value);
  let cookie = `${name}=${encodedValue}`;
  
  // Add attributes
  if (opts.path) {
    cookie += `; Path=${opts.path}`;
  }
  
  if (opts.domain) {
    cookie += `; Domain=${opts.domain}`;
  }
  
  if (typeof opts.maxAge === 'number') {
    cookie += `; Max-Age=${Math.floor(opts.maxAge)}`;
  }
  
  if (opts.expires instanceof Date) {
    cookie += `; Expires=${opts.expires.toUTCString()}`;
  }
  
  if (opts.httpOnly) {
    cookie += '; HttpOnly';
  }
  
  if (opts.secure) {
    cookie += '; Secure';
  }
  
  if (opts.sameSite) {
    cookie += `; SameSite=${opts.sameSite}`;
  }
  
  if (opts.partitioned) {
    cookie += '; Partitioned';
  }
  
  return cookie;
}

/**
 * Create a cookie that deletes an existing cookie
 */
function createDeleteCookie(
  name: string,
  options: Partial<CookieOptions> = {}
): string {
  return serializeCookie(name, '', {
    ...options,
    maxAge: 0,
    expires: new Date(0)
  });
}

export {
  serializeCookie,
  createDeleteCookie,
  isValidCookieName,
  CookieOptions,
  DEFAULT_OPTIONS
};
```

### Cookie Parsing

```typescript
// src/cookies/parser.ts

/**
 * Parse a Cookie header string into key-value pairs
 * 
 * @param cookieHeader - Raw Cookie header value
 * @returns Object with cookie name-value pairs
 */
function parseCookies(cookieHeader: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  
  if (!cookieHeader || typeof cookieHeader !== 'string') {
    return cookies;
  }
  
  // Split by semicolon
  const pairs = cookieHeader.split(';');
  
  for (const pair of pairs) {
    const trimmed = pair.trim();
    
    // Find first equals sign (value may contain =)
    const equalsIndex = trimmed.indexOf('=');
    
    if (equalsIndex === -1) {
      continue;  // Skip malformed pairs
    }
    
    const name = trimmed.substring(0, equalsIndex).trim();
    const value = trimmed.substring(equalsIndex + 1).trim();
    
    if (name && !cookies.hasOwnProperty(name)) {
      try {
        // Decode URI-encoded value
        cookies[name] = decodeURIComponent(value);
      } catch {
        // Keep raw value if decode fails
        cookies[name] = value;
      }
    }
  }
  
  return cookies;
}

/**
 * Get a specific cookie from header
 */
function getCookie(cookieHeader: string, name: string): string | undefined {
  const cookies = parseCookies(cookieHeader);
  return cookies[name];
}

/**
 * Check if a cookie exists in header
 */
function hasCookie(cookieHeader: string, name: string): boolean {
  const cookies = parseCookies(cookieHeader);
  return name in cookies;
}

export { parseCookies, getCookie, hasCookie };
```

### Cookie Handler

```typescript
// src/cookies/handler.ts

import { serializeCookie, createDeleteCookie, CookieOptions } from './serializer';
import { parseCookies, getCookie, hasCookie } from './parser';

/**
 * Cookie names used by AuthSystem
 */
export const COOKIE_NAMES = {
  FINGERPRINT: '__Secure-Fpt',
  REFRESH_TOKEN: '__Secure-Ref',
  SESSION: '__Host-Sid'
} as const;

/**
 * High-level cookie management
 */
class CookieHandler {
  private defaultOptions: Partial<CookieOptions>;
  
  constructor(defaultOptions: Partial<CookieOptions> = {}) {
    this.defaultOptions = {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      path: '/',
      ...defaultOptions
    };
  }
  
  /**
   * Create a Set-Cookie header value
   */
  serialize(
    name: string,
    value: string,
    options: CookieOptions = {}
  ): string {
    return serializeCookie(name, value, {
      ...this.defaultOptions,
      ...options
    });
  }
  
  /**
   * Create a cookie deletion header
   */
  delete(name: string, options: Partial<CookieOptions> = {}): string {
    return createDeleteCookie(name, {
      ...this.defaultOptions,
      ...options
    });
  }
  
  /**
   * Parse Cookie header into object
   */
  parse(cookieHeader: string): Record<string, string> {
    return parseCookies(cookieHeader);
  }
  
  /**
   * Get a specific cookie value
   */
  get(cookieHeader: string, name: string): string | undefined {
    return getCookie(cookieHeader, name);
  }
  
  /**
   * Check if cookie exists
   */
  has(cookieHeader: string, name: string): boolean {
    return hasCookie(cookieHeader, name);
  }
  
  /**
   * Create fingerprint cookie
   */
  createFingerprintCookie(value: string, maxAge?: number): string {
    return this.serialize(COOKIE_NAMES.FINGERPRINT, value, {
      maxAge,
      sameSite: 'Strict'
    });
  }
  
  /**
   * Create refresh token cookie
   */
  createRefreshTokenCookie(value: string, maxAgeSeconds: number = 30 * 24 * 60 * 60): string {
    return this.serialize(COOKIE_NAMES.REFRESH_TOKEN, value, {
      maxAge: maxAgeSeconds,
      sameSite: 'Strict'
    });
  }
  
  /**
   * Get fingerprint from request
   */
  getFingerprint(cookieHeader: string): string | undefined {
    return this.get(cookieHeader, COOKIE_NAMES.FINGERPRINT);
  }
  
  /**
   * Get refresh token from request
   */
  getRefreshToken(cookieHeader: string): string | undefined {
    return this.get(cookieHeader, COOKIE_NAMES.REFRESH_TOKEN);
  }
  
  /**
   * Create all logout cookies (clear auth cookies)
   */
  createLogoutCookies(): string[] {
    return [
      this.delete(COOKIE_NAMES.FINGERPRINT),
      this.delete(COOKIE_NAMES.REFRESH_TOKEN)
    ];
  }
}

export { CookieHandler, COOKIE_NAMES };
```

### Cookie Index

```typescript
// src/cookies/index.ts

export { serializeCookie, createDeleteCookie, isValidCookieName, CookieOptions, DEFAULT_OPTIONS } from './serializer';
export { parseCookies, getCookie, hasCookie } from './parser';
export { CookieHandler, COOKIE_NAMES } from './handler';
```

### Testing Cookies

```typescript
async function testCookies(): Promise<void> {
  console.log('Testing Cookie Library...\n');
  
  const handler = new CookieHandler();
  
  // Test serialization
  console.log('Serializing cookies...');
  
  const basicCookie = handler.serialize('test', 'value');
  console.log('Basic:', basicCookie);
  
  const secureCookie = handler.serialize('__Secure-Token', 'abc123', {
    maxAge: 3600,
    sameSite: 'Strict'
  });
  console.log('Secure:', secureCookie);
  
  // Test fingerprint cookie
  const fptCookie = handler.createFingerprintCookie('fingerprint123');
  console.log('Fingerprint:', fptCookie);
  
  // Test refresh token cookie
  const refCookie = handler.createRefreshTokenCookie('refresh456');
  console.log('Refresh:', refCookie);
  
  // Test parsing
  console.log('\nParsing cookies...');
  
  const cookieHeader = '__Secure-Fpt=abc; __Secure-Ref=xyz; session=123';
  const parsed = handler.parse(cookieHeader);
  console.log('Parsed:', parsed);
  
  // Test get
  const fpt = handler.getFingerprint(cookieHeader);
  console.log('Fingerprint value:', fpt);
  
  const ref = handler.getRefreshToken(cookieHeader);
  console.log('Refresh value:', ref);
  
  // Test deletion
  console.log('\nLogout cookies...');
  const logoutCookies = handler.createLogoutCookies();
  logoutCookies.forEach(c => console.log(' ', c));
  
  // Test prefix validation
  console.log('\nPrefix validation...');
  
  try {
    serializeCookie('__Secure-Bad', 'value', { secure: false });
    console.log('❌ Should have thrown for missing Secure');
  } catch (e) {
    console.log('✅ Correctly rejected __Secure- without Secure');
  }
  
  try {
    serializeCookie('__Host-Bad', 'value', { secure: true, domain: 'example.com' });
    console.log('❌ Should have thrown for Domain attribute');
  } catch (e) {
    console.log('✅ Correctly rejected __Host- with Domain');
  }
}

testCookies();
```

### Integration: Complete Token Security Flow

```typescript
import { TokenFingerprinter } from './fingerprint';
import { CookieHandler } from './cookies';
import { createRS256Token, verifyRS256Token } from './jwt';

/**
 * Complete token creation with fingerprinting
 */
async function createSecureToken(
  userId: string,
  privateKey: CryptoKey,
  keyId: string
): Promise<{
  accessToken: string;
  cookies: string[];
}> {
  const fingerprinter = new TokenFingerprinter();
  const cookieHandler = new CookieHandler();
  
  // Generate fingerprint
  const { claim, raw } = await fingerprinter.create();
  
  // Create access token with fingerprint hash
  const accessToken = await createRS256Token(
    {
      sub: userId,
      ...claim  // Includes fpt claim
    },
    privateKey,
    keyId,
    { expiresIn: 900 }  // 15 minutes
  );
  
  // Create cookies
  const cookies = [
    cookieHandler.createFingerprintCookie(raw, 900)
  ];
  
  return { accessToken, cookies };
}

/**
 * Complete token verification with fingerprinting
 */
async function verifySecureToken(
  authHeader: string | undefined,
  cookieHeader: string | undefined,
  getPublicKey: (kid: string) => Promise<CryptoKey | null>
): Promise<{
  valid: boolean;
  userId?: string;
  error?: string;
}> {
  // Extract token from Authorization header
  if (!authHeader?.startsWith('Bearer ')) {
    return { valid: false, error: 'MISSING_TOKEN' };
  }
  
  const token = authHeader.slice(7);
  
  // Verify JWT signature and claims
  const jwtResult = await verifyRS256Token(token, getPublicKey);
  
  if (!jwtResult.valid) {
    return { valid: false, error: jwtResult.error };
  }
  
  // Verify fingerprint
  const fingerprinter = new TokenFingerprinter();
  const fpResult = await fingerprinter.validate(
    cookieHeader,
    jwtResult.payload!
  );
  
  if (!fpResult.valid) {
    return { valid: false, error: fpResult.error };
  }
  
  return {
    valid: true,
    userId: jwtResult.payload!.sub as string
  };
}
```

### Exercise 6.2

1. Create `src/cookies/serializer.ts`, `src/cookies/parser.ts`, and `src/cookies/handler.ts`
2. Test that `__Secure-` prefix validation works
3. Implement a full flow: create token with fingerprint, verify with matching cookie
4. Verify that token without fingerprint cookie is rejected

---

## Summary

In this part, you learned:

1. **Token Fingerprinting** — Binding JWTs to browser sessions with OWASP-recommended pattern
2. **Cookie Security** — HttpOnly, Secure, SameSite attributes and cookie prefixes
3. **Cookie Library** — Framework-agnostic serialization and parsing

### Files Created

```
src/
├── crypto/
│   └── ...              # (from Parts 1-2)
├── password/
│   └── ...              # (from Part 3)
├── jwt/
│   └── ...              # (from Parts 4-5)
├── fingerprint/
│   ├── generate.ts      # Fingerprint creation
│   ├── validate.ts      # Fingerprint validation
│   └── index.ts         # TokenFingerprinter class
└── cookies/
    ├── serializer.ts    # Set-Cookie creation
    ├── parser.ts        # Cookie header parsing
    ├── handler.ts       # High-level cookie API
    └── index.ts         # Public exports
```

### Key Takeaways

- Token fingerprinting adds a second factor that XSS cannot steal
- Always use `HttpOnly` for security-sensitive cookies
- `SameSite=Strict` provides CSRF protection
- Cookie prefixes (`__Secure-`, `__Host-`) enforce security requirements
- Never trust tokens without validating the fingerprint

### Security Checklist

Before moving on, ensure:
- [ ] Fingerprint hash in JWT matches hash of cookie value
- [ ] Missing fingerprint cookie causes token rejection
- [ ] Wrong fingerprint causes token rejection
- [ ] Cookies have HttpOnly, Secure, SameSite attributes
- [ ] Cookie prefix requirements are enforced

### Next Steps

In **Part 7: Session Management**, we'll implement:
- Session store design with storage abstraction
- Refresh token flow with rotation
- Multi-device session tracking and revocation
