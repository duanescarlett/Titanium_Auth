# Part 10: Production Readiness

You've built a complete authentication system. Before deploying to production, we need to conduct a security audit, optimize performance, implement monitoring, and consider deployment best practices.

---

## Table of Contents

1. [Security Audit Checklist](#1-security-audit-checklist)
2. [Performance Optimization](#2-performance-optimization)
3. [Monitoring, Logging, and Deployment](#3-monitoring-logging-and-deployment)

---

## 1. Security Audit Checklist

### Cryptographic Security

```typescript
// src/audit/crypto-audit.ts

/**
 * Cryptographic security checklist
 */
export const CryptoAuditChecklist = {
  passwordHashing: {
    algorithm: 'PBKDF2-HMAC-SHA256',
    requirements: [
      '✓ Minimum 600,000 iterations (OWASP 2023)',
      '✓ 16+ byte random salt per password',
      '✓ 32+ byte derived key output',
      '✓ Salt stored with hash (PHC format)',
      '✓ Timing-safe comparison for verification'
    ],
    verify: async () => {
      const { hashPassword, verifyPassword } = await import('../password');
      
      // Test hash format
      const hash = await hashPassword('test');
      const parts = hash.split('$');
      
      return {
        validFormat: parts[1] === 'pbkdf2-sha256',
        iterations: parseInt(parts[2]) >= 600000,
        saltLength: atob(parts[3].replace(/-/g, '+').replace(/_/g, '/')).length >= 16
      };
    }
  },
  
  jwtSigning: {
    algorithm: 'RS256 (RSA-SHA256)',
    requirements: [
      '✓ 2048-bit RSA keys minimum',
      '✓ Private key securely stored',
      '✓ Key rotation implemented',
      '✓ Key ID (kid) in JWT header',
      '✓ Signature verified before trusting claims'
    ]
  },
  
  tokenFingerprinting: {
    requirements: [
      '✓ 32+ byte random fingerprint',
      '✓ SHA-256 hash stored in JWT',
      '✓ Raw value in HttpOnly cookie',
      '✓ Constant-time comparison'
    ]
  },
  
  randomGeneration: {
    requirements: [
      '✓ Using crypto.getRandomValues()',
      '✓ Not using Math.random()',
      '✓ Sufficient entropy (256+ bits for tokens)'
    ]
  }
};

/**
 * Run cryptographic audit
 */
export async function runCryptoAudit(): Promise<{
  passed: boolean;
  results: Record<string, { passed: boolean; details: string }>;
}> {
  const results: Record<string, { passed: boolean; details: string }> = {};
  
  // Test password hashing
  try {
    const hashResult = await CryptoAuditChecklist.passwordHashing.verify();
    results.passwordHashing = {
      passed: hashResult.validFormat && hashResult.iterations && hashResult.saltLength,
      details: JSON.stringify(hashResult)
    };
  } catch (error) {
    results.passwordHashing = { passed: false, details: String(error) };
  }
  
  // Additional checks would go here
  
  const allPassed = Object.values(results).every(r => r.passed);
  
  return { passed: allPassed, results };
}
```

### Token Security Audit

```typescript
// src/audit/token-audit.ts

/**
 * Token security checklist
 */
export const TokenSecurityChecklist = {
  accessToken: {
    requirements: [
      '✓ Short lifetime (15 minutes or less)',
      '✓ Contains minimal claims (sub, iat, exp)',
      '✓ No sensitive data in payload',
      '✓ Signature verified on every request',
      '✓ Issuer (iss) and audience (aud) validated',
      '✓ Token fingerprint validated'
    ],
    antiPatterns: [
      '✗ Storing in localStorage (XSS vulnerable)',
      '✗ Including password hash in claims',
      '✗ No expiration or very long expiration',
      '✗ Trusting claims without verification'
    ]
  },
  
  refreshToken: {
    requirements: [
      '✓ Opaque random string (not JWT)',
      '✓ Stored hashed in database',
      '✓ HttpOnly, Secure, SameSite cookie',
      '✓ Token rotation on each use',
      '✓ Token family for reuse detection',
      '✓ Bound to session/device'
    ],
    antiPatterns: [
      '✗ Storing raw token in database',
      '✗ No rotation (same token reused)',
      '✗ Accessible to JavaScript',
      '✗ No revocation mechanism'
    ]
  },
  
  cookies: {
    requirements: [
      '✓ HttpOnly attribute set',
      '✓ Secure attribute set (HTTPS only)',
      '✓ SameSite=Strict or Lax',
      '✓ __Secure- or __Host- prefix',
      '✓ Appropriate Path restriction',
      '✓ No sensitive data in cookie value'
    ]
  }
};

/**
 * Audit a JWT for security issues
 */
export function auditJWT(token: string): {
  issues: string[];
  warnings: string[];
  info: Record<string, unknown>;
} {
  const issues: string[] = [];
  const warnings: string[] = [];
  
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      issues.push('Invalid JWT format');
      return { issues, warnings, info: {} };
    }
    
    // Decode header
    const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
    
    // Decode payload
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    
    // Check algorithm
    if (header.alg === 'none') {
      issues.push('CRITICAL: Algorithm is "none" - no signature verification!');
    } else if (header.alg === 'HS256') {
      warnings.push('Consider using RS256 for asymmetric signing');
    }
    
    // Check for kid
    if (!header.kid) {
      warnings.push('No key ID (kid) in header - complicates key rotation');
    }
    
    // Check expiration
    if (!payload.exp) {
      issues.push('No expiration (exp) claim - token never expires!');
    } else {
      const expiresAt = new Date(payload.exp * 1000);
      const now = new Date();
      const lifetimeMinutes = (payload.exp - payload.iat) / 60;
      
      if (expiresAt < now) {
        warnings.push(`Token is expired (${expiresAt.toISOString()})`);
      }
      
      if (lifetimeMinutes > 60) {
        warnings.push(`Long token lifetime: ${lifetimeMinutes} minutes`);
      }
    }
    
    // Check for sensitive data
    const sensitiveFields = ['password', 'passwordHash', 'secret', 'apiKey', 'ssn', 'creditCard'];
    for (const field of sensitiveFields) {
      if (payload[field]) {
        issues.push(`CRITICAL: Sensitive field "${field}" in token payload!`);
      }
    }
    
    // Check fingerprint
    if (!payload.fpt) {
      warnings.push('No fingerprint (fpt) claim - token not bound to session');
    }
    
    return {
      issues,
      warnings,
      info: {
        algorithm: header.alg,
        keyId: header.kid,
        subject: payload.sub,
        issuer: payload.iss,
        audience: payload.aud,
        issuedAt: payload.iat ? new Date(payload.iat * 1000).toISOString() : undefined,
        expiresAt: payload.exp ? new Date(payload.exp * 1000).toISOString() : undefined,
        hasFingerprint: !!payload.fpt
      }
    };
  } catch (error) {
    issues.push(`Failed to parse token: ${error}`);
    return { issues, warnings, info: {} };
  }
}
```

### Security Headers

```typescript
// src/audit/headers.ts

/**
 * Security headers for auth endpoints
 */
export const SecurityHeaders = {
  /**
   * Headers that MUST be set on all responses
   */
  required: {
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '0',  // Deprecated, can cause issues
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'"
  },
  
  /**
   * Headers for API responses
   */
  api: {
    'Cache-Control': 'no-store, max-age=0',
    'Pragma': 'no-cache'
  },
  
  /**
   * CORS headers (adjust origins for your use case)
   */
  cors: {
    'Access-Control-Allow-Origin': 'https://your-domain.com',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Max-Age': '86400'
  }
};

/**
 * Express middleware for security headers
 */
export function securityHeadersMiddleware() {
  return (req: any, res: any, next: any) => {
    // Set required headers
    for (const [header, value] of Object.entries(SecurityHeaders.required)) {
      res.setHeader(header, value);
    }
    
    // Set API headers
    for (const [header, value] of Object.entries(SecurityHeaders.api)) {
      res.setHeader(header, value);
    }
    
    next();
  };
}

/**
 * Audit response headers
 */
export function auditResponseHeaders(headers: Record<string, string>): {
  missing: string[];
  incorrect: { header: string; expected: string; actual: string }[];
} {
  const missing: string[] = [];
  const incorrect: { header: string; expected: string; actual: string }[] = [];
  
  for (const [header, expectedValue] of Object.entries(SecurityHeaders.required)) {
    const actual = headers[header.toLowerCase()];
    
    if (!actual) {
      missing.push(header);
    } else if (actual !== expectedValue) {
      incorrect.push({ header, expected: expectedValue, actual });
    }
  }
  
  return { missing, incorrect };
}
```

### Complete Security Checklist

```typescript
// src/audit/checklist.ts

/**
 * Complete production security checklist
 */
export const ProductionSecurityChecklist = {
  
  // ─────────────────────────────────────────────────────────────────────────
  // Authentication
  // ─────────────────────────────────────────────────────────────────────────
  
  authentication: [
    { id: 'AUTH-001', check: 'Passwords hashed with PBKDF2/Argon2/bcrypt', critical: true },
    { id: 'AUTH-002', check: 'Password minimum length ≥ 12 characters', critical: true },
    { id: 'AUTH-003', check: 'Account lockout after failed attempts', critical: false },
    { id: 'AUTH-004', check: 'Timing-safe password comparison', critical: true },
    { id: 'AUTH-005', check: 'No user enumeration via error messages', critical: true },
    { id: 'AUTH-006', check: 'Email verification implemented', critical: false },
    { id: 'AUTH-007', check: 'Password reset uses secure tokens', critical: true },
  ],
  
  // ─────────────────────────────────────────────────────────────────────────
  // Session Management
  // ─────────────────────────────────────────────────────────────────────────
  
  sessionManagement: [
    { id: 'SESS-001', check: 'Access tokens have short lifetime (≤15 min)', critical: true },
    { id: 'SESS-002', check: 'Refresh tokens stored hashed', critical: true },
    { id: 'SESS-003', check: 'Token rotation on refresh', critical: true },
    { id: 'SESS-004', check: 'Token reuse detection', critical: true },
    { id: 'SESS-005', check: 'Session revocation works immediately', critical: true },
    { id: 'SESS-006', check: 'Logout invalidates all tokens', critical: true },
    { id: 'SESS-007', check: 'Session limit per user enforced', critical: false },
    { id: 'SESS-008', check: 'Token fingerprinting implemented', critical: true },
  ],
  
  // ─────────────────────────────────────────────────────────────────────────
  // Cookie Security
  // ─────────────────────────────────────────────────────────────────────────
  
  cookieSecurity: [
    { id: 'COOK-001', check: 'HttpOnly flag on auth cookies', critical: true },
    { id: 'COOK-002', check: 'Secure flag on all cookies', critical: true },
    { id: 'COOK-003', check: 'SameSite=Strict or Lax', critical: true },
    { id: 'COOK-004', check: '__Secure- or __Host- prefix used', critical: false },
    { id: 'COOK-005', check: 'Cookie path restricted appropriately', critical: false },
  ],
  
  // ─────────────────────────────────────────────────────────────────────────
  // Transport Security
  // ─────────────────────────────────────────────────────────────────────────
  
  transportSecurity: [
    { id: 'TRANS-001', check: 'HTTPS enforced (HSTS header)', critical: true },
    { id: 'TRANS-002', check: 'TLS 1.2 or higher required', critical: true },
    { id: 'TRANS-003', check: 'Certificate valid and not expiring soon', critical: true },
    { id: 'TRANS-004', check: 'HTTP redirects to HTTPS', critical: true },
  ],
  
  // ─────────────────────────────────────────────────────────────────────────
  // Key Management
  // ─────────────────────────────────────────────────────────────────────────
  
  keyManagement: [
    { id: 'KEY-001', check: 'Private keys not in version control', critical: true },
    { id: 'KEY-002', check: 'Keys stored with appropriate permissions', critical: true },
    { id: 'KEY-003', check: 'Key rotation process documented', critical: true },
    { id: 'KEY-004', check: 'Old keys retained for grace period', critical: true },
    { id: 'KEY-005', check: 'JWKS endpoint available for verification', critical: false },
  ],
  
  // ─────────────────────────────────────────────────────────────────────────
  // Input Validation
  // ─────────────────────────────────────────────────────────────────────────
  
  inputValidation: [
    { id: 'INPUT-001', check: 'Email format validated', critical: true },
    { id: 'INPUT-002', check: 'Password complexity enforced', critical: true },
    { id: 'INPUT-003', check: 'Input length limits enforced', critical: true },
    { id: 'INPUT-004', check: 'SQL injection prevented (parameterized queries)', critical: true },
    { id: 'INPUT-005', check: 'NoSQL injection prevented', critical: true },
  ],
  
  // ─────────────────────────────────────────────────────────────────────────
  // Logging & Monitoring
  // ─────────────────────────────────────────────────────────────────────────
  
  loggingMonitoring: [
    { id: 'LOG-001', check: 'Failed login attempts logged', critical: true },
    { id: 'LOG-002', check: 'Successful logins logged', critical: true },
    { id: 'LOG-003', check: 'Password changes logged', critical: true },
    { id: 'LOG-004', check: 'No passwords/tokens in logs', critical: true },
    { id: 'LOG-005', check: 'Alerting on suspicious activity', critical: false },
    { id: 'LOG-006', check: 'Log retention policy defined', critical: false },
  ]
};

/**
 * Generate audit report
 */
export function generateAuditReport(
  results: Record<string, { id: string; passed: boolean; notes?: string }[]>
): string {
  let report = '# Security Audit Report\n\n';
  report += `Generated: ${new Date().toISOString()}\n\n`;
  
  let totalPassed = 0;
  let totalFailed = 0;
  let criticalFailed = 0;
  
  for (const [category, checks] of Object.entries(results)) {
    report += `## ${category}\n\n`;
    report += '| ID | Status | Check | Notes |\n';
    report += '|----|--------|-------|-------|\n';
    
    for (const check of checks) {
      const status = check.passed ? '✅' : '❌';
      report += `| ${check.id} | ${status} | ${check.id} | ${check.notes ?? ''} |\n`;
      
      if (check.passed) {
        totalPassed++;
      } else {
        totalFailed++;
        // Check if critical
        const checkDef = Object.values(ProductionSecurityChecklist)
          .flat()
          .find(c => c.id === check.id);
        if (checkDef?.critical) {
          criticalFailed++;
        }
      }
    }
    
    report += '\n';
  }
  
  report += '## Summary\n\n';
  report += `- **Passed:** ${totalPassed}\n`;
  report += `- **Failed:** ${totalFailed}\n`;
  report += `- **Critical Failed:** ${criticalFailed}\n\n`;
  
  if (criticalFailed > 0) {
    report += '⚠️ **DO NOT DEPLOY** - Critical security issues found!\n';
  } else if (totalFailed > 0) {
    report += '⚡ Review failed checks before deploying.\n';
  } else {
    report += '✅ All security checks passed!\n';
  }
  
  return report;
}
```

### Exercise 10.1

1. Create `src/audit/crypto-audit.ts` and run it against your implementation
2. Create `src/audit/token-audit.ts` and test your JWTs
3. Generate a security audit report for your system
4. Address any critical issues found

---

## 2. Performance Optimization

### Password Hashing Performance

```typescript
// src/performance/password-tuning.ts

import { getSubtle, getUniversalCrypto } from '../crypto/universal';

/**
 * Benchmark password hashing at different iteration counts
 */
export async function benchmarkPasswordHashing(): Promise<{
  iterations: number;
  averageMs: number;
  recommendation: string;
}[]> {
  const subtle = getSubtle();
  const crypto = getUniversalCrypto();
  
  const iterationCounts = [100000, 200000, 400000, 600000, 800000, 1000000];
  const results: { iterations: number; averageMs: number; recommendation: string }[] = [];
  
  const password = new TextEncoder().encode('TestPassword123!');
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  
  for (const iterations of iterationCounts) {
    const times: number[] = [];
    
    // Run 5 iterations for average
    for (let i = 0; i < 5; i++) {
      const start = performance.now();
      
      const keyMaterial = await subtle.importKey(
        'raw',
        password,
        'PBKDF2',
        false,
        ['deriveBits']
      );
      
      await subtle.deriveBits(
        {
          name: 'PBKDF2',
          salt,
          iterations,
          hash: 'SHA-256'
        },
        keyMaterial,
        256
      );
      
      times.push(performance.now() - start);
    }
    
    const averageMs = times.reduce((a, b) => a + b) / times.length;
    
    let recommendation: string;
    if (averageMs < 100) {
      recommendation = '⚠️ Too fast - increase iterations';
    } else if (averageMs < 250) {
      recommendation = '✓ Good for high-traffic APIs';
    } else if (averageMs < 500) {
      recommendation = '✓ Recommended for most applications';
    } else if (averageMs < 1000) {
      recommendation = '✓ Good security, may impact UX';
    } else {
      recommendation = '⚠️ May be too slow for UX';
    }
    
    results.push({ iterations, averageMs: Math.round(averageMs), recommendation });
  }
  
  return results;
}

/**
 * Calculate optimal iterations for target time
 */
export async function calculateOptimalIterations(
  targetMs: number = 250
): Promise<number> {
  const benchmarks = await benchmarkPasswordHashing();
  
  // Find the iteration count closest to target time
  let closest = benchmarks[0];
  let minDiff = Math.abs(closest.averageMs - targetMs);
  
  for (const result of benchmarks) {
    const diff = Math.abs(result.averageMs - targetMs);
    if (diff < minDiff) {
      minDiff = diff;
      closest = result;
    }
  }
  
  return closest.iterations;
}
```

### JWT Performance

```typescript
// src/performance/jwt-tuning.ts

import { generateRS256KeyPair } from '../jwt/keys';
import { createRS256Token, verifyRS256Token } from '../jwt/rs256';

/**
 * Benchmark JWT operations
 */
export async function benchmarkJWT(): Promise<{
  operation: string;
  averageMs: number;
  opsPerSecond: number;
}[]> {
  const { privateKey, publicKey } = await generateRS256KeyPair();
  const keyId = 'bench-key';
  const results: { operation: string; averageMs: number; opsPerSecond: number }[] = [];
  
  // Benchmark token creation
  const createTimes: number[] = [];
  for (let i = 0; i < 100; i++) {
    const start = performance.now();
    await createRS256Token(
      { sub: 'user_123', email: 'test@example.com' },
      privateKey,
      keyId,
      { expiresIn: 900 }
    );
    createTimes.push(performance.now() - start);
  }
  
  const createAvg = createTimes.reduce((a, b) => a + b) / createTimes.length;
  results.push({
    operation: 'Create RS256 Token',
    averageMs: Math.round(createAvg * 100) / 100,
    opsPerSecond: Math.round(1000 / createAvg)
  });
  
  // Create a token for verification benchmark
  const token = await createRS256Token(
    { sub: 'user_123', email: 'test@example.com' },
    privateKey,
    keyId,
    { expiresIn: 900 }
  );
  
  // Benchmark token verification
  const verifyTimes: number[] = [];
  for (let i = 0; i < 100; i++) {
    const start = performance.now();
    await verifyRS256Token(token, async () => publicKey);
    verifyTimes.push(performance.now() - start);
  }
  
  const verifyAvg = verifyTimes.reduce((a, b) => a + b) / verifyTimes.length;
  results.push({
    operation: 'Verify RS256 Token',
    averageMs: Math.round(verifyAvg * 100) / 100,
    opsPerSecond: Math.round(1000 / verifyAvg)
  });
  
  // Benchmark key pair generation
  const keygenTimes: number[] = [];
  for (let i = 0; i < 10; i++) {
    const start = performance.now();
    await generateRS256KeyPair();
    keygenTimes.push(performance.now() - start);
  }
  
  const keygenAvg = keygenTimes.reduce((a, b) => a + b) / keygenTimes.length;
  results.push({
    operation: 'Generate RS256 Key Pair',
    averageMs: Math.round(keygenAvg * 100) / 100,
    opsPerSecond: Math.round(1000 / keygenAvg)
  });
  
  return results;
}
```

### Caching Strategies

```typescript
// src/performance/caching.ts

/**
 * LRU Cache for public keys
 */
export class KeyCache {
  private cache: Map<string, { key: CryptoKey; expiresAt: number }>;
  private maxSize: number;
  private ttlMs: number;
  
  constructor(maxSize: number = 10, ttlSeconds: number = 300) {
    this.cache = new Map();
    this.maxSize = maxSize;
    this.ttlMs = ttlSeconds * 1000;
  }
  
  get(keyId: string): CryptoKey | null {
    const entry = this.cache.get(keyId);
    
    if (!entry) {
      return null;
    }
    
    if (Date.now() > entry.expiresAt) {
      this.cache.delete(keyId);
      return null;
    }
    
    // Move to end (most recently used)
    this.cache.delete(keyId);
    this.cache.set(keyId, entry);
    
    return entry.key;
  }
  
  set(keyId: string, key: CryptoKey): void {
    // Evict oldest if at capacity
    if (this.cache.size >= this.maxSize) {
      const oldest = this.cache.keys().next().value;
      if (oldest) {
        this.cache.delete(oldest);
      }
    }
    
    this.cache.set(keyId, {
      key,
      expiresAt: Date.now() + this.ttlMs
    });
  }
  
  clear(): void {
    this.cache.clear();
  }
  
  size(): number {
    return this.cache.size;
  }
}

/**
 * Cached key provider wrapper
 */
export function createCachedKeyProvider(
  provider: { getPublicKey(kid: string): Promise<CryptoKey | null> },
  cache: KeyCache = new KeyCache()
): (kid: string) => Promise<CryptoKey | null> {
  return async (kid: string) => {
    // Check cache first
    const cached = cache.get(kid);
    if (cached) {
      return cached;
    }
    
    // Fetch from provider
    const key = await provider.getPublicKey(kid);
    
    if (key) {
      cache.set(kid, key);
    }
    
    return key;
  };
}

/**
 * Session cache for reducing database lookups
 */
export class SessionCache {
  private cache: Map<string, { data: unknown; expiresAt: number }>;
  private ttlMs: number;
  
  constructor(ttlSeconds: number = 60) {
    this.cache = new Map();
    this.ttlMs = ttlSeconds * 1000;
  }
  
  get<T>(key: string): T | null {
    const entry = this.cache.get(key);
    
    if (!entry || Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return null;
    }
    
    return entry.data as T;
  }
  
  set(key: string, data: unknown): void {
    this.cache.set(key, {
      data,
      expiresAt: Date.now() + this.ttlMs
    });
  }
  
  invalidate(key: string): void {
    this.cache.delete(key);
  }
  
  invalidatePattern(pattern: RegExp): number {
    let count = 0;
    for (const key of this.cache.keys()) {
      if (pattern.test(key)) {
        this.cache.delete(key);
        count++;
      }
    }
    return count;
  }
}
```

### Connection Pooling

```typescript
// src/performance/database.ts

/**
 * Database connection pool configuration
 */
export interface PoolConfig {
  /** Minimum connections to maintain */
  min: number;
  
  /** Maximum connections allowed */
  max: number;
  
  /** Idle timeout in milliseconds */
  idleTimeoutMs: number;
  
  /** Connection timeout in milliseconds */
  connectionTimeoutMs: number;
  
  /** Statement timeout in milliseconds */
  statementTimeoutMs: number;
}

/**
 * Recommended pool settings for auth workloads
 */
export const RecommendedPoolConfig: PoolConfig = {
  min: 2,
  max: 10,
  idleTimeoutMs: 30000,
  connectionTimeoutMs: 5000,
  statementTimeoutMs: 10000
};

/**
 * Example: PostgreSQL pool setup
 */
export const PostgresPoolExample = `
import { Pool } from 'pg';

const pool = new Pool({
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT ?? '5432'),
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  
  // Pool configuration
  min: 2,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
  
  // SSL for production
  ssl: process.env.NODE_ENV === 'production' ? {
    rejectUnauthorized: true,
    ca: process.env.DB_CA_CERT
  } : undefined
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  await pool.end();
});
`;

/**
 * Example: Redis connection for session cache
 */
export const RedisExample = `
import Redis from 'ioredis';

const redis = new Redis({
  host: process.env.REDIS_HOST,
  port: parseInt(process.env.REDIS_PORT ?? '6379'),
  password: process.env.REDIS_PASSWORD,
  
  // Connection settings
  maxRetriesPerRequest: 3,
  enableReadyCheck: true,
  
  // TLS for production
  tls: process.env.NODE_ENV === 'production' ? {} : undefined
});

// Session store using Redis
class RedisSessionStore implements SessionStore {
  async findByTokenHash(hash: string) {
    const data = await redis.get(\`session:token:\${hash}\`);
    return data ? JSON.parse(data) : null;
  }
  
  async create(input) {
    const session = { /* ... */ };
    const pipeline = redis.pipeline();
    
    pipeline.setex(
      \`session:\${session.id}\`, 
      30 * 24 * 60 * 60,  // 30 days
      JSON.stringify(session)
    );
    
    pipeline.setex(
      \`session:token:\${session.refreshTokenHash}\`,
      30 * 24 * 60 * 60,
      JSON.stringify(session)
    );
    
    await pipeline.exec();
    return session;
  }
}
`;
```

### Exercise 10.2

1. Run password hashing benchmark on your target hardware
2. Benchmark JWT creation and verification
3. Implement key caching for your application
4. Configure database connection pooling appropriately

---

## 3. Monitoring, Logging, and Deployment

### Structured Logging

```typescript
// src/logging/logger.ts

/**
 * Log levels
 */
export enum LogLevel {
  DEBUG = 'debug',
  INFO = 'info',
  WARN = 'warn',
  ERROR = 'error'
}

/**
 * Structured log entry
 */
export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  service: string;
  correlationId?: string;
  userId?: string;
  sessionId?: string;
  action?: string;
  duration?: number;
  error?: {
    name: string;
    message: string;
    stack?: string;
  };
  metadata?: Record<string, unknown>;
}

/**
 * Auth-specific log events
 */
export const AuthLogEvents = {
  // Authentication events
  LOGIN_SUCCESS: 'auth.login.success',
  LOGIN_FAILURE: 'auth.login.failure',
  LOGOUT: 'auth.logout',
  LOGOUT_ALL: 'auth.logout.all',
  
  // Registration events
  REGISTER_SUCCESS: 'auth.register.success',
  REGISTER_FAILURE: 'auth.register.failure',
  
  // Token events
  TOKEN_REFRESH: 'auth.token.refresh',
  TOKEN_REFRESH_FAILURE: 'auth.token.refresh.failure',
  TOKEN_REUSE_DETECTED: 'auth.token.reuse',
  TOKEN_VERIFY_FAILURE: 'auth.token.verify.failure',
  
  // Session events
  SESSION_CREATED: 'auth.session.created',
  SESSION_REVOKED: 'auth.session.revoked',
  SESSION_EXPIRED: 'auth.session.expired',
  
  // Security events
  FINGERPRINT_MISMATCH: 'auth.security.fingerprint_mismatch',
  RATE_LIMIT_EXCEEDED: 'auth.security.rate_limit',
  SUSPICIOUS_ACTIVITY: 'auth.security.suspicious',
  
  // Password events
  PASSWORD_CHANGED: 'auth.password.changed',
  PASSWORD_RESET_REQUESTED: 'auth.password.reset_requested',
  PASSWORD_RESET_COMPLETED: 'auth.password.reset_completed'
} as const;

/**
 * Logger class for auth events
 */
export class AuthLogger {
  private serviceName: string;
  private minLevel: LogLevel;
  
  constructor(serviceName: string = 'auth-service', minLevel: LogLevel = LogLevel.INFO) {
    this.serviceName = serviceName;
    this.minLevel = minLevel;
  }
  
  private shouldLog(level: LogLevel): boolean {
    const levels = [LogLevel.DEBUG, LogLevel.INFO, LogLevel.WARN, LogLevel.ERROR];
    return levels.indexOf(level) >= levels.indexOf(this.minLevel);
  }
  
  private formatEntry(entry: LogEntry): string {
    // Remove sensitive data
    const sanitized = this.sanitize(entry);
    return JSON.stringify(sanitized);
  }
  
  private sanitize(entry: LogEntry): LogEntry {
    const sanitized = { ...entry };
    
    // Remove any sensitive fields that might have leaked in
    if (sanitized.metadata) {
      const sensitiveKeys = ['password', 'token', 'refreshToken', 'accessToken', 'secret'];
      for (const key of sensitiveKeys) {
        if (key in sanitized.metadata) {
          sanitized.metadata[key] = '[REDACTED]';
        }
      }
    }
    
    return sanitized;
  }
  
  log(level: LogLevel, message: string, data: Partial<LogEntry> = {}): void {
    if (!this.shouldLog(level)) return;
    
    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      service: this.serviceName,
      ...data
    };
    
    const formatted = this.formatEntry(entry);
    
    switch (level) {
      case LogLevel.ERROR:
        console.error(formatted);
        break;
      case LogLevel.WARN:
        console.warn(formatted);
        break;
      default:
        console.log(formatted);
    }
  }
  
  // Convenience methods
  debug(message: string, data?: Partial<LogEntry>): void {
    this.log(LogLevel.DEBUG, message, data);
  }
  
  info(message: string, data?: Partial<LogEntry>): void {
    this.log(LogLevel.INFO, message, data);
  }
  
  warn(message: string, data?: Partial<LogEntry>): void {
    this.log(LogLevel.WARN, message, data);
  }
  
  error(message: string, error?: Error, data?: Partial<LogEntry>): void {
    this.log(LogLevel.ERROR, message, {
      ...data,
      error: error ? {
        name: error.name,
        message: error.message,
        stack: error.stack
      } : undefined
    });
  }
  
  // Auth-specific logging methods
  loginSuccess(userId: string, sessionId: string, metadata?: Record<string, unknown>): void {
    this.info(AuthLogEvents.LOGIN_SUCCESS, {
      userId,
      sessionId,
      action: AuthLogEvents.LOGIN_SUCCESS,
      metadata
    });
  }
  
  loginFailure(email: string, reason: string, metadata?: Record<string, unknown>): void {
    this.warn(AuthLogEvents.LOGIN_FAILURE, {
      action: AuthLogEvents.LOGIN_FAILURE,
      metadata: {
        email: this.maskEmail(email),
        reason,
        ...metadata
      }
    });
  }
  
  tokenReuseDetected(userId: string, sessionId: string, metadata?: Record<string, unknown>): void {
    this.error(AuthLogEvents.TOKEN_REUSE_DETECTED, undefined, {
      userId,
      sessionId,
      action: AuthLogEvents.TOKEN_REUSE_DETECTED,
      metadata
    });
  }
  
  private maskEmail(email: string): string {
    const [local, domain] = email.split('@');
    if (!domain) return '***@***';
    
    const maskedLocal = local.length > 2 
      ? local[0] + '*'.repeat(local.length - 2) + local[local.length - 1]
      : '***';
    
    return `${maskedLocal}@${domain}`;
  }
}

// Singleton instance
export const logger = new AuthLogger();
```

### Metrics

```typescript
// src/monitoring/metrics.ts

/**
 * Metric types
 */
export type MetricType = 'counter' | 'gauge' | 'histogram';

/**
 * Metric definition
 */
export interface MetricDefinition {
  name: string;
  type: MetricType;
  help: string;
  labels?: string[];
}

/**
 * Auth service metrics
 */
export const AuthMetrics: Record<string, MetricDefinition> = {
  // Request metrics
  authRequestsTotal: {
    name: 'auth_requests_total',
    type: 'counter',
    help: 'Total number of auth requests',
    labels: ['endpoint', 'status']
  },
  
  authRequestDuration: {
    name: 'auth_request_duration_seconds',
    type: 'histogram',
    help: 'Auth request duration in seconds',
    labels: ['endpoint']
  },
  
  // Authentication metrics
  loginAttemptsTotal: {
    name: 'auth_login_attempts_total',
    type: 'counter',
    help: 'Total login attempts',
    labels: ['status']  // success, failure, blocked
  },
  
  registrationsTotal: {
    name: 'auth_registrations_total',
    type: 'counter',
    help: 'Total user registrations',
    labels: ['status']
  },
  
  // Session metrics
  activeSessions: {
    name: 'auth_active_sessions',
    type: 'gauge',
    help: 'Current number of active sessions'
  },
  
  tokenRefreshesTotal: {
    name: 'auth_token_refreshes_total',
    type: 'counter',
    help: 'Total token refresh operations',
    labels: ['status']
  },
  
  tokenReuseDetections: {
    name: 'auth_token_reuse_detections_total',
    type: 'counter',
    help: 'Token reuse detection events'
  },
  
  // Performance metrics
  passwordHashDuration: {
    name: 'auth_password_hash_duration_seconds',
    type: 'histogram',
    help: 'Password hashing duration in seconds'
  },
  
  jwtSignDuration: {
    name: 'auth_jwt_sign_duration_seconds',
    type: 'histogram',
    help: 'JWT signing duration in seconds'
  },
  
  jwtVerifyDuration: {
    name: 'auth_jwt_verify_duration_seconds',
    type: 'histogram',
    help: 'JWT verification duration in seconds'
  }
};

/**
 * Simple metrics collector (replace with Prometheus client in production)
 */
export class MetricsCollector {
  private counters: Map<string, number> = new Map();
  private gauges: Map<string, number> = new Map();
  private histograms: Map<string, number[]> = new Map();
  
  increment(name: string, labels: Record<string, string> = {}, value: number = 1): void {
    const key = this.makeKey(name, labels);
    const current = this.counters.get(key) ?? 0;
    this.counters.set(key, current + value);
  }
  
  gauge(name: string, value: number, labels: Record<string, string> = {}): void {
    const key = this.makeKey(name, labels);
    this.gauges.set(key, value);
  }
  
  histogram(name: string, value: number, labels: Record<string, string> = {}): void {
    const key = this.makeKey(name, labels);
    const values = this.histograms.get(key) ?? [];
    values.push(value);
    this.histograms.set(key, values);
  }
  
  private makeKey(name: string, labels: Record<string, string>): string {
    const labelStr = Object.entries(labels)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}="${v}"`)
      .join(',');
    
    return labelStr ? `${name}{${labelStr}}` : name;
  }
  
  /**
   * Export metrics in Prometheus format
   */
  exportPrometheus(): string {
    const lines: string[] = [];
    
    // Export counters
    for (const [key, value] of this.counters) {
      lines.push(`${key} ${value}`);
    }
    
    // Export gauges
    for (const [key, value] of this.gauges) {
      lines.push(`${key} ${value}`);
    }
    
    // Export histograms (simplified)
    for (const [key, values] of this.histograms) {
      if (values.length === 0) continue;
      
      const sum = values.reduce((a, b) => a + b, 0);
      const count = values.length;
      
      lines.push(`${key}_sum ${sum}`);
      lines.push(`${key}_count ${count}`);
    }
    
    return lines.join('\n');
  }
  
  /**
   * Get metrics as JSON
   */
  exportJSON(): Record<string, unknown> {
    return {
      counters: Object.fromEntries(this.counters),
      gauges: Object.fromEntries(this.gauges),
      histograms: Object.fromEntries(
        Array.from(this.histograms.entries()).map(([key, values]) => [
          key,
          {
            count: values.length,
            sum: values.reduce((a, b) => a + b, 0),
            avg: values.length > 0 ? values.reduce((a, b) => a + b, 0) / values.length : 0,
            min: values.length > 0 ? Math.min(...values) : 0,
            max: values.length > 0 ? Math.max(...values) : 0
          }
        ])
      )
    };
  }
}

// Singleton instance
export const metrics = new MetricsCollector();
```

### Health Checks

```typescript
// src/monitoring/health.ts

/**
 * Health check result
 */
export interface HealthCheckResult {
  status: 'healthy' | 'degraded' | 'unhealthy';
  checks: {
    name: string;
    status: 'pass' | 'fail';
    duration?: number;
    message?: string;
  }[];
  version?: string;
  uptime?: number;
}

/**
 * Health check function type
 */
export type HealthCheck = () => Promise<{
  status: 'pass' | 'fail';
  message?: string;
}>;

/**
 * Health check manager
 */
export class HealthChecker {
  private checks: Map<string, HealthCheck> = new Map();
  private startTime: number = Date.now();
  private version: string;
  
  constructor(version: string = '1.0.0') {
    this.version = version;
  }
  
  /**
   * Register a health check
   */
  register(name: string, check: HealthCheck): void {
    this.checks.set(name, check);
  }
  
  /**
   * Run all health checks
   */
  async check(): Promise<HealthCheckResult> {
    const results: HealthCheckResult['checks'] = [];
    
    for (const [name, check] of this.checks) {
      const start = Date.now();
      
      try {
        const result = await Promise.race([
          check(),
          new Promise<{ status: 'fail'; message: string }>((_, reject) =>
            setTimeout(() => reject(new Error('Timeout')), 5000)
          )
        ]);
        
        results.push({
          name,
          status: result.status,
          duration: Date.now() - start,
          message: result.message
        });
      } catch (error) {
        results.push({
          name,
          status: 'fail',
          duration: Date.now() - start,
          message: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    }
    
    // Determine overall status
    const failedChecks = results.filter(r => r.status === 'fail');
    let status: HealthCheckResult['status'];
    
    if (failedChecks.length === 0) {
      status = 'healthy';
    } else if (failedChecks.length < results.length) {
      status = 'degraded';
    } else {
      status = 'unhealthy';
    }
    
    return {
      status,
      checks: results,
      version: this.version,
      uptime: Math.floor((Date.now() - this.startTime) / 1000)
    };
  }
}

/**
 * Common health checks
 */
export const CommonHealthChecks = {
  /**
   * Database connectivity check
   */
  database: (pool: { query: (sql: string) => Promise<unknown> }): HealthCheck => {
    return async () => {
      try {
        await pool.query('SELECT 1');
        return { status: 'pass' };
      } catch (error) {
        return { 
          status: 'fail', 
          message: error instanceof Error ? error.message : 'Database unreachable' 
        };
      }
    };
  },
  
  /**
   * Redis connectivity check
   */
  redis: (client: { ping: () => Promise<string> }): HealthCheck => {
    return async () => {
      try {
        const result = await client.ping();
        return { status: result === 'PONG' ? 'pass' : 'fail' };
      } catch (error) {
        return { 
          status: 'fail', 
          message: error instanceof Error ? error.message : 'Redis unreachable' 
        };
      }
    };
  },
  
  /**
   * Key provider check
   */
  keyProvider: (provider: { getSigningKey: () => Promise<unknown> }): HealthCheck => {
    return async () => {
      try {
        await provider.getSigningKey();
        return { status: 'pass' };
      } catch (error) {
        return { 
          status: 'fail', 
          message: 'Signing key unavailable' 
        };
      }
    };
  },
  
  /**
   * Memory usage check
   */
  memory: (maxHeapMB: number = 512): HealthCheck => {
    return async () => {
      if (typeof process === 'undefined') {
        return { status: 'pass', message: 'N/A in browser' };
      }
      
      const used = process.memoryUsage();
      const heapMB = used.heapUsed / 1024 / 1024;
      
      if (heapMB > maxHeapMB) {
        return { 
          status: 'fail', 
          message: `Heap usage ${Math.round(heapMB)}MB exceeds ${maxHeapMB}MB` 
        };
      }
      
      return { 
        status: 'pass', 
        message: `Heap: ${Math.round(heapMB)}MB` 
      };
    };
  }
};
```

### Deployment Configuration

```typescript
// src/deployment/config.ts

/**
 * Environment-specific configuration
 */
export interface DeploymentConfig {
  // Server
  port: number;
  host: string;
  trustProxy: boolean;
  
  // Database
  databaseUrl: string;
  databasePoolMin: number;
  databasePoolMax: number;
  
  // Redis (optional)
  redisUrl?: string;
  
  // Keys
  keysPath: string;
  keyRotationDays: number;
  
  // Auth settings
  accessTokenLifetime: number;
  refreshTokenLifetimeDays: number;
  maxSessionsPerUser: number;
  
  // Security
  corsOrigins: string[];
  rateLimitRequests: number;
  rateLimitWindowMs: number;
  
  // Logging
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  
  // Features
  enableFingerprinting: boolean;
  enableTokenRotation: boolean;
  requireEmailVerification: boolean;
}

/**
 * Load configuration from environment
 */
export function loadConfig(): DeploymentConfig {
  const env = process.env;
  
  return {
    // Server
    port: parseInt(env.PORT ?? '3000'),
    host: env.HOST ?? '0.0.0.0',
    trustProxy: env.TRUST_PROXY === 'true',
    
    // Database
    databaseUrl: env.DATABASE_URL ?? '',
    databasePoolMin: parseInt(env.DB_POOL_MIN ?? '2'),
    databasePoolMax: parseInt(env.DB_POOL_MAX ?? '10'),
    
    // Redis
    redisUrl: env.REDIS_URL,
    
    // Keys
    keysPath: env.KEYS_PATH ?? './keys',
    keyRotationDays: parseInt(env.KEY_ROTATION_DAYS ?? '90'),
    
    // Auth settings
    accessTokenLifetime: parseInt(env.ACCESS_TOKEN_LIFETIME ?? '900'),
    refreshTokenLifetimeDays: parseInt(env.REFRESH_TOKEN_LIFETIME_DAYS ?? '30'),
    maxSessionsPerUser: parseInt(env.MAX_SESSIONS_PER_USER ?? '5'),
    
    // Security
    corsOrigins: (env.CORS_ORIGINS ?? '').split(',').filter(Boolean),
    rateLimitRequests: parseInt(env.RATE_LIMIT_REQUESTS ?? '100'),
    rateLimitWindowMs: parseInt(env.RATE_LIMIT_WINDOW_MS ?? '60000'),
    
    // Logging
    logLevel: (env.LOG_LEVEL ?? 'info') as DeploymentConfig['logLevel'],
    
    // Features
    enableFingerprinting: env.ENABLE_FINGERPRINTING !== 'false',
    enableTokenRotation: env.ENABLE_TOKEN_ROTATION !== 'false',
    requireEmailVerification: env.REQUIRE_EMAIL_VERIFICATION === 'true'
  };
}

/**
 * Validate configuration
 */
export function validateConfig(config: DeploymentConfig): string[] {
  const errors: string[] = [];
  
  if (!config.databaseUrl) {
    errors.push('DATABASE_URL is required');
  }
  
  if (config.accessTokenLifetime > 3600) {
    errors.push('ACCESS_TOKEN_LIFETIME should be 3600 seconds (1 hour) or less');
  }
  
  if (config.corsOrigins.length === 0 && process.env.NODE_ENV === 'production') {
    errors.push('CORS_ORIGINS should be set in production');
  }
  
  if (config.refreshTokenLifetimeDays > 90) {
    errors.push('REFRESH_TOKEN_LIFETIME_DAYS should be 90 days or less');
  }
  
  return errors;
}

/**
 * Example .env file content
 */
export const ExampleEnvFile = `
# Server
PORT=3000
HOST=0.0.0.0
TRUST_PROXY=true
NODE_ENV=production

# Database
DATABASE_URL=postgres://user:pass@localhost:5432/auth
DB_POOL_MIN=2
DB_POOL_MAX=10

# Redis (optional, for session caching)
REDIS_URL=redis://localhost:6379

# Keys
KEYS_PATH=/app/keys
KEY_ROTATION_DAYS=90

# Auth Settings
ACCESS_TOKEN_LIFETIME=900
REFRESH_TOKEN_LIFETIME_DAYS=30
MAX_SESSIONS_PER_USER=5

# Security
CORS_ORIGINS=https://app.example.com,https://admin.example.com
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW_MS=60000

# Logging
LOG_LEVEL=info

# Features
ENABLE_FINGERPRINTING=true
ENABLE_TOKEN_ROTATION=true
REQUIRE_EMAIL_VERIFICATION=false
`;
```

### Docker Deployment

```dockerfile
# Dockerfile

# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
RUN npm ci

# Copy source
COPY . .

# Build
RUN npm run build

# Production stage
FROM node:20-alpine AS production

# Security: run as non-root
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

WORKDIR /app

# Copy built files
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package*.json ./

# Create keys directory
RUN mkdir -p /app/keys && chown nodejs:nodejs /app/keys

USER nodejs

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

EXPOSE 3000

CMD ["node", "dist/server.js"]
```

```yaml
# docker-compose.yml

version: '3.8'

services:
  auth:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - DATABASE_URL=postgres://auth:authpass@postgres:5432/auth
      - REDIS_URL=redis://redis:6379
      - KEYS_PATH=/app/keys
    volumes:
      - auth-keys:/app/keys
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_started
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_USER=auth
      - POSTGRES_PASSWORD=authpass
      - POSTGRES_DB=auth
    volumes:
      - postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U auth"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    volumes:
      - redis-data:/data
    restart: unless-stopped

volumes:
  auth-keys:
  postgres-data:
  redis-data:
```

### Exercise 10.3

1. Create a structured logging implementation
2. Implement health checks for your dependencies
3. Create a Dockerfile for your auth service
4. Configure metrics collection for Prometheus

---

## Summary

In this final part, you learned:

1. **Security Audit** — Comprehensive checklists for cryptography, tokens, and configuration
2. **Performance Optimization** — Benchmarking, caching, and connection pooling
3. **Monitoring & Deployment** — Logging, metrics, health checks, and containerization

### Files Created

```
src/
├── audit/
│   ├── crypto-audit.ts  # Cryptographic security checks
│   ├── token-audit.ts   # Token security analysis
│   ├── headers.ts       # Security headers
│   └── checklist.ts     # Complete security checklist
├── performance/
│   ├── password-tuning.ts  # Password hashing benchmarks
│   ├── jwt-tuning.ts    # JWT performance
│   ├── caching.ts       # Key and session caching
│   └── database.ts      # Connection pooling
├── logging/
│   └── logger.ts        # Structured logging
├── monitoring/
│   ├── metrics.ts       # Metrics collection
│   └── health.ts        # Health checks
└── deployment/
    └── config.ts        # Environment configuration
```

### Production Checklist

Before deploying:

- [ ] All critical security checks pass
- [ ] Password hashing benchmarked for target latency
- [ ] Key caching implemented
- [ ] Database connection pooling configured
- [ ] Structured logging enabled
- [ ] Metrics collection set up
- [ ] Health checks implemented
- [ ] HTTPS enforced
- [ ] Security headers configured
- [ ] Environment variables properly set
- [ ] Secrets management in place
- [ ] Backup and recovery tested

### Congratulations! 🎉

You've completed the entire tutorial series and built a production-ready authentication system from scratch using only native Web Crypto APIs. Your system includes:

- **Zero dependencies** for core auth logic
- **RS256 JWT signing** with key rotation
- **PBKDF2 password hashing** (600k iterations)
- **Token fingerprinting** for theft prevention
- **Refresh token rotation** with reuse detection
- **Multi-device session management**
- **Framework-agnostic design**
- **Comprehensive testing utilities**
- **Production monitoring and deployment**

### Next Steps

To continue improving your auth system:

1. **Add email verification** with secure tokens
2. **Implement password reset** flow
3. **Add MFA support** (TOTP, WebAuthn)
4. **Create admin dashboard** for user management
5. **Implement audit logging** for compliance
6. **Add account lockout** after failed attempts
7. **Consider Argon2** when available in Web Crypto

### Resources

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [JWT Best Practices (RFC 8725)](https://datatracker.ietf.org/doc/html/rfc8725)
- [Web Crypto API Specification](https://www.w3.org/TR/WebCryptoAPI/)

Thank you for following along! 🚀
