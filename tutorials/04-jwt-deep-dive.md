# Part 4: JWT Deep Dive

JSON Web Tokens (JWTs) are the foundation of our authentication system. In this part, we'll understand JWT structure, implement HS256 signing, and then upgrade to RS256 for asymmetric cryptography.

---

## Table of Contents

1. [JWT Structure Explained](#1-jwt-structure-explained)
2. [Building a JWT Library (HS256)](#2-building-a-jwt-library-hs256)
3. [Upgrading to RS256](#3-upgrading-to-rs256)

---

## 1. JWT Structure Explained

### What is a JWT?

A JWT (pronounced "jot") is a compact, URL-safe token format for securely transmitting claims between parties. It consists of three parts separated by dots:

```
xxxxx.yyyyy.zzzzz
  │      │      │
  │      │      └── Signature
  │      └── Payload (claims)
  └── Header
```

Each part is Base64URL encoded.

### The Header

The header describes the token type and signing algorithm:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key_abc123"
}
```

| Field | Description |
|-------|-------------|
| `alg` | Algorithm: HS256 (HMAC), RS256 (RSA), etc. |
| `typ` | Token type (always "JWT") |
| `kid` | Key ID (for key rotation support) |

### The Payload (Claims)

The payload contains claims — statements about the user and token:

```json
{
  "sub": "user_123",
  "iat": 1703548800,
  "exp": 1703549700,
  "iss": "https://auth.example.com",
  "aud": "https://api.example.com",
  "jti": "token_xyz789",
  "fpt": "abc123def456"
}
```

#### Registered Claims (Standard)

| Claim | Name | Description |
|-------|------|-------------|
| `sub` | Subject | User identifier |
| `iat` | Issued At | Unix timestamp of token creation |
| `exp` | Expiration | Unix timestamp when token expires |
| `nbf` | Not Before | Token not valid before this time |
| `iss` | Issuer | Who issued the token |
| `aud` | Audience | Who the token is intended for |
| `jti` | JWT ID | Unique identifier for the token |

#### Custom Claims (Our System)

| Claim | Description |
|-------|-------------|
| `fpt` | Fingerprint hash (SHA-256 of cookie value) |
| `sid` | Session ID (links to session store) |
| `role` | User role (for authorization) |

### The Signature

The signature ensures the token hasn't been tampered with:

```
RSASHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  privateKey
)
```

### Visual Breakdown

```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleV9hYmMxMjMifQ
.
eyJzdWIiOiJ1c2VyXzEyMyIsImlhdCI6MTcwMzU0ODgwMCwiZXhwIjoxNzAzNTQ5NzAwfQ
.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

↓ Decoded ↓

Header:  {"alg":"RS256","typ":"JWT","kid":"key_abc123"}
Payload: {"sub":"user_123","iat":1703548800,"exp":1703549700}
Signature: <binary signature data>
```

### Security Considerations

1. **Never trust unverified tokens** — Always verify the signature first
2. **Always check expiration** — Reject expired tokens
3. **Validate issuer/audience** — Ensure tokens are for your system
4. **Use appropriate algorithms** — Never allow "none" algorithm
5. **Keep payloads small** — Tokens are sent with every request

---

## 2. Building a JWT Library (HS256)

Before implementing RS256, let's understand JWT signing with the simpler HS256 (HMAC-SHA256) algorithm.

### Types and Interfaces

```typescript
// src/jwt/types.ts

/**
 * JWT Header
 */
export interface JWTHeader {
  alg: 'HS256' | 'RS256';
  typ: 'JWT';
  kid?: string;  // Key ID for rotation
}

/**
 * JWT Payload (claims)
 */
export interface JWTPayload {
  // Registered claims
  sub?: string;    // Subject (user ID)
  iat?: number;    // Issued at (Unix timestamp)
  exp?: number;    // Expiration (Unix timestamp)
  nbf?: number;    // Not before (Unix timestamp)
  iss?: string;    // Issuer
  aud?: string | string[];  // Audience
  jti?: string;    // JWT ID
  
  // Custom claims
  fpt?: string;    // Fingerprint hash
  sid?: string;    // Session ID
  
  // Allow additional claims
  [key: string]: unknown;
}

/**
 * Options for token creation
 */
export interface TokenOptions {
  expiresIn?: number;   // Seconds until expiration
  issuer?: string;
  audience?: string;
  jwtId?: string;
}

/**
 * Options for token verification
 */
export interface VerifyOptions {
  issuer?: string;
  audience?: string;
  clockTolerance?: number;  // Seconds of clock skew allowed
}

/**
 * Result of token verification
 */
export interface VerifyResult {
  valid: boolean;
  error?: string;
  header?: JWTHeader;
  payload?: JWTPayload;
}
```

### HS256 Implementation

```typescript
// src/jwt/hs256.ts

import { encode as base64urlEncode, decode as base64urlDecode, decodeToString } from '../crypto/base64url';
import { createHMACKey, hmacSign, hmacVerify } from '../crypto/hmac';
import { generateToken } from '../crypto/random';
import { JWTHeader, JWTPayload, TokenOptions, VerifyOptions, VerifyResult } from './types';

/**
 * Encode a segment (header or payload) to Base64URL
 */
function encodeSegment(data: object): string {
  const json = JSON.stringify(data);
  return base64urlEncode(json);
}

/**
 * Decode a Base64URL segment to object
 */
function decodeSegment<T>(segment: string): T {
  const json = decodeToString(segment);
  return JSON.parse(json);
}

/**
 * Create a JWT signed with HS256 (HMAC-SHA256)
 */
async function createHS256Token(
  payload: JWTPayload,
  secret: string,
  options: TokenOptions = {}
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  
  // Build header
  const header: JWTHeader = {
    alg: 'HS256',
    typ: 'JWT'
  };
  
  // Build payload with standard claims
  const fullPayload: JWTPayload = {
    ...payload,
    iat: payload.iat ?? now,
    exp: payload.exp ?? now + (options.expiresIn ?? 3600),
    jti: payload.jti ?? options.jwtId ?? generateToken(16)
  };
  
  // Add optional claims
  if (options.issuer) fullPayload.iss = options.issuer;
  if (options.audience) fullPayload.aud = options.audience;
  
  // Encode header and payload
  const encodedHeader = encodeSegment(header);
  const encodedPayload = encodeSegment(fullPayload);
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  
  // Sign
  const key = await createHMACKey(secret);
  const signature = await hmacSign(key, signingInput);
  const encodedSignature = base64urlEncode(new Uint8Array(signature));
  
  return `${signingInput}.${encodedSignature}`;
}

/**
 * Verify an HS256 JWT
 */
async function verifyHS256Token(
  token: string,
  secret: string,
  options: VerifyOptions = {}
): Promise<VerifyResult> {
  // Split token
  const parts = token.split('.');
  
  if (parts.length !== 3) {
    return { valid: false, error: 'INVALID_TOKEN_FORMAT' };
  }
  
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  
  // Decode header and payload
  let header: JWTHeader;
  let payload: JWTPayload;
  
  try {
    header = decodeSegment<JWTHeader>(encodedHeader);
    payload = decodeSegment<JWTPayload>(encodedPayload);
  } catch {
    return { valid: false, error: 'INVALID_TOKEN_ENCODING' };
  }
  
  // Verify algorithm
  if (header.alg !== 'HS256') {
    return { valid: false, error: 'INVALID_ALGORITHM' };
  }
  
  // Verify signature
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const key = await createHMACKey(secret);
  const signatureBytes = base64urlDecode(encodedSignature);
  
  const isSignatureValid = await hmacVerify(key, signatureBytes, signingInput);
  
  if (!isSignatureValid) {
    return { valid: false, error: 'INVALID_SIGNATURE' };
  }
  
  // Verify claims
  const now = Math.floor(Date.now() / 1000);
  const clockTolerance = options.clockTolerance ?? 0;
  
  // Check expiration
  if (payload.exp !== undefined && payload.exp < now - clockTolerance) {
    return { valid: false, error: 'TOKEN_EXPIRED', header, payload };
  }
  
  // Check not-before
  if (payload.nbf !== undefined && payload.nbf > now + clockTolerance) {
    return { valid: false, error: 'TOKEN_NOT_YET_VALID', header, payload };
  }
  
  // Check issuer
  if (options.issuer !== undefined && payload.iss !== options.issuer) {
    return { valid: false, error: 'INVALID_ISSUER', header, payload };
  }
  
  // Check audience
  if (options.audience !== undefined) {
    const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!audiences.includes(options.audience)) {
      return { valid: false, error: 'INVALID_AUDIENCE', header, payload };
    }
  }
  
  return { valid: true, header, payload };
}

export { createHS256Token, verifyHS256Token };
```

### Testing HS256

```typescript
async function testHS256(): Promise<void> {
  console.log('Testing HS256 JWT...\n');
  
  const secret = 'my-super-secret-key-at-least-32-bytes';
  
  // Create token
  const token = await createHS256Token(
    { sub: 'user_123', role: 'admin' },
    secret,
    { expiresIn: 3600, issuer: 'auth.example.com' }
  );
  
  console.log('Token:', token);
  console.log('Parts:', token.split('.').length);
  
  // Decode without verification (for inspection)
  const [header, payload] = token.split('.').slice(0, 2).map(
    s => JSON.parse(decodeToString(s))
  );
  console.log('\nHeader:', header);
  console.log('Payload:', payload);
  
  // Verify valid token
  const result = await verifyHS256Token(token, secret, { issuer: 'auth.example.com' });
  console.log('\nVerification:', result.valid ? '✅ Valid' : '❌ Invalid');
  
  // Verify with wrong secret
  const wrongSecret = await verifyHS256Token(token, 'wrong-secret');
  console.log('Wrong secret:', !wrongSecret.valid ? '✅ Rejected' : '❌ Accepted');
  
  // Verify expired token
  const expiredToken = await createHS256Token(
    { sub: 'user_123' },
    secret,
    { expiresIn: -1 }  // Already expired
  );
  const expiredResult = await verifyHS256Token(expiredToken, secret);
  console.log('Expired token:', expiredResult.error === 'TOKEN_EXPIRED' ? '✅ Rejected' : '❌ Wrong error');
}

testHS256();
```

### Exercise 4.1

1. Create `src/jwt/types.ts` with all interfaces
2. Create `src/jwt/hs256.ts` with HS256 signing and verification
3. Create a token and try tampering with the payload — verify it's rejected

---

## 3. Upgrading to RS256

### Why RS256?

HS256 uses a **symmetric** key — the same secret signs and verifies tokens. This has limitations:

| HS256 (Symmetric) | RS256 (Asymmetric) |
|-------------------|-------------------|
| Same key for sign & verify | Private key signs, public key verifies |
| Secret must be shared | Only public key needs sharing |
| Can't verify without signing ability | Read-only verification possible |
| Simple, fast | Slightly slower, more secure |

RS256 is better for:
- **Microservices** — Share public key, keep private key secure
- **Third-party verification** — Clients can verify without your secret
- **Key rotation** — Rotate private key, publish new public key

### RSA Key Concepts

```
┌─────────────────────────────────────────────────────────────────┐
│                        RSA Key Pair                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Private Key                      Public Key                    │
│   ───────────                      ──────────                    │
│   • Keep SECRET                    • Can be shared freely        │
│   • Used to SIGN tokens            • Used to VERIFY tokens       │
│   • Stored on auth server          • Published to all services   │
│   • Never transmitted              • Via JWKS endpoint           │
│                                                                  │
│   ┌─────────┐                      ┌─────────┐                   │
│   │ d, p, q │   ──────────────►    │  n, e   │                   │
│   └─────────┘   Can derive         └─────────┘                   │
│                 public from                                       │
│                 private                                           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Implementation

```typescript
// src/jwt/rs256.ts

import { getSubtle } from '../crypto/universal';
import { encode as base64urlEncode, decode as base64urlDecode, decodeToString } from '../crypto/base64url';
import { generateToken } from '../crypto/random';
import { JWTHeader, JWTPayload, TokenOptions, VerifyOptions, VerifyResult } from './types';

/**
 * Encode a segment (header or payload) to Base64URL
 */
function encodeSegment(data: object): string {
  const json = JSON.stringify(data);
  return base64urlEncode(json);
}

/**
 * Decode a Base64URL segment to object
 */
function decodeSegment<T>(segment: string): T {
  const json = decodeToString(segment);
  return JSON.parse(json);
}

/**
 * Create a JWT signed with RS256 (RSA-SHA256)
 */
async function createRS256Token(
  payload: JWTPayload,
  privateKey: CryptoKey,
  keyId: string,
  options: TokenOptions = {}
): Promise<string> {
  const subtle = getSubtle();
  const now = Math.floor(Date.now() / 1000);
  
  // Build header with key ID
  const header: JWTHeader = {
    alg: 'RS256',
    typ: 'JWT',
    kid: keyId
  };
  
  // Build payload with standard claims
  const fullPayload: JWTPayload = {
    ...payload,
    iat: payload.iat ?? now,
    exp: payload.exp ?? now + (options.expiresIn ?? 900),  // 15 min default
    jti: payload.jti ?? options.jwtId ?? generateToken(16)
  };
  
  // Add optional claims
  if (options.issuer) fullPayload.iss = options.issuer;
  if (options.audience) fullPayload.aud = options.audience;
  
  // Encode header and payload
  const encodedHeader = encodeSegment(header);
  const encodedPayload = encodeSegment(fullPayload);
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  
  // Sign with RSA-SHA256
  const signingInputBytes = new TextEncoder().encode(signingInput);
  const signatureBuffer = await subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    privateKey,
    signingInputBytes
  );
  
  const encodedSignature = base64urlEncode(new Uint8Array(signatureBuffer));
  
  return `${signingInput}.${encodedSignature}`;
}

/**
 * Verify an RS256 JWT
 * 
 * @param token - The JWT to verify
 * @param getPublicKey - Function to retrieve public key by key ID
 * @param options - Verification options
 */
async function verifyRS256Token(
  token: string,
  getPublicKey: (keyId: string) => Promise<CryptoKey | null>,
  options: VerifyOptions = {}
): Promise<VerifyResult> {
  const subtle = getSubtle();
  
  // Split token
  const parts = token.split('.');
  
  if (parts.length !== 3) {
    return { valid: false, error: 'INVALID_TOKEN_FORMAT' };
  }
  
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  
  // Decode header and payload
  let header: JWTHeader;
  let payload: JWTPayload;
  
  try {
    header = decodeSegment<JWTHeader>(encodedHeader);
    payload = decodeSegment<JWTPayload>(encodedPayload);
  } catch {
    return { valid: false, error: 'INVALID_TOKEN_ENCODING' };
  }
  
  // Verify algorithm
  if (header.alg !== 'RS256') {
    return { valid: false, error: 'INVALID_ALGORITHM' };
  }
  
  // Get public key by kid
  if (!header.kid) {
    return { valid: false, error: 'MISSING_KEY_ID' };
  }
  
  const publicKey = await getPublicKey(header.kid);
  
  if (!publicKey) {
    return { valid: false, error: 'UNKNOWN_KEY_ID' };
  }
  
  // Verify signature
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signingInputBytes = new TextEncoder().encode(signingInput);
  const signatureBytes = base64urlDecode(encodedSignature);
  
  const isSignatureValid = await subtle.verify(
    { name: 'RSASSA-PKCS1-v1_5' },
    publicKey,
    signatureBytes,
    signingInputBytes
  );
  
  if (!isSignatureValid) {
    return { valid: false, error: 'INVALID_SIGNATURE' };
  }
  
  // Verify claims
  const now = Math.floor(Date.now() / 1000);
  const clockTolerance = options.clockTolerance ?? 0;
  
  // Check expiration
  if (payload.exp !== undefined && payload.exp < now - clockTolerance) {
    return { valid: false, error: 'TOKEN_EXPIRED', header, payload };
  }
  
  // Check not-before
  if (payload.nbf !== undefined && payload.nbf > now + clockTolerance) {
    return { valid: false, error: 'TOKEN_NOT_YET_VALID', header, payload };
  }
  
  // Check issuer
  if (options.issuer !== undefined && payload.iss !== options.issuer) {
    return { valid: false, error: 'INVALID_ISSUER', header, payload };
  }
  
  // Check audience
  if (options.audience !== undefined) {
    const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!audiences.includes(options.audience)) {
      return { valid: false, error: 'INVALID_AUDIENCE', header, payload };
    }
  }
  
  return { valid: true, header, payload };
}

/**
 * Decode a JWT without verification (for inspection only)
 * WARNING: Never trust data from an unverified token!
 */
function decodeToken(token: string): { header: JWTHeader; payload: JWTPayload } | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    
    return {
      header: decodeSegment<JWTHeader>(parts[0]),
      payload: decodeSegment<JWTPayload>(parts[1])
    };
  } catch {
    return null;
  }
}

export { createRS256Token, verifyRS256Token, decodeToken };
```

### Generating RSA Keys

```typescript
// src/jwt/keys.ts

import { getSubtle } from '../crypto/universal';

/**
 * Generate an RSA key pair for RS256 signing
 */
async function generateRSAKeyPair(): Promise<CryptoKeyPair> {
  const subtle = getSubtle();
  
  return subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,  // 2048 minimum, 4096 for long-lived keys
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),  // 65537
      hash: { name: 'SHA-256' }
    },
    true,  // extractable (needed for export)
    ['sign', 'verify']
  );
}

/**
 * Export public key to JWK format
 */
async function exportPublicKeyJWK(publicKey: CryptoKey): Promise<JsonWebKey> {
  const subtle = getSubtle();
  return subtle.exportKey('jwk', publicKey);
}

/**
 * Export private key to JWK format
 */
async function exportPrivateKeyJWK(privateKey: CryptoKey): Promise<JsonWebKey> {
  const subtle = getSubtle();
  return subtle.exportKey('jwk', privateKey);
}

/**
 * Import public key from JWK
 */
async function importPublicKeyJWK(jwk: JsonWebKey): Promise<CryptoKey> {
  const subtle = getSubtle();
  
  return subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } },
    true,
    ['verify']
  );
}

/**
 * Import private key from JWK
 */
async function importPrivateKeyJWK(jwk: JsonWebKey): Promise<CryptoKey> {
  const subtle = getSubtle();
  
  return subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } },
    true,
    ['sign']
  );
}

export {
  generateRSAKeyPair,
  exportPublicKeyJWK,
  exportPrivateKeyJWK,
  importPublicKeyJWK,
  importPrivateKeyJWK
};
```

### Testing RS256

```typescript
async function testRS256(): Promise<void> {
  console.log('Testing RS256 JWT...\n');
  
  // Generate key pair
  console.log('Generating RSA key pair...');
  const keyPair = await generateRSAKeyPair();
  const keyId = 'key_test_123';
  
  // Export for inspection
  const publicJWK = await exportPublicKeyJWK(keyPair.publicKey);
  console.log('Public key (n length):', publicJWK.n?.length, 'chars');
  
  // Create token
  const token = await createRS256Token(
    { sub: 'user_456', role: 'user' },
    keyPair.privateKey,
    keyId,
    { expiresIn: 900, issuer: 'auth.example.com' }
  );
  
  console.log('\nToken:', token.substring(0, 50) + '...');
  
  // Decode without verification
  const decoded = decodeToken(token);
  console.log('Header:', decoded?.header);
  console.log('Payload:', decoded?.payload);
  
  // Create key lookup function
  const keys = new Map<string, CryptoKey>();
  keys.set(keyId, keyPair.publicKey);
  
  const getPublicKey = async (kid: string) => keys.get(kid) ?? null;
  
  // Verify valid token
  const result = await verifyRS256Token(token, getPublicKey, {
    issuer: 'auth.example.com'
  });
  console.log('\nVerification:', result.valid ? '✅ Valid' : '❌ Invalid');
  
  // Verify with unknown key ID
  const unknownResult = await verifyRS256Token(token, async () => null);
  console.log('Unknown key:', unknownResult.error === 'UNKNOWN_KEY_ID' ? '✅ Rejected' : '❌ Wrong error');
  
  // Create tampered token
  const parts = token.split('.');
  const tamperedPayload = base64urlEncode(JSON.stringify({
    ...decoded?.payload,
    role: 'admin'  // Try to escalate privileges
  }));
  const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;
  
  const tamperedResult = await verifyRS256Token(tamperedToken, getPublicKey);
  console.log('Tampered token:', !tamperedResult.valid ? '✅ Rejected' : '❌ Accepted');
}

testRS256();
```

### Unified JWT Module

```typescript
// src/jwt/index.ts

import { createRS256Token, verifyRS256Token, decodeToken } from './rs256';
import { createHS256Token, verifyHS256Token } from './hs256';
import { generateRSAKeyPair, exportPublicKeyJWK, exportPrivateKeyJWK, importPublicKeyJWK, importPrivateKeyJWK } from './keys';
import type { JWTHeader, JWTPayload, TokenOptions, VerifyOptions, VerifyResult } from './types';

export {
  // RS256 (recommended)
  createRS256Token,
  verifyRS256Token,
  
  // HS256 (for testing/simple cases)
  createHS256Token,
  verifyHS256Token,
  
  // Utilities
  decodeToken,
  
  // Key management
  generateRSAKeyPair,
  exportPublicKeyJWK,
  exportPrivateKeyJWK,
  importPublicKeyJWK,
  importPrivateKeyJWK,
  
  // Types
  JWTHeader,
  JWTPayload,
  TokenOptions,
  VerifyOptions,
  VerifyResult
};
```

### Exercise 4.2

1. Create `src/jwt/rs256.ts` with RS256 signing and verification
2. Create `src/jwt/keys.ts` with key generation and export
3. Generate a key pair, create a token, export the public key to JWK
4. Try importing the public key and verifying the token

---

## Summary

In this part, you learned:

1. **JWT Structure** — Header, payload, signature with Base64URL encoding
2. **HS256 Signing** — Symmetric HMAC-SHA256 for simple use cases
3. **RS256 Signing** — Asymmetric RSA-SHA256 for microservices

### Files Created

```
src/
├── crypto/
│   └── ...           # (from Parts 1-3)
├── password/
│   └── ...           # (from Part 3)
└── jwt/
    ├── types.ts      # Type definitions
    ├── hs256.ts      # HMAC-SHA256 signing
    ├── rs256.ts      # RSA-SHA256 signing
    ├── keys.ts       # Key generation/import/export
    └── index.ts      # Public API
```

### Key Takeaways

- JWTs are three Base64URL-encoded parts: header, payload, signature
- HS256 is simpler but requires sharing the secret
- RS256 allows public key distribution for decentralized verification
- Always verify signature BEFORE trusting any claims
- Include `kid` in header for key rotation support

### Security Checklist

Before moving on, ensure:
- [ ] Tokens include expiration (`exp`) claim
- [ ] Signature verification rejects tampered tokens
- [ ] Unknown algorithms are rejected
- [ ] Key ID (`kid`) is included for rotation support
- [ ] You understand when to use HS256 vs RS256

### Next Steps

In **Part 5: Key Management**, we'll implement:
- RSA key pair storage (PEM and JWK formats)
- Filesystem persistence
- Key rotation with graceful transitions
- JWKS endpoint for public key distribution
