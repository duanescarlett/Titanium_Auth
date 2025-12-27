# Part 1: Foundations

Building a secure authentication system requires a solid understanding of cryptographic primitives. In this part, we'll explore the Web Crypto API, implement Base64URL encoding from scratch, and learn how to generate cryptographically secure random values.

---

## Table of Contents

1. [Understanding Web Crypto API](#1-understanding-web-crypto-api)
2. [Base64URL Encoding from Scratch](#2-base64url-encoding-from-scratch)
3. [Secure Random Generation](#3-secure-random-generation)

---

## 1. Understanding Web Crypto API

### What is Web Crypto API?

The Web Crypto API is a low-level interface for performing cryptographic operations in JavaScript. Unlike external libraries, it's built into all modern JavaScript runtimes:

- **Browsers** — Available globally as `window.crypto` or `crypto`
- **Node.js 16+** — Available as `crypto.webcrypto` or globally in Node 19+
- **Deno** — Available globally as `crypto`
- **Bun** — Available globally as `crypto`
- **Cloudflare Workers** — Available globally as `crypto`

### Why Use Web Crypto API?

| Advantage | Description |
|-----------|-------------|
| **Native Performance** | Implemented in C/C++, faster than JavaScript libraries |
| **Security** | Audited, maintained by browser/runtime vendors |
| **No Dependencies** | Zero supply chain risk |
| **Standardized** | W3C specification, consistent across platforms |

### The `crypto.subtle` Interface

All cryptographic operations live under `crypto.subtle`. The name "subtle" is intentional — it reminds developers that cryptography is nuanced and easy to misuse.

```typescript
// Available in all modern runtimes
const subtle = crypto.subtle;

// Key operations
subtle.generateKey()    // Generate cryptographic keys
subtle.importKey()      // Import existing keys
subtle.exportKey()      // Export keys to various formats
subtle.deriveKey()      // Derive keys from passwords
subtle.deriveBits()     // Derive raw bits from passwords

// Cryptographic operations
subtle.encrypt()        // Encrypt data
subtle.decrypt()        // Decrypt data
subtle.sign()           // Create digital signatures
subtle.verify()         // Verify digital signatures
subtle.digest()         // Hash data (SHA-256, etc.)
subtle.wrapKey()        // Wrap (encrypt) a key
subtle.unwrapKey()      // Unwrap (decrypt) a key
```

### Everything is Asynchronous

Unlike Node.js's `crypto` module which has synchronous methods, Web Crypto API is **entirely Promise-based**:

```typescript
// ❌ This doesn't exist
const hash = crypto.subtle.digestSync('SHA-256', data);

// ✅ Always use await or .then()
const hash = await crypto.subtle.digest('SHA-256', data);
```

This design prevents blocking the main thread during expensive operations like key generation.

### Working with Binary Data

Web Crypto API works with `ArrayBuffer` and `TypedArray` (like `Uint8Array`), not strings:

```typescript
// Convert string to bytes
const encoder = new TextEncoder();
const data = encoder.encode('Hello, World!');
// data is now Uint8Array

// Convert bytes to string
const decoder = new TextDecoder();
const text = decoder.decode(data);
// text is now 'Hello, World!'
```

### Cross-Runtime Compatibility

Different runtimes expose the crypto object differently. Here's a universal accessor:

```typescript
// src/crypto/universal.ts

/**
 * Get the Web Crypto API instance that works across all runtimes
 */
function getUniversalCrypto(): Crypto {
  // Modern browsers, Deno, Bun, Cloudflare Workers, Node 19+
  if (typeof globalThis.crypto !== 'undefined') {
    return globalThis.crypto;
  }
  
  // Node.js 16-18
  if (typeof globalThis.require !== 'undefined') {
    const { webcrypto } = require('crypto');
    return webcrypto as Crypto;
  }
  
  throw new Error('Web Crypto API is not available in this environment');
}

/**
 * Get the SubtleCrypto interface
 */
function getSubtle(): SubtleCrypto {
  return getUniversalCrypto().subtle;
}

export { getUniversalCrypto, getSubtle };
```

### Supported Algorithms

| Category | Algorithms |
|----------|------------|
| **Hashing** | SHA-1, SHA-256, SHA-384, SHA-512 |
| **HMAC** | HMAC with any SHA variant |
| **Symmetric Encryption** | AES-CBC, AES-CTR, AES-GCM |
| **Asymmetric Encryption** | RSA-OAEP |
| **Signing** | RSASSA-PKCS1-v1_5, RSA-PSS, ECDSA |
| **Key Derivation** | PBKDF2, HKDF |
| **Key Agreement** | ECDH |

### Your First Web Crypto Operation

Let's hash a string using SHA-256:

```typescript
async function hashString(message: string): Promise<string> {
  // 1. Convert string to bytes
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  
  // 2. Hash the bytes
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  
  // 3. Convert to hex string for display
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  
  return hashHex;
}

// Usage
const hash = await hashString('Hello, World!');
console.log(hash);
// Output: dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f
```

### Exercise 1.1

1. Create a file `src/crypto/universal.ts` with the cross-runtime crypto accessor
2. Test it in Node.js and your browser's console
3. Hash your name using SHA-256 and SHA-512, compare the output lengths

---

## 2. Base64URL Encoding from Scratch

### Why Base64URL?

JWTs (JSON Web Tokens) use **Base64URL** encoding, not regular Base64. The differences are:

| Character | Base64 | Base64URL |
|-----------|--------|-----------|
| 62nd | `+` | `-` |
| 63rd | `/` | `_` |
| Padding | Required `=` | Optional (usually removed) |

Base64URL is URL-safe — you can put it in URLs and HTTP headers without escaping.

### The Encoding Algorithm

Base64 encoding converts binary data to ASCII text using 64 characters:

```
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_
```

The process:
1. Take 3 bytes (24 bits) of binary data
2. Split into 4 groups of 6 bits each
3. Map each 6-bit value (0-63) to a character
4. If input isn't divisible by 3, pad with `=` (we'll skip this for Base64URL)

### Implementation

```typescript
// src/crypto/base64url.ts

const BASE64URL_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/**
 * Encode bytes to Base64URL string
 */
function encode(input: Uint8Array | ArrayBuffer | string): string {
  // Convert input to Uint8Array
  let bytes: Uint8Array;
  
  if (typeof input === 'string') {
    bytes = new TextEncoder().encode(input);
  } else if (input instanceof ArrayBuffer) {
    bytes = new Uint8Array(input);
  } else {
    bytes = input;
  }
  
  let result = '';
  const len = bytes.length;
  
  // Process 3 bytes at a time
  for (let i = 0; i < len; i += 3) {
    // Get up to 3 bytes
    const b1 = bytes[i];
    const b2 = i + 1 < len ? bytes[i + 1] : 0;
    const b3 = i + 2 < len ? bytes[i + 2] : 0;
    
    // Convert to 4 Base64 characters
    const c1 = b1 >> 2;
    const c2 = ((b1 & 0x03) << 4) | (b2 >> 4);
    const c3 = ((b2 & 0x0f) << 2) | (b3 >> 6);
    const c4 = b3 & 0x3f;
    
    result += BASE64URL_CHARS[c1];
    result += BASE64URL_CHARS[c2];
    
    // Only add c3 if we had at least 2 bytes
    if (i + 1 < len) {
      result += BASE64URL_CHARS[c3];
    }
    
    // Only add c4 if we had 3 bytes
    if (i + 2 < len) {
      result += BASE64URL_CHARS[c4];
    }
  }
  
  return result;
}

/**
 * Decode Base64URL string to bytes
 */
function decode(input: string): Uint8Array {
  // Build reverse lookup table
  const lookup: { [key: string]: number } = {};
  for (let i = 0; i < BASE64URL_CHARS.length; i++) {
    lookup[BASE64URL_CHARS[i]] = i;
  }
  
  // Remove any padding (shouldn't exist in Base64URL, but just in case)
  const str = input.replace(/=+$/, '');
  
  // Calculate output length
  const outputLen = Math.floor((str.length * 3) / 4);
  const output = new Uint8Array(outputLen);
  
  let outputIndex = 0;
  
  // Process 4 characters at a time
  for (let i = 0; i < str.length; i += 4) {
    const c1 = lookup[str[i]] || 0;
    const c2 = lookup[str[i + 1]] || 0;
    const c3 = i + 2 < str.length ? lookup[str[i + 2]] : 0;
    const c4 = i + 3 < str.length ? lookup[str[i + 3]] : 0;
    
    // Convert 4 Base64 chars to 3 bytes
    output[outputIndex++] = (c1 << 2) | (c2 >> 4);
    
    if (i + 2 < str.length) {
      output[outputIndex++] = ((c2 & 0x0f) << 4) | (c3 >> 2);
    }
    
    if (i + 3 < str.length) {
      output[outputIndex++] = ((c3 & 0x03) << 6) | c4;
    }
  }
  
  return output;
}

/**
 * Decode Base64URL string directly to a string
 */
function decodeToString(input: string): string {
  const bytes = decode(input);
  return new TextDecoder().decode(bytes);
}

/**
 * Encode a JSON object to Base64URL
 */
function encodeJSON(obj: object): string {
  return encode(JSON.stringify(obj));
}

/**
 * Decode Base64URL to a JSON object
 */
function decodeJSON<T = unknown>(input: string): T {
  return JSON.parse(decodeToString(input));
}

export { encode, decode, decodeToString, encodeJSON, decodeJSON };
```

### Alternative: Using Built-in btoa/atob

For simpler use cases, you can wrap the built-in functions:

```typescript
// Simpler but less educational implementation
function encodeSimple(input: Uint8Array | ArrayBuffer | string): string {
  let bytes: Uint8Array;
  
  if (typeof input === 'string') {
    bytes = new TextEncoder().encode(input);
  } else if (input instanceof ArrayBuffer) {
    bytes = new Uint8Array(input);
  } else {
    bytes = input;
  }
  
  // Convert bytes to binary string
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  
  // Use btoa for Base64, then convert to Base64URL
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function decodeSimple(input: string): Uint8Array {
  // Convert Base64URL to Base64
  let base64 = input
    .replace(/-/g, '+')
    .replace(/_/g, '/');
  
  // Add padding if needed
  const padding = base64.length % 4;
  if (padding) {
    base64 += '='.repeat(4 - padding);
  }
  
  // Decode
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  
  return bytes;
}
```

### Testing Your Implementation

```typescript
// Test round-trip
const original = 'Hello, World!';
const encoded = encode(original);
const decoded = decodeToString(encoded);

console.log('Original:', original);
console.log('Encoded:', encoded);  // SGVsbG8sIFdvcmxkIQ
console.log('Decoded:', decoded);  // Hello, World!
console.log('Match:', original === decoded);  // true

// Test with binary data
const binaryData = new Uint8Array([0, 255, 128, 64, 32]);
const encodedBinary = encode(binaryData);
const decodedBinary = decode(encodedBinary);

console.log('Binary match:', 
  binaryData.every((val, i) => val === decodedBinary[i])
);  // true

// Test with JSON
const obj = { userId: 123, role: 'admin' };
const encodedJSON = encodeJSON(obj);
const decodedJSON = decodeJSON(encodedJSON);
console.log('JSON match:', JSON.stringify(obj) === JSON.stringify(decodedJSON));
```

### Exercise 1.2

1. Create `src/crypto/base64url.ts` with the full implementation
2. Test with special characters: `{"emoji": "🔐", "name": "José"}`
3. Compare output length of hex encoding vs Base64URL for the same data

---

## 3. Secure Random Generation

### Why Secure Randomness Matters

Authentication tokens, session IDs, and cryptographic keys all require **unpredictable** random values. Regular `Math.random()` is **NOT** suitable:

```typescript
// ❌ NEVER use for security
const insecureToken = Math.random().toString(36);

// ✅ Use crypto.getRandomValues()
const secureBytes = crypto.getRandomValues(new Uint8Array(32));
```

`Math.random()` uses a PRNG (Pseudo-Random Number Generator) that:
- Can be predicted if the seed is known
- May have patterns over many iterations
- Varies between JavaScript engines

`crypto.getRandomValues()` uses the operating system's CSPRNG (Cryptographically Secure PRNG) which:
- Gathers entropy from hardware events (mouse movements, disk timing, etc.)
- Is designed to be unpredictable
- Is suitable for cryptographic operations

### Entropy Requirements

Different security contexts require different amounts of randomness:

| Use Case | Minimum Bits | Bytes |
|----------|--------------|-------|
| Session ID | 128 | 16 |
| CSRF Token | 128 | 16 |
| Access Token ID | 256 | 32 |
| Refresh Token | 256-384 | 32-48 |
| Encryption Key | 256 | 32 |
| RSA Key | 2048+ | N/A (generated differently) |

### Implementation

```typescript
// src/crypto/random.ts

import { getUniversalCrypto } from './universal';
import { encode as base64urlEncode } from './base64url';

/**
 * Generate cryptographically secure random bytes
 */
function generateRandomBytes(length: number): Uint8Array {
  const crypto = getUniversalCrypto();
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

/**
 * Generate a secure random token as Base64URL string
 * @param byteLength - Number of random bytes (default 32 = 256 bits)
 */
function generateToken(byteLength: number = 32): string {
  const bytes = generateRandomBytes(byteLength);
  return base64urlEncode(bytes);
}

/**
 * Generate a secure random token as hexadecimal string
 */
function generateHexToken(byteLength: number = 32): string {
  const bytes = generateRandomBytes(byteLength);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Generate a UUID v4 (random UUID)
 * Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
 */
function generateUUID(): string {
  const crypto = getUniversalCrypto();
  
  // Use native implementation if available (Node 16.7+, modern browsers)
  if (typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  
  // Fallback implementation
  const bytes = generateRandomBytes(16);
  
  // Set version (4) and variant (RFC 4122)
  bytes[6] = (bytes[6] & 0x0f) | 0x40;  // Version 4
  bytes[8] = (bytes[8] & 0x3f) | 0x80;  // Variant 1
  
  // Convert to hex with dashes
  const hex = Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32)
  ].join('-');
}

/**
 * Generate a session ID with high entropy
 * Uses 32 bytes (256 bits) of randomness
 */
function generateSessionId(): string {
  return generateToken(32);
}

/**
 * Generate a refresh token with extra entropy
 * Uses 48 bytes (384 bits) for long-lived tokens
 */
function generateRefreshToken(): string {
  return generateToken(48);
}

/**
 * Generate a key ID for JWT key rotation
 * Format: key_<timestamp>_<random>
 */
function generateKeyId(): string {
  const timestamp = Date.now().toString(36);
  const randomPart = generateToken(6);  // 48 bits of randomness
  return `key_${timestamp}_${randomPart}`;
}

/**
 * Generate a numeric OTP (One-Time Password)
 * @param length - Number of digits (default 6)
 */
function generateOTP(length: number = 6): string {
  const bytes = generateRandomBytes(length);
  let otp = '';
  
  for (let i = 0; i < length; i++) {
    // Map byte (0-255) to digit (0-9)
    otp += (bytes[i] % 10).toString();
  }
  
  return otp;
}

export {
  generateRandomBytes,
  generateToken,
  generateHexToken,
  generateUUID,
  generateSessionId,
  generateRefreshToken,
  generateKeyId,
  generateOTP
};
```

### Understanding Token Formats

Different formats have different trade-offs:

```typescript
// Same 32 bytes, different representations
const bytes = generateRandomBytes(32);

// Hex: 64 characters, easy to read, case-insensitive
const hex = generateHexToken(32);
// Example: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2

// Base64URL: 43 characters, more compact, URL-safe
const base64url = generateToken(32);
// Example: obLD1OX2Kj8mN5pQ7rS9tU1vW3xY5zA7bC9dE1fG3hI

// UUID: 36 characters, standardized format, recognizable
const uuid = generateUUID();
// Example: 550e8400-e29b-41d4-a716-446655440000
```

### Secure Token Generation Best Practices

1. **Never truncate tokens** — If you need a shorter token, generate fewer bytes
2. **Don't mix with predictable data** — Adding timestamps reduces entropy
3. **Use appropriate length** — More bytes = more security = longer strings
4. **Regenerate on each use** — For CSRF tokens, OTPs, etc.

```typescript
// ❌ Bad: Truncating reduces security
const badToken = generateToken(32).slice(0, 10);

// ✅ Good: Generate the length you need
const goodToken = generateToken(8);  // 64 bits if that's acceptable

// ❌ Bad: Mixing timestamp reduces entropy
const badId = Date.now() + generateToken(16);

// ✅ Good: Keep random part separate or use UUID
const goodId = generateUUID();
```

### Testing Randomness

While you can't truly test randomness, you can verify basic properties:

```typescript
function testRandomness(): void {
  // Test uniqueness
  const tokens = new Set<string>();
  for (let i = 0; i < 10000; i++) {
    const token = generateToken(16);
    if (tokens.has(token)) {
      throw new Error('Collision detected!');
    }
    tokens.add(token);
  }
  console.log('✅ No collisions in 10,000 tokens');
  
  // Test length consistency
  const token = generateToken(32);
  // Base64 encodes 3 bytes as 4 characters
  // 32 bytes = 43 characters (without padding)
  console.log('Token length:', token.length);
  console.log('✅ Length is correct:', token.length === 43);
  
  // Test character set
  const validChars = /^[A-Za-z0-9_-]+$/;
  console.log('✅ Valid Base64URL:', validChars.test(token));
  
  // Test UUID format
  const uuid = generateUUID();
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  console.log('✅ Valid UUID v4:', uuidRegex.test(uuid));
}

testRandomness();
```

### Exercise 1.3

1. Create `src/crypto/random.ts` with all the functions above
2. Generate 1000 UUIDs and verify they're all unique
3. Measure the time to generate 10,000 tokens
4. Implement a `generateAlphanumericCode(length: number)` function that generates codes like `A7B3C9D2`

---

## Summary

In this part, you learned:

1. **Web Crypto API** — The native, secure, cross-platform cryptography interface
2. **Base64URL Encoding** — URL-safe encoding for JWTs and tokens
3. **Secure Randomness** — Generating unpredictable tokens using `crypto.getRandomValues()`

### Files Created

```
src/
└── crypto/
    ├── universal.ts   # Cross-runtime crypto access
    ├── base64url.ts   # Base64URL encoding/decoding
    └── random.ts      # Secure random generation
```

### Key Takeaways

- Always use `crypto.subtle` for cryptographic operations
- Never use `Math.random()` for security-sensitive code
- Base64URL is the encoding standard for JWTs
- Different token types need different entropy levels

### Next Steps

In **Part 2: Cryptographic Primitives**, we'll build on these foundations to implement:
- SHA-256 hashing utilities
- HMAC operations for message authentication
- Constant-time comparison to prevent timing attacks

These are the building blocks for JWT signing and password verification.
