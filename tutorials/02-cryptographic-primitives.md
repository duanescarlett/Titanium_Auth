# Part 2: Cryptographic Primitives

Now that we have our foundations in place, it's time to build the cryptographic primitives that power authentication. In this part, we'll implement SHA-256 hashing, HMAC operations for message authentication, and constant-time comparison to prevent timing attacks.

---

## Table of Contents

1. [SHA-256 Hashing](#1-sha-256-hashing)
2. [HMAC Operations](#2-hmac-operations)
3. [Constant-Time Comparison](#3-constant-time-comparison)

---

## 1. SHA-256 Hashing

### What is SHA-256?

SHA-256 (Secure Hash Algorithm 256-bit) is a cryptographic hash function that:
- Takes input of any size
- Produces a fixed 256-bit (32-byte) output
- Is deterministic — same input always produces same output
- Is one-way — you cannot reverse the hash to get the original input
- Is collision-resistant — it's computationally infeasible to find two inputs with the same hash

### Use Cases in Authentication

| Use Case | Description |
|----------|-------------|
| **Token Fingerprinting** | Hash a random value to bind tokens to sessions |
| **Refresh Token Storage** | Store hash of refresh token, not the token itself |
| **Password Hashing** | (Combined with PBKDF2) Derive keys from passwords |
| **Data Integrity** | Verify that data hasn't been tampered with |

### Implementation

```typescript
// src/crypto/hash.ts

import { getSubtle } from './universal';
import { encode as base64urlEncode } from './base64url';

/**
 * Compute SHA-256 hash of data
 * @param data - String or bytes to hash
 * @returns Raw hash as ArrayBuffer
 */
async function sha256(data: string | Uint8Array): Promise<ArrayBuffer> {
  const subtle = getSubtle();
  const bytes = typeof data === 'string' 
    ? new TextEncoder().encode(data) 
    : data;
  
  return subtle.digest('SHA-256', bytes);
}

/**
 * Compute SHA-256 hash and return as hex string
 */
async function sha256Hex(data: string | Uint8Array): Promise<string> {
  const hash = await sha256(data);
  const bytes = new Uint8Array(hash);
  
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Compute SHA-256 hash and return as Base64URL string
 */
async function sha256Base64(data: string | Uint8Array): Promise<string> {
  const hash = await sha256(data);
  return base64urlEncode(new Uint8Array(hash));
}

/**
 * Compute SHA-512 hash (for higher security requirements)
 */
async function sha512(data: string | Uint8Array): Promise<ArrayBuffer> {
  const subtle = getSubtle();
  const bytes = typeof data === 'string' 
    ? new TextEncoder().encode(data) 
    : data;
  
  return subtle.digest('SHA-512', bytes);
}

/**
 * Compute SHA-512 hash and return as hex string
 */
async function sha512Hex(data: string | Uint8Array): Promise<string> {
  const hash = await sha512(data);
  const bytes = new Uint8Array(hash);
  
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export { sha256, sha256Hex, sha256Base64, sha512, sha512Hex };
```

### Testing Hashing

```typescript
// Verify against known test vectors
async function testHashing(): Promise<void> {
  // Test vector: SHA-256 of empty string
  const emptyHash = await sha256Hex('');
  const expectedEmpty = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  console.log('Empty string hash:', emptyHash === expectedEmpty ? '✅ Pass' : '❌ Fail');
  
  // Test vector: SHA-256 of "hello"
  const helloHash = await sha256Hex('hello');
  const expectedHello = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';
  console.log('Hello hash:', helloHash === expectedHello ? '✅ Pass' : '❌ Fail');
  
  // Test determinism
  const hash1 = await sha256Hex('test');
  const hash2 = await sha256Hex('test');
  console.log('Deterministic:', hash1 === hash2 ? '✅ Pass' : '❌ Fail');
  
  // Test avalanche effect (small change = big difference)
  const hashA = await sha256Hex('hello');
  const hashB = await sha256Hex('hellp');  // One character different
  console.log('Avalanche effect: Hashes are completely different');
  console.log('  hello:', hashA);
  console.log('  hellp:', hashB);
}

testHashing();
```

### Exercise 2.1

1. Create `src/crypto/hash.ts` with SHA-256 and SHA-512 implementations
2. Hash the string "password123" and observe the output length
3. Verify the avalanche effect by hashing "password123" and "password124"

---

## 2. HMAC Operations

### What is HMAC?

HMAC (Hash-based Message Authentication Code) combines a cryptographic hash with a secret key to provide:
- **Authentication** — Only someone with the key can create a valid HMAC
- **Integrity** — Any modification to the message invalidates the HMAC

HMAC is defined as:
```
HMAC(key, message) = Hash((key ⊕ opad) || Hash((key ⊕ ipad) || message))
```

But we don't need to implement this ourselves — Web Crypto API does it for us!

### Use Cases in Authentication

| Use Case | Description |
|----------|-------------|
| **JWT Signing (HS256)** | Sign tokens with HMAC-SHA256 |
| **Cookie Signing** | Ensure cookies weren't tampered with |
| **Webhook Verification** | Verify requests from external services |
| **API Request Signing** | Authenticate API requests |

### Implementation

```typescript
// src/crypto/hmac.ts

import { getSubtle } from './universal';
import { encode as base64urlEncode, decode as base64urlDecode } from './base64url';

type HMACAlgorithm = 'SHA-256' | 'SHA-384' | 'SHA-512';

/**
 * Create an HMAC key from a secret
 */
async function createHMACKey(
  secret: string | Uint8Array,
  algorithm: HMACAlgorithm = 'SHA-256'
): Promise<CryptoKey> {
  const subtle = getSubtle();
  const keyData = typeof secret === 'string'
    ? new TextEncoder().encode(secret)
    : secret;
  
  return subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: algorithm },
    false,  // not extractable
    ['sign', 'verify']
  );
}

/**
 * Sign data using HMAC
 * @returns Signature as ArrayBuffer
 */
async function hmacSign(
  key: CryptoKey,
  data: string | Uint8Array
): Promise<ArrayBuffer> {
  const subtle = getSubtle();
  const bytes = typeof data === 'string'
    ? new TextEncoder().encode(data)
    : data;
  
  return subtle.sign('HMAC', key, bytes);
}

/**
 * Sign data and return signature as Base64URL
 */
async function hmacSignBase64(
  key: CryptoKey,
  data: string | Uint8Array
): Promise<string> {
  const signature = await hmacSign(key, data);
  return base64urlEncode(new Uint8Array(signature));
}

/**
 * Verify an HMAC signature
 */
async function hmacVerify(
  key: CryptoKey,
  signature: ArrayBuffer | Uint8Array,
  data: string | Uint8Array
): Promise<boolean> {
  const subtle = getSubtle();
  const dataBytes = typeof data === 'string'
    ? new TextEncoder().encode(data)
    : data;
  const sigBytes = signature instanceof ArrayBuffer
    ? signature
    : signature.buffer;
  
  return subtle.verify('HMAC', key, sigBytes, dataBytes);
}

/**
 * Verify a Base64URL-encoded HMAC signature
 */
async function hmacVerifyBase64(
  key: CryptoKey,
  signatureBase64: string,
  data: string | Uint8Array
): Promise<boolean> {
  const signature = base64urlDecode(signatureBase64);
  return hmacVerify(key, signature, data);
}

/**
 * One-shot function to sign data with a secret
 * Convenient for simple use cases
 */
async function signWithSecret(
  secret: string,
  data: string,
  algorithm: HMACAlgorithm = 'SHA-256'
): Promise<string> {
  const key = await createHMACKey(secret, algorithm);
  return hmacSignBase64(key, data);
}

/**
 * One-shot function to verify a signature
 */
async function verifyWithSecret(
  secret: string,
  signature: string,
  data: string,
  algorithm: HMACAlgorithm = 'SHA-256'
): Promise<boolean> {
  const key = await createHMACKey(secret, algorithm);
  return hmacVerifyBase64(key, signature, data);
}

export {
  createHMACKey,
  hmacSign,
  hmacSignBase64,
  hmacVerify,
  hmacVerifyBase64,
  signWithSecret,
  verifyWithSecret,
  HMACAlgorithm
};
```

### How JWT HS256 Signing Works

This is a preview of how we'll use HMAC in Part 4:

```typescript
async function signJWT(header: object, payload: object, secret: string): Promise<string> {
  // 1. Encode header and payload
  const encodedHeader = base64urlEncode(JSON.stringify(header));
  const encodedPayload = base64urlEncode(JSON.stringify(payload));
  
  // 2. Create signing input
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  
  // 3. Sign with HMAC-SHA256
  const signature = await signWithSecret(secret, signingInput);
  
  // 4. Combine all parts
  return `${signingInput}.${signature}`;
}
```

### Testing HMAC

```typescript
async function testHMAC(): Promise<void> {
  const secret = 'my-secret-key';
  const message = 'Hello, World!';
  
  // Test signing
  const signature = await signWithSecret(secret, message);
  console.log('Signature:', signature);
  
  // Test verification
  const isValid = await verifyWithSecret(secret, signature, message);
  console.log('Valid signature:', isValid ? '✅ Pass' : '❌ Fail');
  
  // Test with wrong message
  const isValidWrong = await verifyWithSecret(secret, signature, 'Wrong message');
  console.log('Wrong message rejected:', !isValidWrong ? '✅ Pass' : '❌ Fail');
  
  // Test with wrong secret
  const isValidWrongKey = await verifyWithSecret('wrong-key', signature, message);
  console.log('Wrong secret rejected:', !isValidWrongKey ? '✅ Pass' : '❌ Fail');
  
  // Test consistency
  const sig1 = await signWithSecret(secret, message);
  const sig2 = await signWithSecret(secret, message);
  console.log('Consistent signatures:', sig1 === sig2 ? '✅ Pass' : '❌ Fail');
}

testHMAC();
```

### Exercise 2.2

1. Create `src/crypto/hmac.ts` with all HMAC functions
2. Sign a message with SHA-256 and SHA-512, compare signature lengths
3. Create a function that signs a cookie value and appends the signature

---

## 3. Constant-Time Comparison

### The Timing Attack Problem

When comparing strings character by character, the time taken reveals information:

```typescript
// ❌ VULNERABLE to timing attacks
function insecureCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;  // Returns early on first mismatch!
    }
  }
  
  return true;
}
```

An attacker can measure response times:
- If the first character is wrong: ~1 comparison
- If the first character is right: ~2+ comparisons
- By trying all possibilities for each position, they can guess the secret

### How Constant-Time Comparison Works

We must always compare ALL characters, regardless of mismatches:

```typescript
// ✅ SECURE against timing attacks
function constantTimeCompare(a: string, b: string): boolean {
  // Always compare full length even if lengths differ
  if (a.length !== b.length) {
    // Compare a against itself to maintain timing
    b = a;
  }
  
  let result = a.length === b.length ? 0 : 1;
  
  for (let i = 0; i < a.length; i++) {
    // XOR the character codes - result is 0 only if equal
    // Use bitwise OR to accumulate any differences
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  
  return result === 0;
}
```

### Implementation

```typescript
// src/crypto/timing.ts

/**
 * Constant-time string comparison
 * Prevents timing attacks by always comparing all characters
 */
function timingSafeEqual(a: string, b: string): boolean {
  // If lengths differ, compare a against itself but still return false
  // This ensures the loop runs for the same duration
  if (a.length !== b.length) {
    b = a;  // Use 'a' to maintain loop iterations
  }
  
  let result = a.length === b.length ? 0 : 1;
  
  for (let i = 0; i < a.length; i++) {
    // XOR character codes - 0 if equal, non-zero if different
    // OR accumulates any differences
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  
  return result === 0;
}

/**
 * Constant-time comparison for Uint8Arrays
 */
function timingSafeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  
  let result = 0;
  
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  
  return result === 0;
}

/**
 * Constant-time comparison for Base64URL strings
 * Useful for comparing tokens
 */
function timingSafeEqualBase64(a: string, b: string): boolean {
  return timingSafeEqual(a, b);
}

/**
 * Constant-time comparison for hex strings
 * Normalizes case before comparing
 */
function timingSafeEqualHex(a: string, b: string): boolean {
  return timingSafeEqual(a.toLowerCase(), b.toLowerCase());
}

export {
  timingSafeEqual,
  timingSafeEqualBytes,
  timingSafeEqualBase64,
  timingSafeEqualHex
};
```

### Why XOR and OR?

Let's break down the bit manipulation:

```typescript
// XOR (^) returns 0 if bits are the same
0b1010 ^ 0b1010  // 0b0000 (0) - equal
0b1010 ^ 0b1011  // 0b0001 (1) - different

// OR (|) accumulates any non-zero values
let result = 0;
result |= 0;  // result = 0
result |= 0;  // result = 0
result |= 1;  // result = 1 - this difference is now captured
result |= 0;  // result = 1 - stays non-zero

// Final check: result === 0 means all comparisons were equal
```

### When to Use Constant-Time Comparison

Always use it when comparing:
- Passwords or password hashes
- API keys or tokens
- HMAC signatures
- Session IDs
- Any secret value

```typescript
// ❌ Don't do this
if (userToken === validToken) { ... }

// ✅ Do this
if (timingSafeEqual(userToken, validToken)) { ... }
```

### Testing Constant-Time Comparison

```typescript
function testTimingSafe(): void {
  // Test equal strings
  console.log('Equal strings:', 
    timingSafeEqual('secret', 'secret') === true ? '✅ Pass' : '❌ Fail'
  );
  
  // Test different strings (same length)
  console.log('Different strings (same length):', 
    timingSafeEqual('secret', 'secrex') === false ? '✅ Pass' : '❌ Fail'
  );
  
  // Test different lengths
  console.log('Different lengths:', 
    timingSafeEqual('secret', 'secrets') === false ? '✅ Pass' : '❌ Fail'
  );
  
  // Test empty strings
  console.log('Empty strings:', 
    timingSafeEqual('', '') === true ? '✅ Pass' : '❌ Fail'
  );
  
  // Test bytes
  const a = new Uint8Array([1, 2, 3, 4]);
  const b = new Uint8Array([1, 2, 3, 4]);
  const c = new Uint8Array([1, 2, 3, 5]);
  
  console.log('Equal bytes:', 
    timingSafeEqualBytes(a, b) === true ? '✅ Pass' : '❌ Fail'
  );
  console.log('Different bytes:', 
    timingSafeEqualBytes(a, c) === false ? '✅ Pass' : '❌ Fail'
  );
}

testTimingSafe();
```

### Demonstrating the Vulnerability

This test shows why regular comparison is dangerous:

```typescript
// WARNING: Educational purposes only!
function demonstrateTimingAttack(): void {
  const secret = 'supersecretpassword123';
  
  // Measure time for different prefix matches
  const prefixes = [
    'xupersecretpassword123',  // Wrong first char
    'sxpersecretpassword123',  // Wrong second char
    'suxersecretpassword123',  // Wrong third char
    'supxrsecretpassword123',  // Wrong fourth char
  ];
  
  console.log('Timing differences (vulnerable comparison):');
  
  for (const prefix of prefixes) {
    const start = performance.now();
    
    // Run many iterations to amplify timing difference
    for (let i = 0; i < 100000; i++) {
      let result = true;
      for (let j = 0; j < secret.length && result; j++) {
        if (secret[j] !== prefix[j]) {
          result = false;
        }
      }
    }
    
    const elapsed = performance.now() - start;
    console.log(`  ${prefix.slice(0, 4)}...: ${elapsed.toFixed(2)}ms`);
  }
  
  // Compare with constant-time
  console.log('\nTiming with constant-time comparison:');
  
  for (const prefix of prefixes) {
    const start = performance.now();
    
    for (let i = 0; i < 100000; i++) {
      timingSafeEqual(secret, prefix);
    }
    
    const elapsed = performance.now() - start;
    console.log(`  ${prefix.slice(0, 4)}...: ${elapsed.toFixed(2)}ms`);
  }
}

demonstrateTimingAttack();
```

### Exercise 2.3

1. Create `src/crypto/timing.ts` with all timing-safe functions
2. Write a test that demonstrates timing differences in regular comparison
3. Verify that your implementation shows consistent timing regardless of match position

---

## Summary

In this part, you learned:

1. **SHA-256 Hashing** — One-way, deterministic hashing for fingerprints and token storage
2. **HMAC Operations** — Keyed hashing for JWT signing and message authentication
3. **Constant-Time Comparison** — Preventing timing attacks when comparing secrets

### Files Created

```
src/
└── crypto/
    ├── universal.ts   # (from Part 1)
    ├── base64url.ts   # (from Part 1)
    ├── random.ts      # (from Part 1)
    ├── hash.ts        # SHA-256/512 hashing
    ├── hmac.ts        # HMAC sign/verify
    └── timing.ts      # Constant-time comparison
```

### Key Takeaways

- SHA-256 produces a fixed 32-byte output regardless of input size
- HMAC combines a secret key with hashing for authentication
- Always use constant-time comparison for secrets to prevent timing attacks
- The XOR + OR pattern accumulates differences without revealing position

### Security Checklist

Before moving on, ensure:
- [ ] SHA-256 test vectors pass
- [ ] HMAC signatures are consistent and verifiable
- [ ] Timing-safe comparison works for equal and unequal strings
- [ ] You understand why each of these matters for authentication

### Next Steps

In **Part 3: Password Security**, we'll use these primitives to implement:
- PBKDF2 password hashing with 600,000 iterations
- Secure salt generation
- PHC string format for storage
- Password verification with timing-safe comparison
