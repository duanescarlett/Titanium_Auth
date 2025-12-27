# Part 3: Password Security

Storing passwords securely is one of the most critical aspects of authentication. In this part, we'll implement industry-standard password hashing using PBKDF2 with the Web Crypto API, following OWASP 2023 guidelines.

---

## Table of Contents

1. [Understanding Password Hashing](#1-understanding-password-hashing)
2. [PBKDF2 with Web Crypto API](#2-pbkdf2-with-web-crypto-api)
3. [PHC String Format](#3-phc-string-format)

---

## 1. Understanding Password Hashing

### Why Not Just Hash Passwords?

A simple SHA-256 hash of a password is **NOT secure**:

```typescript
// ❌ NEVER do this
const passwordHash = await sha256Hex('password123');
// Output: ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f
```

Problems with simple hashing:
1. **Rainbow tables** — Precomputed hashes for common passwords
2. **Speed** — SHA-256 is designed to be fast; attackers can try billions per second
3. **No salt** — Same password = same hash across all users

### What Makes Password Hashing Secure?

| Property | Description |
|----------|-------------|
| **Salting** | Random bytes added to each password (prevents rainbow tables) |
| **Slowness** | Intentionally slow to make brute-force impractical |
| **Memory-hard** | Uses lots of memory (optional, not in PBKDF2) |
| **Adjustable cost** | Can increase iterations as hardware improves |

### OWASP 2023 Recommendations

| Algorithm | Minimum Iterations | Memory |
|-----------|-------------------|--------|
| **PBKDF2-HMAC-SHA256** | 600,000 | N/A |
| **PBKDF2-HMAC-SHA512** | 210,000 | N/A |
| Argon2id | 3 | 64 MB |
| bcrypt | 10 (cost factor) | 4 KB |
| scrypt | N=2^17 | 128 MB |

We're using **PBKDF2** because it's available natively in Web Crypto API. For new systems, Argon2id is preferred but requires external libraries.

### How PBKDF2 Works

PBKDF2 (Password-Based Key Derivation Function 2) repeatedly applies HMAC:

```
DK = PBKDF2(PRF, Password, Salt, c, dkLen)

Where:
- PRF = Pseudo-random function (HMAC-SHA256)
- Password = User's password
- Salt = Random bytes (unique per password)
- c = Iteration count (600,000)
- dkLen = Desired key length (32 bytes)
```

Each iteration:
```
U1 = PRF(Password, Salt || INT(i))
U2 = PRF(Password, U1)
U3 = PRF(Password, U2)
...
DK = U1 ⊕ U2 ⊕ U3 ⊕ ... ⊕ Uc
```

This makes each password guess take significant CPU time.

---

## 2. PBKDF2 with Web Crypto API

### Configuration

```typescript
// src/password/config.ts

/**
 * Password hashing configuration
 * Based on OWASP 2023 recommendations
 */
export const PASSWORD_CONFIG = {
  // PBKDF2 iterations - minimum 600,000 for SHA-256
  iterations: 600000,
  
  // Salt length - 16 bytes (128 bits) minimum
  saltLength: 16,
  
  // Output key length - 32 bytes (256 bits)
  keyLength: 32,
  
  // Hash algorithm
  hash: 'SHA-256' as const,
  
  // Algorithm identifier for storage
  algorithm: 'pbkdf2-sha256'
} as const;

/**
 * How long hashing should take (for benchmarking)
 * Target: 100-500ms on average hardware
 */
export const TARGET_HASH_TIME_MS = 250;
```

### Implementation

```typescript
// src/password/hash.ts

import { getSubtle, getUniversalCrypto } from '../crypto/universal';
import { encode as base64urlEncode, decode as base64urlDecode } from '../crypto/base64url';
import { PASSWORD_CONFIG } from './config';

/**
 * Result of password hashing
 */
interface HashResult {
  hash: string;        // Base64URL encoded derived key
  salt: string;        // Base64URL encoded salt
  iterations: number;  // Number of iterations used
  algorithm: string;   // Algorithm identifier
}

/**
 * Hash a password using PBKDF2-HMAC-SHA256
 * 
 * @param password - The user's password
 * @returns Hash result with all parameters needed for verification
 */
async function hashPassword(password: string): Promise<HashResult> {
  const crypto = getUniversalCrypto();
  const subtle = getSubtle();
  
  // 1. Generate random salt
  const salt = new Uint8Array(PASSWORD_CONFIG.saltLength);
  crypto.getRandomValues(salt);
  
  // 2. Import password as key material
  const passwordBytes = new TextEncoder().encode(password);
  const keyMaterial = await subtle.importKey(
    'raw',
    passwordBytes,
    'PBKDF2',
    false,  // not extractable
    ['deriveBits']
  );
  
  // 3. Derive key using PBKDF2
  const derivedBits = await subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: PASSWORD_CONFIG.iterations,
      hash: PASSWORD_CONFIG.hash
    },
    keyMaterial,
    PASSWORD_CONFIG.keyLength * 8  // deriveBits expects bits, not bytes
  );
  
  // 4. Encode results
  return {
    hash: base64urlEncode(new Uint8Array(derivedBits)),
    salt: base64urlEncode(salt),
    iterations: PASSWORD_CONFIG.iterations,
    algorithm: PASSWORD_CONFIG.algorithm
  };
}

/**
 * Hash password with a specific salt (for verification)
 */
async function hashPasswordWithSalt(
  password: string,
  salt: Uint8Array,
  iterations: number
): Promise<Uint8Array> {
  const subtle = getSubtle();
  
  const passwordBytes = new TextEncoder().encode(password);
  const keyMaterial = await subtle.importKey(
    'raw',
    passwordBytes,
    'PBKDF2',
    false,
    ['deriveBits']
  );
  
  const derivedBits = await subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: iterations,
      hash: PASSWORD_CONFIG.hash
    },
    keyMaterial,
    PASSWORD_CONFIG.keyLength * 8
  );
  
  return new Uint8Array(derivedBits);
}

export { hashPassword, hashPasswordWithSalt, HashResult };
```

### Verification

```typescript
// src/password/verify.ts

import { decode as base64urlDecode, encode as base64urlEncode } from '../crypto/base64url';
import { timingSafeEqual } from '../crypto/timing';
import { hashPasswordWithSalt, HashResult } from './hash';

/**
 * Verify a password against a stored hash
 * 
 * @param password - The password to verify
 * @param stored - The stored hash result
 * @returns true if password matches, false otherwise
 */
async function verifyPassword(
  password: string,
  stored: HashResult
): Promise<boolean> {
  // 1. Decode the stored salt
  const salt = base64urlDecode(stored.salt);
  
  // 2. Hash the provided password with the same parameters
  const computedHash = await hashPasswordWithSalt(
    password,
    salt,
    stored.iterations
  );
  
  // 3. Compare using constant-time comparison
  const computedHashBase64 = base64urlEncode(computedHash);
  return timingSafeEqual(computedHashBase64, stored.hash);
}

/**
 * Check if a hash needs to be upgraded
 * (e.g., if iterations have been increased)
 */
function needsRehash(stored: HashResult, currentIterations: number): boolean {
  return stored.iterations < currentIterations;
}

export { verifyPassword, needsRehash };
```

### Testing Password Hashing

```typescript
async function testPasswordHashing(): Promise<void> {
  console.log('Testing password hashing...\n');
  
  // Test basic hashing
  const password = 'MySecurePassword123!';
  
  console.log('Hashing password...');
  const startHash = performance.now();
  const result = await hashPassword(password);
  const hashTime = performance.now() - startHash;
  
  console.log(`  Time: ${hashTime.toFixed(0)}ms`);
  console.log(`  Salt: ${result.salt}`);
  console.log(`  Hash: ${result.hash}`);
  console.log(`  Iterations: ${result.iterations}`);
  
  // Test verification
  console.log('\nVerifying correct password...');
  const startVerify = performance.now();
  const isValid = await verifyPassword(password, result);
  const verifyTime = performance.now() - startVerify;
  
  console.log(`  Time: ${verifyTime.toFixed(0)}ms`);
  console.log(`  Valid: ${isValid ? '✅ Pass' : '❌ Fail'}`);
  
  // Test wrong password
  console.log('\nVerifying wrong password...');
  const isInvalid = await verifyPassword('WrongPassword', result);
  console.log(`  Rejected: ${!isInvalid ? '✅ Pass' : '❌ Fail'}`);
  
  // Test unique salts
  console.log('\nTesting unique salts...');
  const result2 = await hashPassword(password);
  const saltsUnique = result.salt !== result2.salt;
  const hashesUnique = result.hash !== result2.hash;
  console.log(`  Salts unique: ${saltsUnique ? '✅ Pass' : '❌ Fail'}`);
  console.log(`  Hashes unique: ${hashesUnique ? '✅ Pass' : '❌ Fail'}`);
}

testPasswordHashing();
```

### Benchmarking Iterations

```typescript
/**
 * Benchmark to find optimal iteration count for target time
 */
async function benchmarkIterations(targetMs: number = 250): Promise<number> {
  const testPassword = 'benchmark-password';
  const testIterations = [100000, 200000, 400000, 600000, 800000, 1000000];
  
  console.log(`Benchmarking for ${targetMs}ms target...\n`);
  
  for (const iterations of testIterations) {
    const subtle = getSubtle();
    const crypto = getUniversalCrypto();
    
    const salt = new Uint8Array(16);
    crypto.getRandomValues(salt);
    
    const passwordBytes = new TextEncoder().encode(testPassword);
    const keyMaterial = await subtle.importKey(
      'raw',
      passwordBytes,
      'PBKDF2',
      false,
      ['deriveBits']
    );
    
    const start = performance.now();
    await subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: iterations,
        hash: 'SHA-256'
      },
      keyMaterial,
      256
    );
    const elapsed = performance.now() - start;
    
    console.log(`  ${iterations.toLocaleString()} iterations: ${elapsed.toFixed(0)}ms`);
    
    if (elapsed >= targetMs) {
      console.log(`\nRecommended: ${iterations.toLocaleString()} iterations`);
      return iterations;
    }
  }
  
  console.log('\nHardware is fast! Consider using more iterations.');
  return testIterations[testIterations.length - 1];
}

benchmarkIterations();
```

### Exercise 3.1

1. Create `src/password/config.ts`, `src/password/hash.ts`, and `src/password/verify.ts`
2. Benchmark the hashing time on your machine
3. Try different iteration counts and observe the time difference

---

## 3. PHC String Format

### What is PHC Format?

PHC (Password Hashing Competition) string format is a standardized way to store password hashes. It includes all parameters needed for verification:

```
$<algorithm>$<parameters>$<salt>$<hash>
```

Examples:
```
$pbkdf2-sha256$i=600000$<salt>$<hash>
$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
$bcrypt$12$<salt+hash>
```

### Benefits of PHC Format

1. **Self-describing** — Contains algorithm and parameters
2. **Future-proof** — Can upgrade algorithm without breaking existing hashes
3. **Portable** — Standard format across languages/frameworks
4. **Secure** — Encourages storing all parameters together

### Implementation

```typescript
// src/password/serialize.ts

import { HashResult } from './hash';

/**
 * Serialize a hash result to PHC string format
 * 
 * Format: $pbkdf2-sha256$i=<iterations>$<salt>$<hash>
 */
function serializeHash(result: HashResult): string {
  const parts = [
    '',  // Empty first element for leading $
    result.algorithm,
    `i=${result.iterations}`,
    result.salt,
    result.hash
  ];
  
  return parts.join('$');
}

/**
 * Parse a PHC string back to HashResult
 * 
 * Throws if format is invalid
 */
function deserializeHash(phcString: string): HashResult {
  // Split and remove empty first element
  const parts = phcString.split('$').filter(Boolean);
  
  if (parts.length !== 4) {
    throw new Error(`Invalid PHC string format: expected 4 parts, got ${parts.length}`);
  }
  
  const [algorithm, params, salt, hash] = parts;
  
  // Validate algorithm
  if (!algorithm.startsWith('pbkdf2-')) {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }
  
  // Parse iterations
  const iterationsMatch = params.match(/i=(\d+)/);
  if (!iterationsMatch) {
    throw new Error('Missing iterations parameter');
  }
  
  const iterations = parseInt(iterationsMatch[1], 10);
  if (isNaN(iterations) || iterations < 1) {
    throw new Error(`Invalid iterations: ${iterationsMatch[1]}`);
  }
  
  return {
    algorithm,
    iterations,
    salt,
    hash
  };
}

/**
 * Validate a PHC string format without parsing
 */
function isValidPHCString(phcString: string): boolean {
  try {
    deserializeHash(phcString);
    return true;
  } catch {
    return false;
  }
}

/**
 * Extract algorithm from PHC string (for upgrade decisions)
 */
function getAlgorithm(phcString: string): string | null {
  const match = phcString.match(/^\$([^$]+)\$/);
  return match ? match[1] : null;
}

/**
 * Extract iterations from PHC string (for upgrade decisions)
 */
function getIterations(phcString: string): number | null {
  const match = phcString.match(/\$i=(\d+)\$/);
  return match ? parseInt(match[1], 10) : null;
}

export {
  serializeHash,
  deserializeHash,
  isValidPHCString,
  getAlgorithm,
  getIterations
};
```

### Complete Password Module

```typescript
// src/password/index.ts

import { hashPassword, HashResult } from './hash';
import { verifyPassword, needsRehash } from './verify';
import { serializeHash, deserializeHash, isValidPHCString, getIterations } from './serialize';
import { PASSWORD_CONFIG } from './config';

/**
 * Hash a password and return PHC string for storage
 */
async function hash(password: string): Promise<string> {
  const result = await hashPassword(password);
  return serializeHash(result);
}

/**
 * Verify a password against a PHC string
 */
async function verify(password: string, phcString: string): Promise<boolean> {
  const stored = deserializeHash(phcString);
  return verifyPassword(password, stored);
}

/**
 * Check if a stored hash should be upgraded
 */
function shouldUpgrade(phcString: string): boolean {
  const iterations = getIterations(phcString);
  if (iterations === null) return true;
  return iterations < PASSWORD_CONFIG.iterations;
}

/**
 * Complete password operations for authentication
 */
const password = {
  hash,
  verify,
  shouldUpgrade,
  isValid: isValidPHCString,
  
  // Expose config for reference
  config: PASSWORD_CONFIG
};

export default password;
export { hash, verify, shouldUpgrade };
```

### Usage Example

```typescript
import password from './password';

// Registration
async function registerUser(email: string, plainPassword: string) {
  // Hash the password
  const passwordHash = await password.hash(plainPassword);
  
  // Store in database
  // Example: $pbkdf2-sha256$i=600000$abc123...$xyz789...
  await db.users.create({
    email,
    passwordHash
  });
}

// Login
async function loginUser(email: string, plainPassword: string) {
  // Fetch user from database
  const user = await db.users.findByEmail(email);
  
  if (!user) {
    // Use constant-time comparison by still hashing
    await password.hash(plainPassword);  // Prevent timing attack
    throw new Error('Invalid credentials');
  }
  
  // Verify password
  const isValid = await password.verify(plainPassword, user.passwordHash);
  
  if (!isValid) {
    throw new Error('Invalid credentials');
  }
  
  // Check if hash needs upgrade
  if (password.shouldUpgrade(user.passwordHash)) {
    // Re-hash with current parameters
    const newHash = await password.hash(plainPassword);
    await db.users.update(user.id, { passwordHash: newHash });
  }
  
  return user;
}
```

### Testing PHC Format

```typescript
async function testPHCFormat(): Promise<void> {
  console.log('Testing PHC string format...\n');
  
  // Test serialization
  const result = await hashPassword('test-password');
  const phcString = serializeHash(result);
  
  console.log('PHC String:', phcString);
  console.log('  Starts with $:', phcString.startsWith('$') ? '✅' : '❌');
  console.log('  Parts:', phcString.split('$').filter(Boolean).length === 4 ? '✅' : '❌');
  
  // Test deserialization
  const parsed = deserializeHash(phcString);
  console.log('\nParsed:');
  console.log('  Algorithm:', parsed.algorithm);
  console.log('  Iterations:', parsed.iterations);
  console.log('  Salt length:', parsed.salt.length);
  console.log('  Hash length:', parsed.hash.length);
  
  // Test round-trip
  const reSerialized = serializeHash(parsed);
  console.log('\nRound-trip:', phcString === reSerialized ? '✅ Match' : '❌ Mismatch');
  
  // Test verification through PHC string
  const password = 'test-password';
  const phc = await hash(password);
  const valid = await verify(password, phc);
  console.log('\nFull flow verification:', valid ? '✅ Pass' : '❌ Fail');
  
  // Test upgrade detection
  const oldPhc = '$pbkdf2-sha256$i=100000$abc$xyz';
  console.log('\nUpgrade detection:');
  console.log('  Old hash needs upgrade:', shouldUpgrade(oldPhc) ? '✅ Yes' : '❌ No');
  console.log('  Current hash needs upgrade:', shouldUpgrade(phc) ? '❌ Yes' : '✅ No');
}

testPHCFormat();
```

### Migration from Other Formats

```typescript
/**
 * Handle legacy password formats during migration
 */
async function verifyAndMigrate(
  password: string,
  storedHash: string,
  updateHash: (newHash: string) => Promise<void>
): Promise<boolean> {
  // Check if it's already in PHC format
  if (isValidPHCString(storedHash)) {
    const isValid = await verify(password, storedHash);
    
    if (isValid && shouldUpgrade(storedHash)) {
      const newHash = await hash(password);
      await updateHash(newHash);
    }
    
    return isValid;
  }
  
  // Handle legacy formats (example: old bcrypt or plain sha256)
  // This is where you'd add support for migrating old hashes
  
  // For now, reject unknown formats
  console.warn('Unknown hash format, rejecting');
  return false;
}
```

### Exercise 3.2

1. Create `src/password/serialize.ts` with PHC format functions
2. Create `src/password/index.ts` as the main export
3. Test the full flow: hash → serialize → deserialize → verify
4. Try parsing this PHC string: `$pbkdf2-sha256$i=600000$dGVzdHNhbHQ$dGVzdGhhc2g`

---

## Summary

In this part, you learned:

1. **Password Hashing Fundamentals** — Why simple hashing is insufficient
2. **PBKDF2 Implementation** — Using Web Crypto API with 600,000 iterations
3. **PHC String Format** — Standardized, portable password hash storage

### Files Created

```
src/
├── crypto/
│   └── ...              # (from Parts 1-2)
└── password/
    ├── config.ts        # Configuration constants
    ├── hash.ts          # PBKDF2 hashing
    ├── verify.ts        # Password verification
    ├── serialize.ts     # PHC string format
    └── index.ts         # Public API
```

### Key Takeaways

- PBKDF2 with 600,000 iterations is the OWASP 2023 minimum for SHA-256
- Each password must have a unique random salt
- Always use constant-time comparison for password verification
- PHC format makes hashes self-describing and future-proof
- Re-hash passwords on login if iterations have increased

### Security Checklist

Before moving on, ensure:
- [ ] Hashing takes at least 250ms on your hardware
- [ ] Each hash has a unique salt (test by hashing same password twice)
- [ ] Verification uses constant-time comparison
- [ ] PHC strings can be serialized and deserialized correctly
- [ ] You understand why we hash on failed login (timing attack prevention)

### Next Steps

In **Part 4: JWT Deep Dive**, we'll implement:
- JWT structure and claims
- HS256 signing with HMAC
- Upgrading to RS256 for asymmetric signing
- Token verification with all security checks
