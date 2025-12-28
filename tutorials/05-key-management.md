# Part 5: Key Management

Asymmetric cryptography requires careful key lifecycle management. In this tutorial, we'll implement RSA key generation, secure storage, automatic rotation, and JWKS distribution for token verification.

---

## Table of Contents

1. [RSA Key Generation](#1-rsa-key-generation)
2. [Key Storage and Loading](#2-key-storage-and-loading)
3. [Key Rotation and JWKS](#3-key-rotation-and-jwks)

---

## 1. RSA Key Generation

### Why RSA-2048?

For RS256 JWTs, we need RSA key pairs:
- **Private key**: Signs tokens (kept secret on auth server)
- **Public key**: Verifies tokens (distributed to all services)

RSA-2048 provides adequate security through 2030+ while maintaining reasonable performance.

### Generating Key Pairs

```typescript
// src/keys/generate.ts

import { getSubtle } from '../crypto/universal';

/**
 * RSA key pair for JWT signing
 */
export interface RSAKeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  keyId: string;
  createdAt: Date;
}

/**
 * Generate a new RSA-2048 key pair for RS256 signing
 */
export async function generateKeyPair(): Promise<RSAKeyPair> {
  const subtle = getSubtle();
  
  const keyPair = await subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
      hash: 'SHA-256'
    },
    true, // extractable - needed for export
    ['sign', 'verify']
  );
  
  // Generate unique key ID
  const keyId = await generateKeyId();
  
  return {
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    keyId,
    createdAt: new Date()
  };
}

/**
 * Generate a unique key ID based on timestamp and random bytes
 */
async function generateKeyId(): Promise<string> {
  const subtle = getSubtle();
  const crypto = globalThis.crypto;
  
  // Combine timestamp with random bytes for uniqueness
  const timestamp = Date.now().toString(36);
  const randomBytes = new Uint8Array(8);
  crypto.getRandomValues(randomBytes);
  
  // Hash to create fixed-length ID
  const combined = new TextEncoder().encode(timestamp + Array.from(randomBytes).join(''));
  const hash = await subtle.digest('SHA-256', combined);
  
  // Take first 12 bytes, encode as base64url
  const hashArray = new Uint8Array(hash).slice(0, 12);
  return btoa(String.fromCharCode(...hashArray))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}
```

### Exporting Keys

Keys must be exported for storage. We use standard formats:
- **PKCS#8**: Private key format
- **SPKI**: Public key format
- **JWK**: JSON Web Key (for JWKS endpoint)

```typescript
// src/keys/export.ts

import { getSubtle } from '../crypto/universal';
import { encode } from '../crypto/base64url';

/**
 * Exported key data for storage
 */
export interface ExportedKeyPair {
  keyId: string;
  privateKeyPkcs8: string;  // Base64-encoded PKCS#8
  publicKeySpki: string;    // Base64-encoded SPKI
  publicKeyJwk: JsonWebKey; // For JWKS endpoint
  createdAt: string;        // ISO timestamp
}

/**
 * Export key pair to storable format
 */
export async function exportKeyPair(
  keyPair: { privateKey: CryptoKey; publicKey: CryptoKey; keyId: string; createdAt: Date }
): Promise<ExportedKeyPair> {
  const subtle = getSubtle();
  
  // Export private key as PKCS#8
  const privateKeyBuffer = await subtle.exportKey('pkcs8', keyPair.privateKey);
  const privateKeyPkcs8 = btoa(String.fromCharCode(...new Uint8Array(privateKeyBuffer)));
  
  // Export public key as SPKI
  const publicKeyBuffer = await subtle.exportKey('spki', keyPair.publicKey);
  const publicKeySpki = btoa(String.fromCharCode(...new Uint8Array(publicKeyBuffer)));
  
  // Export public key as JWK (for JWKS)
  const publicKeyJwk = await subtle.exportKey('jwk', keyPair.publicKey);
  
  // Add key ID to JWK
  publicKeyJwk.kid = keyPair.keyId;
  publicKeyJwk.use = 'sig';
  publicKeyJwk.alg = 'RS256';
  
  return {
    keyId: keyPair.keyId,
    privateKeyPkcs8,
    publicKeySpki,
    publicKeyJwk,
    createdAt: keyPair.createdAt.toISOString()
  };
}

/**
 * Export only the public key for distribution
 */
export async function exportPublicKey(
  publicKey: CryptoKey,
  keyId: string
): Promise<JsonWebKey> {
  const subtle = getSubtle();
  
  const jwk = await subtle.exportKey('jwk', publicKey);
  jwk.kid = keyId;
  jwk.use = 'sig';
  jwk.alg = 'RS256';
  
  return jwk;
}
```

### Importing Keys

```typescript
// src/keys/import.ts

import { getSubtle } from '../crypto/universal';

/**
 * Import private key from PKCS#8 format
 */
export async function importPrivateKey(pkcs8Base64: string): Promise<CryptoKey> {
  const subtle = getSubtle();
  
  // Decode base64 to ArrayBuffer
  const binaryString = atob(pkcs8Base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  
  return subtle.importKey(
    'pkcs8',
    bytes.buffer,
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256'
    },
    false, // not extractable after import
    ['sign']
  );
}

/**
 * Import public key from SPKI format
 */
export async function importPublicKey(spkiBase64: string): Promise<CryptoKey> {
  const subtle = getSubtle();
  
  const binaryString = atob(spkiBase64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  
  return subtle.importKey(
    'spki',
    bytes.buffer,
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256'
    },
    true, // extractable for JWKS export
    ['verify']
  );
}

/**
 * Import public key from JWK format
 */
export async function importPublicKeyJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  const subtle = getSubtle();
  
  return subtle.importKey(
    'jwk',
    jwk,
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256'
    },
    true,
    ['verify']
  );
}
```

### Exercise 5.1

1. Generate a key pair and export it
2. Import the exported keys and verify they work
3. Sign a test message with the private key
4. Verify the signature with the public key

---

## 2. Key Storage and Loading

### Storage Interface

We'll create an abstraction that works with any storage backend:

```typescript
// src/keys/storage.ts

import { ExportedKeyPair } from './export';

/**
 * Key metadata without sensitive data
 */
export interface KeyMetadata {
  keyId: string;
  createdAt: Date;
  rotatedAt?: Date;
  expiresAt?: Date;
  status: 'active' | 'rotated' | 'expired';
}

/**
 * Key storage interface
 */
export interface KeyStorage {
  /**
   * Save a new key pair
   */
  save(keyPair: ExportedKeyPair): Promise<void>;
  
  /**
   * Load the current active key pair
   */
  loadCurrent(): Promise<ExportedKeyPair | null>;
  
  /**
   * Load a specific key by ID (for verification during rotation)
   */
  loadByKeyId(keyId: string): Promise<ExportedKeyPair | null>;
  
  /**
   * List all key metadata
   */
  listKeys(): Promise<KeyMetadata[]>;
  
  /**
   * Mark a key as rotated
   */
  markRotated(keyId: string): Promise<void>;
  
  /**
   * Delete expired keys
   */
  deleteExpired(): Promise<number>;
}
```

### Filesystem Storage

For server environments, filesystem storage with proper permissions:

```typescript
// src/keys/filesystem-storage.ts

import { KeyStorage, KeyMetadata } from './storage';
import { ExportedKeyPair } from './export';

// Using dynamic imports for Node.js compatibility
type FSModule = typeof import('fs/promises');
type PathModule = typeof import('path');

/**
 * Filesystem-based key storage
 * 
 * Directory structure:
 *   keys/
 *     current/
 *       key.json        # Current active key
 *     rotated/
 *       {keyId}/
 *         key.json      # Rotated key (kept for grace period)
 *         metadata.json # Rotation timestamp
 */
export class FilesystemKeyStorage implements KeyStorage {
  private basePath: string;
  private fs: FSModule | null = null;
  private path: PathModule | null = null;
  
  constructor(basePath: string = './keys') {
    this.basePath = basePath;
  }
  
  private async ensureModules(): Promise<{ fs: FSModule; path: PathModule }> {
    if (!this.fs || !this.path) {
      this.fs = await import('fs/promises');
      this.path = await import('path');
    }
    return { fs: this.fs, path: this.path };
  }
  
  private async ensureDirectories(): Promise<void> {
    const { fs, path } = await this.ensureModules();
    
    await fs.mkdir(path.join(this.basePath, 'current'), { recursive: true });
    await fs.mkdir(path.join(this.basePath, 'rotated'), { recursive: true });
  }
  
  async save(keyPair: ExportedKeyPair): Promise<void> {
    const { fs, path } = await this.ensureModules();
    await this.ensureDirectories();
    
    const currentPath = path.join(this.basePath, 'current', 'key.json');
    
    // Check if there's an existing key to rotate
    try {
      const existing = await this.loadCurrent();
      if (existing) {
        await this.rotateKey(existing);
      }
    } catch {
      // No existing key, that's fine
    }
    
    // Save new key as current
    await fs.writeFile(
      currentPath,
      JSON.stringify(keyPair, null, 2),
      { mode: 0o600 } // Owner read/write only
    );
  }
  
  private async rotateKey(keyPair: ExportedKeyPair): Promise<void> {
    const { fs, path } = await this.ensureModules();
    
    const rotatedDir = path.join(this.basePath, 'rotated', keyPair.keyId);
    await fs.mkdir(rotatedDir, { recursive: true });
    
    // Save key
    await fs.writeFile(
      path.join(rotatedDir, 'key.json'),
      JSON.stringify(keyPair, null, 2),
      { mode: 0o600 }
    );
    
    // Save rotation metadata
    const metadata = {
      rotatedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString() // 7 day grace
    };
    
    await fs.writeFile(
      path.join(rotatedDir, 'metadata.json'),
      JSON.stringify(metadata, null, 2)
    );
  }
  
  async loadCurrent(): Promise<ExportedKeyPair | null> {
    const { fs, path } = await this.ensureModules();
    
    try {
      const currentPath = path.join(this.basePath, 'current', 'key.json');
      const content = await fs.readFile(currentPath, 'utf-8');
      return JSON.parse(content);
    } catch {
      return null;
    }
  }
  
  async loadByKeyId(keyId: string): Promise<ExportedKeyPair | null> {
    const { fs, path } = await this.ensureModules();
    
    // Check current key first
    const current = await this.loadCurrent();
    if (current?.keyId === keyId) {
      return current;
    }
    
    // Check rotated keys
    try {
      const rotatedPath = path.join(this.basePath, 'rotated', keyId, 'key.json');
      const content = await fs.readFile(rotatedPath, 'utf-8');
      return JSON.parse(content);
    } catch {
      return null;
    }
  }
  
  async listKeys(): Promise<KeyMetadata[]> {
    const { fs, path } = await this.ensureModules();
    const keys: KeyMetadata[] = [];
    
    // Get current key
    const current = await this.loadCurrent();
    if (current) {
      keys.push({
        keyId: current.keyId,
        createdAt: new Date(current.createdAt),
        status: 'active'
      });
    }
    
    // Get rotated keys
    try {
      const rotatedDir = path.join(this.basePath, 'rotated');
      const entries = await fs.readdir(rotatedDir, { withFileTypes: true });
      
      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        
        try {
          const keyPath = path.join(rotatedDir, entry.name, 'key.json');
          const metaPath = path.join(rotatedDir, entry.name, 'metadata.json');
          
          const keyContent = await fs.readFile(keyPath, 'utf-8');
          const keyData = JSON.parse(keyContent);
          
          let metadata: { rotatedAt?: string; expiresAt?: string } = {};
          try {
            const metaContent = await fs.readFile(metaPath, 'utf-8');
            metadata = JSON.parse(metaContent);
          } catch {
            // Metadata optional
          }
          
          const expiresAt = metadata.expiresAt ? new Date(metadata.expiresAt) : undefined;
          const isExpired = expiresAt && expiresAt < new Date();
          
          keys.push({
            keyId: keyData.keyId,
            createdAt: new Date(keyData.createdAt),
            rotatedAt: metadata.rotatedAt ? new Date(metadata.rotatedAt) : undefined,
            expiresAt,
            status: isExpired ? 'expired' : 'rotated'
          });
        } catch {
          // Skip invalid entries
        }
      }
    } catch {
      // No rotated directory
    }
    
    return keys;
  }
  
  async markRotated(keyId: string): Promise<void> {
    // Already handled in save() when rotating
  }
  
  async deleteExpired(): Promise<number> {
    const { fs, path } = await this.ensureModules();
    
    const keys = await this.listKeys();
    const expired = keys.filter(k => k.status === 'expired');
    
    for (const key of expired) {
      try {
        const rotatedDir = path.join(this.basePath, 'rotated', key.keyId);
        await fs.rm(rotatedDir, { recursive: true });
      } catch {
        // Ignore deletion errors
      }
    }
    
    return expired.length;
  }
}
```

### Key Provider

The key provider loads and caches keys for use:

```typescript
// src/keys/provider.ts

import { KeyStorage } from './storage';
import { importPrivateKey, importPublicKey, importPublicKeyJwk } from './import';
import { generateKeyPair } from './generate';
import { exportKeyPair, ExportedKeyPair } from './export';

/**
 * Loaded key ready for use
 */
export interface LoadedKey {
  keyId: string;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  createdAt: Date;
}

/**
 * Key provider options
 */
export interface KeyProviderOptions {
  /** Storage backend */
  storage: KeyStorage;
  
  /** Key lifetime in days before rotation (default: 90) */
  rotationDays?: number;
  
  /** Grace period in days for old keys (default: 7) */
  gracePeriodDays?: number;
  
  /** Auto-generate key if none exists (default: true) */
  autoGenerate?: boolean;
}

/**
 * Key provider manages key lifecycle
 */
export class KeyProvider {
  private storage: KeyStorage;
  private rotationDays: number;
  private gracePeriodDays: number;
  private autoGenerate: boolean;
  
  // Cache loaded keys
  private currentKey: LoadedKey | null = null;
  private keyCache: Map<string, CryptoKey> = new Map();
  
  constructor(options: KeyProviderOptions) {
    this.storage = options.storage;
    this.rotationDays = options.rotationDays ?? 90;
    this.gracePeriodDays = options.gracePeriodDays ?? 7;
    this.autoGenerate = options.autoGenerate ?? true;
  }
  
  /**
   * Get the current signing key
   */
  async getSigningKey(): Promise<LoadedKey> {
    // Check cache
    if (this.currentKey && !this.needsRotation(this.currentKey)) {
      return this.currentKey;
    }
    
    // Load from storage
    const stored = await this.storage.loadCurrent();
    
    if (stored) {
      // Check if rotation needed
      const createdAt = new Date(stored.createdAt);
      const daysSinceCreation = (Date.now() - createdAt.getTime()) / (1000 * 60 * 60 * 24);
      
      if (daysSinceCreation >= this.rotationDays) {
        // Rotation needed
        return this.rotateKeys();
      }
      
      // Load and cache
      this.currentKey = await this.loadKey(stored);
      return this.currentKey;
    }
    
    // No key exists
    if (this.autoGenerate) {
      return this.rotateKeys();
    }
    
    throw new Error('No signing key available and auto-generation disabled');
  }
  
  /**
   * Get a public key by ID for verification
   */
  async getPublicKey(keyId: string): Promise<CryptoKey | null> {
    // Check cache
    const cached = this.keyCache.get(keyId);
    if (cached) {
      return cached;
    }
    
    // Check current key
    if (this.currentKey?.keyId === keyId) {
      return this.currentKey.publicKey;
    }
    
    // Load from storage
    const stored = await this.storage.loadByKeyId(keyId);
    if (!stored) {
      return null;
    }
    
    // Import and cache public key
    const publicKey = await importPublicKey(stored.publicKeySpki);
    this.keyCache.set(keyId, publicKey);
    
    return publicKey;
  }
  
  /**
   * Get all public keys for JWKS endpoint
   */
  async getPublicKeys(): Promise<JsonWebKey[]> {
    const keys = await this.storage.listKeys();
    const jwks: JsonWebKey[] = [];
    
    for (const keyMeta of keys) {
      if (keyMeta.status === 'expired') continue;
      
      const stored = await this.storage.loadByKeyId(keyMeta.keyId);
      if (stored?.publicKeyJwk) {
        jwks.push(stored.publicKeyJwk);
      }
    }
    
    return jwks;
  }
  
  /**
   * Force key rotation
   */
  async rotateKeys(): Promise<LoadedKey> {
    // Generate new key pair
    const keyPair = await generateKeyPair();
    const exported = await exportKeyPair(keyPair);
    
    // Save to storage (this handles rotating old key)
    await this.storage.save(exported);
    
    // Update cache
    this.currentKey = {
      keyId: keyPair.keyId,
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
      createdAt: keyPair.createdAt
    };
    
    // Clean up expired keys
    await this.storage.deleteExpired();
    
    return this.currentKey;
  }
  
  /**
   * Check if a key needs rotation
   */
  private needsRotation(key: LoadedKey): boolean {
    const daysSinceCreation = (Date.now() - key.createdAt.getTime()) / (1000 * 60 * 60 * 24);
    // Rotate at 90% of lifetime to ensure smooth transition
    return daysSinceCreation >= this.rotationDays * 0.9;
  }
  
  /**
   * Load a stored key into CryptoKey objects
   */
  private async loadKey(stored: ExportedKeyPair): Promise<LoadedKey> {
    const [privateKey, publicKey] = await Promise.all([
      importPrivateKey(stored.privateKeyPkcs8),
      importPublicKey(stored.publicKeySpki)
    ]);
    
    return {
      keyId: stored.keyId,
      privateKey,
      publicKey,
      createdAt: new Date(stored.createdAt)
    };
  }
}
```

### Exercise 5.2

1. Create a `FilesystemKeyStorage` instance
2. Generate and save a key pair
3. Load the key and verify it matches
4. Simulate rotation by saving a new key
5. Verify both keys are accessible

---

## 3. Key Rotation and JWKS

### Rotation Strategy

Our rotation strategy ensures zero-downtime key changes:

1. **New tokens** are signed with the new key immediately
2. **Existing tokens** remain valid during the grace period (7 days)
3. **Old keys** are kept for verification until grace period expires
4. **JWKS endpoint** includes both current and rotated keys

```typescript
// src/keys/rotation.ts

import { KeyProvider } from './provider';
import { KeyStorage } from './storage';

/**
 * Key rotation manager
 */
export class KeyRotationManager {
  private provider: KeyProvider;
  private storage: KeyStorage;
  private checkIntervalMs: number;
  private intervalId: ReturnType<typeof setInterval> | null = null;
  
  constructor(
    provider: KeyProvider,
    storage: KeyStorage,
    checkIntervalHours: number = 24
  ) {
    this.provider = provider;
    this.storage = storage;
    this.checkIntervalMs = checkIntervalHours * 60 * 60 * 1000;
  }
  
  /**
   * Start automatic rotation checks
   */
  start(): void {
    if (this.intervalId) return;
    
    // Check immediately
    this.checkRotation();
    
    // Schedule periodic checks
    this.intervalId = setInterval(() => {
      this.checkRotation();
    }, this.checkIntervalMs);
  }
  
  /**
   * Stop automatic rotation
   */
  stop(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  }
  
  /**
   * Check if rotation is needed and perform it
   */
  async checkRotation(): Promise<{ rotated: boolean; reason?: string }> {
    try {
      const keys = await this.storage.listKeys();
      const current = keys.find(k => k.status === 'active');
      
      if (!current) {
        // No active key, generate one
        await this.provider.rotateKeys();
        return { rotated: true, reason: 'no_active_key' };
      }
      
      const daysSinceCreation = (Date.now() - current.createdAt.getTime()) / (1000 * 60 * 60 * 24);
      
      // Rotate at 81 days (90% of 90-day lifetime)
      if (daysSinceCreation >= 81) {
        await this.provider.rotateKeys();
        return { rotated: true, reason: 'age_threshold' };
      }
      
      // Clean up expired keys
      const deleted = await this.storage.deleteExpired();
      if (deleted > 0) {
        console.log(`Cleaned up ${deleted} expired key(s)`);
      }
      
      return { rotated: false };
    } catch (error) {
      console.error('Key rotation check failed:', error);
      return { rotated: false, reason: 'error' };
    }
  }
  
  /**
   * Get rotation status
   */
  async getStatus(): Promise<{
    currentKeyId: string | null;
    currentKeyAge: number;
    nextRotationIn: number;
    rotatedKeysCount: number;
  }> {
    const keys = await this.storage.listKeys();
    const current = keys.find(k => k.status === 'active');
    const rotated = keys.filter(k => k.status === 'rotated');
    
    if (!current) {
      return {
        currentKeyId: null,
        currentKeyAge: 0,
        nextRotationIn: 0,
        rotatedKeysCount: rotated.length
      };
    }
    
    const currentKeyAge = Math.floor(
      (Date.now() - current.createdAt.getTime()) / (1000 * 60 * 60 * 24)
    );
    
    const nextRotationIn = Math.max(0, 81 - currentKeyAge);
    
    return {
      currentKeyId: current.keyId,
      currentKeyAge,
      nextRotationIn,
      rotatedKeysCount: rotated.length
    };
  }
}
```

### JWKS Endpoint

The JWKS (JSON Web Key Set) endpoint allows other services to fetch public keys:

```typescript
// src/keys/jwks.ts

import { KeyProvider } from './provider';

/**
 * JWKS response format
 */
export interface JWKSResponse {
  keys: JsonWebKey[];
}

/**
 * JWKS handler for HTTP endpoints
 */
export class JWKSHandler {
  private provider: KeyProvider;
  private cacheMaxAge: number;
  
  constructor(provider: KeyProvider, cacheMaxAgeSeconds: number = 3600) {
    this.provider = provider;
    this.cacheMaxAge = cacheMaxAgeSeconds;
  }
  
  /**
   * Get JWKS response
   */
  async getJWKS(): Promise<JWKSResponse> {
    const keys = await this.provider.getPublicKeys();
    return { keys };
  }
  
  /**
   * Get cache headers for JWKS response
   */
  getCacheHeaders(): Record<string, string> {
    return {
      'Cache-Control': `public, max-age=${this.cacheMaxAge}`,
      'Content-Type': 'application/json'
    };
  }
  
  /**
   * Express/Koa compatible handler
   */
  handler() {
    return async (req: unknown, res: { json: (data: unknown) => void; set: (headers: Record<string, string>) => void }) => {
      const jwks = await this.getJWKS();
      res.set(this.getCacheHeaders());
      res.json(jwks);
    };
  }
}

/**
 * Create JWKS endpoint response
 */
export async function createJWKSResponse(provider: KeyProvider): Promise<{
  body: JWKSResponse;
  headers: Record<string, string>;
}> {
  const handler = new JWKSHandler(provider);
  
  return {
    body: await handler.getJWKS(),
    headers: handler.getCacheHeaders()
  };
}
```

### Fetching Remote JWKS

For services that need to verify tokens from other issuers:

```typescript
// src/keys/jwks-client.ts

import { importPublicKeyJwk } from './import';

/**
 * JWKS client options
 */
export interface JWKSClientOptions {
  /** JWKS endpoint URL */
  url: string;
  
  /** Cache TTL in milliseconds (default: 1 hour) */
  cacheTtlMs?: number;
  
  /** Request timeout in milliseconds (default: 5000) */
  timeoutMs?: number;
}

/**
 * Client for fetching and caching JWKS from remote endpoints
 */
export class JWKSClient {
  private url: string;
  private cacheTtlMs: number;
  private timeoutMs: number;
  
  private cache: Map<string, CryptoKey> = new Map();
  private jwksCache: JsonWebKey[] | null = null;
  private lastFetch: number = 0;
  
  constructor(options: JWKSClientOptions) {
    this.url = options.url;
    this.cacheTtlMs = options.cacheTtlMs ?? 60 * 60 * 1000; // 1 hour
    this.timeoutMs = options.timeoutMs ?? 5000;
  }
  
  /**
   * Get a public key by key ID
   */
  async getKey(keyId: string): Promise<CryptoKey | null> {
    // Check key cache
    const cached = this.cache.get(keyId);
    if (cached) {
      return cached;
    }
    
    // Fetch JWKS if cache expired
    if (this.shouldRefetch()) {
      await this.fetchJWKS();
    }
    
    // Find key in JWKS
    const jwk = this.jwksCache?.find(k => k.kid === keyId);
    if (!jwk) {
      // Key not found, try refetching in case of rotation
      await this.fetchJWKS();
      const retryJwk = this.jwksCache?.find(k => k.kid === keyId);
      if (!retryJwk) {
        return null;
      }
      return this.importAndCache(retryJwk);
    }
    
    return this.importAndCache(jwk);
  }
  
  private shouldRefetch(): boolean {
    return !this.jwksCache || Date.now() - this.lastFetch > this.cacheTtlMs;
  }
  
  private async fetchJWKS(): Promise<void> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);
    
    try {
      const response = await fetch(this.url, {
        signal: controller.signal,
        headers: { 'Accept': 'application/json' }
      });
      
      if (!response.ok) {
        throw new Error(`JWKS fetch failed: ${response.status}`);
      }
      
      const data = await response.json() as { keys: JsonWebKey[] };
      this.jwksCache = data.keys;
      this.lastFetch = Date.now();
    } finally {
      clearTimeout(timeoutId);
    }
  }
  
  private async importAndCache(jwk: JsonWebKey): Promise<CryptoKey> {
    const key = await importPublicKeyJwk(jwk);
    if (jwk.kid) {
      this.cache.set(jwk.kid, key);
    }
    return key;
  }
  
  /**
   * Clear the cache (useful for testing or forced refresh)
   */
  clearCache(): void {
    this.cache.clear();
    this.jwksCache = null;
    this.lastFetch = 0;
  }
}
```

### Putting It All Together

```typescript
// src/keys/index.ts

export { generateKeyPair, RSAKeyPair } from './generate';
export { exportKeyPair, exportPublicKey, ExportedKeyPair } from './export';
export { importPrivateKey, importPublicKey, importPublicKeyJwk } from './import';
export { KeyStorage, KeyMetadata } from './storage';
export { FilesystemKeyStorage } from './filesystem-storage';
export { KeyProvider, KeyProviderOptions, LoadedKey } from './provider';
export { KeyRotationManager } from './rotation';
export { JWKSHandler, JWKSResponse, createJWKSResponse } from './jwks';
export { JWKSClient, JWKSClientOptions } from './jwks-client';

/**
 * Quick setup for common use cases
 */
import { FilesystemKeyStorage } from './filesystem-storage';
import { KeyProvider } from './provider';
import { KeyRotationManager } from './rotation';
import { JWKSHandler } from './jwks';

export interface KeySystemOptions {
  /** Path for key storage (default: ./keys) */
  storagePath?: string;
  
  /** Key lifetime in days (default: 90) */
  rotationDays?: number;
  
  /** Grace period for old keys in days (default: 7) */
  gracePeriodDays?: number;
  
  /** Enable automatic rotation checks (default: true) */
  autoRotation?: boolean;
}

export interface KeySystem {
  provider: KeyProvider;
  rotationManager: KeyRotationManager;
  jwksHandler: JWKSHandler;
  
  /** Start rotation checks and return cleanup function */
  start(): () => void;
}

/**
 * Create a complete key management system
 */
export function createKeySystem(options: KeySystemOptions = {}): KeySystem {
  const storage = new FilesystemKeyStorage(options.storagePath ?? './keys');
  
  const provider = new KeyProvider({
    storage,
    rotationDays: options.rotationDays ?? 90,
    gracePeriodDays: options.gracePeriodDays ?? 7,
    autoGenerate: true
  });
  
  const rotationManager = new KeyRotationManager(provider, storage);
  const jwksHandler = new JWKSHandler(provider);
  
  return {
    provider,
    rotationManager,
    jwksHandler,
    
    start() {
      if (options.autoRotation !== false) {
        rotationManager.start();
      }
      
      return () => {
        rotationManager.stop();
      };
    }
  };
}
```

### Example Usage

```typescript
// Example: Setting up key management

import { createKeySystem } from './keys';

async function main() {
  // Create key system
  const keySystem = createKeySystem({
    storagePath: './keys',
    rotationDays: 90,
    autoRotation: true
  });
  
  // Start rotation monitoring
  const cleanup = keySystem.start();
  
  // Get signing key for JWT creation
  const signingKey = await keySystem.provider.getSigningKey();
  console.log('Current key ID:', signingKey.keyId);
  
  // Sign a token (using JWT module from Part 4)
  // const token = await createRS256Token(payload, signingKey.privateKey, signingKey.keyId);
  
  // Get public key for verification (e.g., from kid in JWT header)
  const publicKey = await keySystem.provider.getPublicKey(signingKey.keyId);
  
  // Get JWKS for endpoint
  const jwks = await keySystem.jwksHandler.getJWKS();
  console.log('JWKS:', JSON.stringify(jwks, null, 2));
  
  // Check rotation status
  const status = await keySystem.rotationManager.getStatus();
  console.log('Rotation status:', status);
  
  // Cleanup on shutdown
  process.on('SIGTERM', () => {
    cleanup();
    process.exit(0);
  });
}

main().catch(console.error);
```

### Exercise 5.3

1. Implement a complete key system
2. Create an HTTP endpoint that serves JWKS
3. Test key rotation by modifying the creation date
4. Verify old tokens still work during grace period
5. Implement a JWKSClient that fetches from your endpoint

---

## Summary

In this tutorial, you learned:

1. **RSA Key Generation** — Creating 2048-bit key pairs with unique IDs
2. **Key Export/Import** — Converting between CryptoKey and storable formats (PKCS#8, SPKI, JWK)
3. **Key Storage** — Filesystem-based storage with proper structure and permissions
4. **Key Provider** — Loading, caching, and managing key lifecycle
5. **Key Rotation** — Automatic rotation at 90% lifetime with 7-day grace period
6. **JWKS Distribution** — Serving public keys for token verification

### Files Created

```
src/keys/
├── generate.ts          # Key pair generation
├── export.ts            # Export to storable formats
├── import.ts            # Import from stored formats
├── storage.ts           # Storage interface
├── filesystem-storage.ts # Filesystem implementation
├── provider.ts          # Key provider with caching
├── rotation.ts          # Rotation manager
├── jwks.ts              # JWKS endpoint handler
├── jwks-client.ts       # Remote JWKS fetching
└── index.ts             # Public exports and quick setup
```

### Key Rotation Timeline

```
Day 0:   Key A generated, active
Day 81:  Key A at 90% lifetime, rotation triggered
         Key B generated, active
         Key A moved to rotated (7-day grace)
Day 88:  Key A expired, deleted
Day 162: Key B at 90% lifetime, rotation triggered
         Key C generated, active
         Key B moved to rotated
...
```

### Next Steps

In [Part 6: Token Security](./06-token-security.md), we'll implement token fingerprinting and secure cookie handling to prevent token theft.
