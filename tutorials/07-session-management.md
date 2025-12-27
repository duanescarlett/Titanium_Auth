# Part 7: Session Management

Access tokens are stateless, but refresh tokens require server-side tracking to enable revocation, rotation, and multi-device support. In this part, we'll build a flexible session store abstraction, implement secure refresh token flows, and handle multi-device scenarios.

---

## Table of Contents

1. [Session Store Design](#1-session-store-design)
2. [Refresh Token Flow](#2-refresh-token-flow)
3. [Multi-Device Sessions](#3-multi-device-sessions)

---

## 1. Session Store Design

### Why Server-Side State?

Access tokens are self-contained — the server doesn't need to store them. But refresh tokens need tracking because:

| Requirement | Why Server State is Needed |
|-------------|---------------------------|
| **Revocation** | User logs out, token must be immediately invalid |
| **Rotation** | Old tokens must be invalidated when new ones are issued |
| **Device Tracking** | User wants to see/manage active sessions |
| **Theft Detection** | Reuse of rotated token indicates theft |
| **Limit Sessions** | Cap active sessions per user |

### Session Data Model

```typescript
// src/sessions/types.ts

/**
 * A single session represents one authenticated device/browser
 */
export interface Session {
  /** Unique session identifier */
  id: string;
  
  /** User this session belongs to */
  userId: string;
  
  /** Hashed refresh token (never store raw tokens!) */
  refreshTokenHash: string;
  
  /** When this session was created */
  createdAt: Date;
  
  /** When the refresh token expires */
  expiresAt: Date;
  
  /** Last time this session was used */
  lastUsedAt: Date;
  
  /** Device/browser information */
  userAgent?: string;
  
  /** IP address of the client */
  ipAddress?: string;
  
  /** Optional device identifier */
  deviceId?: string;
  
  /** Whether this session is still valid */
  isRevoked: boolean;
  
  /** If revoked, reason for revocation */
  revokedReason?: 'logout' | 'token_rotation' | 'security' | 'expired' | 'admin';
  
  /** Token family for rotation tracking */
  tokenFamily: string;
  
  /** Generation number within the token family */
  tokenGeneration: number;
}

/**
 * Data needed to create a new session
 */
export interface CreateSessionInput {
  userId: string;
  refreshToken: string;  // Raw token, will be hashed before storage
  expiresAt: Date;
  userAgent?: string;
  ipAddress?: string;
  deviceId?: string;
}

/**
 * Session metadata for user display (no sensitive data)
 */
export interface SessionInfo {
  id: string;
  createdAt: Date;
  lastUsedAt: Date;
  userAgent?: string;
  ipAddress?: string;
  isCurrent: boolean;
}
```

### Storage Abstraction

```typescript
// src/sessions/store.ts

import { Session, CreateSessionInput, SessionInfo } from './types';

/**
 * Abstract session store interface
 * Implement this for your storage backend (memory, Redis, PostgreSQL, etc.)
 */
export interface SessionStore {
  /**
   * Create a new session
   * @returns The created session
   */
  create(input: CreateSessionInput): Promise<Session>;
  
  /**
   * Find session by ID
   */
  findById(sessionId: string): Promise<Session | null>;
  
  /**
   * Find session by refresh token hash
   */
  findByTokenHash(tokenHash: string): Promise<Session | null>;
  
  /**
   * Find all sessions for a user
   */
  findByUserId(userId: string): Promise<Session[]>;
  
  /**
   * Update session (e.g., after token rotation)
   */
  update(sessionId: string, updates: Partial<Session>): Promise<Session | null>;
  
  /**
   * Revoke a specific session
   */
  revoke(sessionId: string, reason: Session['revokedReason']): Promise<boolean>;
  
  /**
   * Revoke all sessions for a user
   * @param exceptSessionId - Optional session to keep active
   */
  revokeAllForUser(userId: string, exceptSessionId?: string): Promise<number>;
  
  /**
   * Revoke all sessions in a token family (theft detection)
   */
  revokeTokenFamily(tokenFamily: string): Promise<number>;
  
  /**
   * Delete expired sessions (cleanup)
   */
  deleteExpired(): Promise<number>;
  
  /**
   * Count active sessions for a user
   */
  countActiveForUser(userId: string): Promise<number>;
}
```

### In-Memory Implementation

```typescript
// src/sessions/memory-store.ts

import { Session, CreateSessionInput } from './types';
import { SessionStore } from './store';
import { generateSecureId, hashToken } from './utils';

/**
 * In-memory session store for development and testing
 * 
 * ⚠️ WARNING: Do not use in production!
 * - Data is lost on restart
 * - No horizontal scaling support
 * - Memory grows unbounded without cleanup
 */
export class MemorySessionStore implements SessionStore {
  private sessions: Map<string, Session> = new Map();
  private tokenHashIndex: Map<string, string> = new Map();  // hash -> sessionId
  private userIndex: Map<string, Set<string>> = new Map();  // userId -> sessionIds
  private familyIndex: Map<string, Set<string>> = new Map(); // family -> sessionIds
  
  async create(input: CreateSessionInput): Promise<Session> {
    const sessionId = generateSecureId();
    const tokenFamily = generateSecureId();
    const tokenHash = await hashToken(input.refreshToken);
    const now = new Date();
    
    const session: Session = {
      id: sessionId,
      userId: input.userId,
      refreshTokenHash: tokenHash,
      createdAt: now,
      expiresAt: input.expiresAt,
      lastUsedAt: now,
      userAgent: input.userAgent,
      ipAddress: input.ipAddress,
      deviceId: input.deviceId,
      isRevoked: false,
      tokenFamily,
      tokenGeneration: 1
    };
    
    // Store session
    this.sessions.set(sessionId, session);
    
    // Update indexes
    this.tokenHashIndex.set(tokenHash, sessionId);
    
    if (!this.userIndex.has(input.userId)) {
      this.userIndex.set(input.userId, new Set());
    }
    this.userIndex.get(input.userId)!.add(sessionId);
    
    if (!this.familyIndex.has(tokenFamily)) {
      this.familyIndex.set(tokenFamily, new Set());
    }
    this.familyIndex.get(tokenFamily)!.add(sessionId);
    
    return session;
  }
  
  async findById(sessionId: string): Promise<Session | null> {
    return this.sessions.get(sessionId) ?? null;
  }
  
  async findByTokenHash(tokenHash: string): Promise<Session | null> {
    const sessionId = this.tokenHashIndex.get(tokenHash);
    if (!sessionId) return null;
    return this.sessions.get(sessionId) ?? null;
  }
  
  async findByUserId(userId: string): Promise<Session[]> {
    const sessionIds = this.userIndex.get(userId);
    if (!sessionIds) return [];
    
    const sessions: Session[] = [];
    for (const id of sessionIds) {
      const session = this.sessions.get(id);
      if (session) {
        sessions.push(session);
      }
    }
    
    return sessions;
  }
  
  async update(sessionId: string, updates: Partial<Session>): Promise<Session | null> {
    const session = this.sessions.get(sessionId);
    if (!session) return null;
    
    // Handle token hash change
    if (updates.refreshTokenHash && updates.refreshTokenHash !== session.refreshTokenHash) {
      this.tokenHashIndex.delete(session.refreshTokenHash);
      this.tokenHashIndex.set(updates.refreshTokenHash, sessionId);
    }
    
    const updatedSession = { ...session, ...updates };
    this.sessions.set(sessionId, updatedSession);
    
    return updatedSession;
  }
  
  async revoke(sessionId: string, reason: Session['revokedReason']): Promise<boolean> {
    const session = this.sessions.get(sessionId);
    if (!session) return false;
    
    session.isRevoked = true;
    session.revokedReason = reason;
    
    // Remove from token hash index (can't be used anymore)
    this.tokenHashIndex.delete(session.refreshTokenHash);
    
    return true;
  }
  
  async revokeAllForUser(userId: string, exceptSessionId?: string): Promise<number> {
    const sessionIds = this.userIndex.get(userId);
    if (!sessionIds) return 0;
    
    let count = 0;
    for (const id of sessionIds) {
      if (id === exceptSessionId) continue;
      
      const revoked = await this.revoke(id, 'security');
      if (revoked) count++;
    }
    
    return count;
  }
  
  async revokeTokenFamily(tokenFamily: string): Promise<number> {
    const sessionIds = this.familyIndex.get(tokenFamily);
    if (!sessionIds) return 0;
    
    let count = 0;
    for (const id of sessionIds) {
      const revoked = await this.revoke(id, 'security');
      if (revoked) count++;
    }
    
    return count;
  }
  
  async deleteExpired(): Promise<number> {
    const now = new Date();
    let count = 0;
    
    for (const [id, session] of this.sessions) {
      if (session.expiresAt < now || session.isRevoked) {
        // Clean up indexes
        this.tokenHashIndex.delete(session.refreshTokenHash);
        this.userIndex.get(session.userId)?.delete(id);
        this.familyIndex.get(session.tokenFamily)?.delete(id);
        this.sessions.delete(id);
        count++;
      }
    }
    
    return count;
  }
  
  async countActiveForUser(userId: string): Promise<number> {
    const sessions = await this.findByUserId(userId);
    const now = new Date();
    
    return sessions.filter(s => 
      !s.isRevoked && s.expiresAt > now
    ).length;
  }
}
```

### Session Utilities

```typescript
// src/sessions/utils.ts

import { getSubtle, getUniversalCrypto } from '../crypto/universal';
import { encode as base64urlEncode } from '../crypto/base64url';

/**
 * Generate a cryptographically secure session ID
 * 
 * @param byteLength - Length in bytes (default 24 = 192 bits)
 * @returns Base64URL-encoded ID
 */
export function generateSecureId(byteLength: number = 24): string {
  const crypto = getUniversalCrypto();
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64urlEncode(bytes);
}

/**
 * Generate a refresh token
 * 
 * @param byteLength - Length in bytes (default 48 = 384 bits)
 * @returns Base64URL-encoded token
 */
export function generateRefreshToken(byteLength: number = 48): string {
  return generateSecureId(byteLength);
}

/**
 * Hash a token for storage
 * Never store raw refresh tokens!
 * 
 * @param token - Raw token value
 * @returns SHA-256 hash as Base64URL
 */
export async function hashToken(token: string): Promise<string> {
  const subtle = getSubtle();
  const encoder = new TextEncoder();
  const data = encoder.encode(token);
  const hashBuffer = await subtle.digest('SHA-256', data);
  return base64urlEncode(new Uint8Array(hashBuffer));
}

/**
 * Check if a session is valid (not revoked, not expired)
 */
export function isSessionValid(session: {
  isRevoked: boolean;
  expiresAt: Date;
}): boolean {
  if (session.isRevoked) return false;
  if (session.expiresAt < new Date()) return false;
  return true;
}

/**
 * Calculate session expiry date
 * 
 * @param daysFromNow - Days until expiry (default 30)
 * @returns Expiry date
 */
export function calculateExpiryDate(daysFromNow: number = 30): Date {
  const date = new Date();
  date.setDate(date.getDate() + daysFromNow);
  return date;
}
```

### Exercise 7.1

1. Create `src/sessions/types.ts` with the Session interface
2. Create `src/sessions/store.ts` with the SessionStore interface
3. Implement `src/sessions/memory-store.ts` for development
4. Test creating, finding, and revoking sessions

---

## 2. Refresh Token Flow

### Token Rotation Strategy

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Refresh Token Rotation                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Login                                                                      │
│   ─────                                                                      │
│   1. User authenticates with credentials                                     │
│   2. Create Session with Token Family "ABC"                                  │
│   3. Issue Refresh Token RT-1 (generation 1)                                 │
│   4. Return Access Token + RT-1                                              │
│                                                                              │
│   Normal Refresh                                                             │
│   ──────────────                                                             │
│   1. Client sends RT-1                                                       │
│   2. Server validates RT-1 hash                                              │
│   3. Increment generation → 2                                                │
│   4. Issue new RT-2 (generation 2)                                           │
│   5. Update session with RT-2 hash                                           │
│   6. RT-1 is now invalid                                                     │
│   7. Return new Access Token + RT-2                                          │
│                                                                              │
│   Token Theft Detection                                                      │
│   ──────────────────────                                                     │
│   1. Attacker uses stolen RT-1                                               │
│   2. Server sees RT-1 hash doesn't match current (RT-2)                      │
│   3. But RT-1 was in same family "ABC"                                       │
│   4. ALERT: Token reuse detected!                                            │
│   5. Revoke ALL tokens in family "ABC"                                       │
│   6. User must re-authenticate                                               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Refresh Token Service

```typescript
// src/sessions/refresh-service.ts

import { Session, CreateSessionInput } from './types';
import { SessionStore } from './store';
import { generateRefreshToken, hashToken, isSessionValid, calculateExpiryDate } from './utils';
import { TokenFingerprinter } from '../fingerprint';
import { CookieHandler } from '../cookies';

/**
 * Configuration for RefreshTokenService
 */
export interface RefreshServiceConfig {
  /** Refresh token lifetime in days */
  tokenLifetimeDays: number;
  
  /** Maximum active sessions per user (0 = unlimited) */
  maxSessionsPerUser: number;
  
  /** Whether to detect and handle token reuse */
  enableReuseDetection: boolean;
}

/**
 * Result of a refresh operation
 */
export interface RefreshResult {
  success: boolean;
  accessToken?: string;
  refreshToken?: string;
  cookies?: string[];
  error?: 'INVALID_TOKEN' | 'SESSION_REVOKED' | 'SESSION_EXPIRED' | 
          'TOKEN_REUSE_DETECTED' | 'FINGERPRINT_MISMATCH' | 'INTERNAL_ERROR';
}

/**
 * Manages refresh token lifecycle
 */
export class RefreshTokenService {
  private store: SessionStore;
  private config: RefreshServiceConfig;
  private fingerprinter: TokenFingerprinter;
  private cookieHandler: CookieHandler;
  private createAccessToken: (userId: string, claims?: Record<string, unknown>) => Promise<string>;
  
  constructor(
    store: SessionStore,
    createAccessToken: (userId: string, claims?: Record<string, unknown>) => Promise<string>,
    config: Partial<RefreshServiceConfig> = {}
  ) {
    this.store = store;
    this.createAccessToken = createAccessToken;
    this.config = {
      tokenLifetimeDays: config.tokenLifetimeDays ?? 30,
      maxSessionsPerUser: config.maxSessionsPerUser ?? 5,
      enableReuseDetection: config.enableReuseDetection ?? true
    };
    this.fingerprinter = new TokenFingerprinter();
    this.cookieHandler = new CookieHandler();
  }
  
  /**
   * Create a new session (called after successful authentication)
   */
  async createSession(input: {
    userId: string;
    userAgent?: string;
    ipAddress?: string;
    deviceId?: string;
  }): Promise<{
    session: Session;
    accessToken: string;
    refreshToken: string;
    cookies: string[];
  }> {
    // Check session limit
    if (this.config.maxSessionsPerUser > 0) {
      const activeCount = await this.store.countActiveForUser(input.userId);
      
      if (activeCount >= this.config.maxSessionsPerUser) {
        // Revoke oldest session
        const sessions = await this.store.findByUserId(input.userId);
        const activeSessions = sessions
          .filter(s => isSessionValid(s))
          .sort((a, b) => a.lastUsedAt.getTime() - b.lastUsedAt.getTime());
        
        if (activeSessions.length > 0) {
          await this.store.revoke(activeSessions[0].id, 'security');
        }
      }
    }
    
    // Generate tokens
    const refreshToken = generateRefreshToken();
    const accessToken = await this.createAccessToken(input.userId);
    
    // Create fingerprint
    const { claim, cookie: fptCookie, raw: fptRaw } = await this.fingerprinter.create();
    
    // Store session
    const session = await this.store.create({
      userId: input.userId,
      refreshToken,
      expiresAt: calculateExpiryDate(this.config.tokenLifetimeDays),
      userAgent: input.userAgent,
      ipAddress: input.ipAddress,
      deviceId: input.deviceId
    });
    
    // Create cookies
    const refreshCookie = this.cookieHandler.createRefreshTokenCookie(
      refreshToken,
      this.config.tokenLifetimeDays * 24 * 60 * 60
    );
    
    return {
      session,
      accessToken,
      refreshToken,
      cookies: [refreshCookie, fptCookie]
    };
  }
  
  /**
   * Refresh tokens using a valid refresh token
   */
  async refresh(input: {
    refreshToken: string;
    cookieHeader?: string;
    userAgent?: string;
    ipAddress?: string;
  }): Promise<RefreshResult> {
    try {
      // Hash the provided token
      const tokenHash = await hashToken(input.refreshToken);
      
      // Find session by token hash
      const session = await this.store.findByTokenHash(tokenHash);
      
      if (!session) {
        // Token not found - might be reused token
        if (this.config.enableReuseDetection) {
          // Try to find a session with this token in its history
          // For simplicity, we'll check if this is a known but rotated token
          // In production, you might store token history
          return { success: false, error: 'INVALID_TOKEN' };
        }
        return { success: false, error: 'INVALID_TOKEN' };
      }
      
      // Check if session is revoked
      if (session.isRevoked) {
        // This could be a reused token after rotation
        if (this.config.enableReuseDetection && session.revokedReason === 'token_rotation') {
          // Revoke entire token family
          await this.store.revokeTokenFamily(session.tokenFamily);
          return { success: false, error: 'TOKEN_REUSE_DETECTED' };
        }
        return { success: false, error: 'SESSION_REVOKED' };
      }
      
      // Check if session is expired
      if (session.expiresAt < new Date()) {
        return { success: false, error: 'SESSION_EXPIRED' };
      }
      
      // Generate new tokens
      const newRefreshToken = generateRefreshToken();
      const newTokenHash = await hashToken(newRefreshToken);
      const accessToken = await this.createAccessToken(session.userId);
      
      // Create new fingerprint
      const { cookie: fptCookie } = await this.fingerprinter.create();
      
      // Update session with new token (rotation)
      await this.store.update(session.id, {
        refreshTokenHash: newTokenHash,
        lastUsedAt: new Date(),
        tokenGeneration: session.tokenGeneration + 1,
        userAgent: input.userAgent ?? session.userAgent,
        ipAddress: input.ipAddress ?? session.ipAddress
      });
      
      // Create new cookies
      const refreshCookie = this.cookieHandler.createRefreshTokenCookie(
        newRefreshToken,
        this.config.tokenLifetimeDays * 24 * 60 * 60
      );
      
      return {
        success: true,
        accessToken,
        refreshToken: newRefreshToken,
        cookies: [refreshCookie, fptCookie]
      };
    } catch (error) {
      console.error('Refresh error:', error);
      return { success: false, error: 'INTERNAL_ERROR' };
    }
  }
  
  /**
   * Revoke a specific session (logout)
   */
  async logout(sessionId: string): Promise<{
    success: boolean;
    cookies: string[];
  }> {
    await this.store.revoke(sessionId, 'logout');
    
    return {
      success: true,
      cookies: this.cookieHandler.createLogoutCookies()
    };
  }
  
  /**
   * Revoke all sessions for a user (logout everywhere)
   */
  async logoutAll(userId: string, exceptSessionId?: string): Promise<{
    success: boolean;
    revokedCount: number;
    cookies: string[];
  }> {
    const count = await this.store.revokeAllForUser(userId, exceptSessionId);
    
    return {
      success: true,
      revokedCount: count,
      cookies: exceptSessionId ? [] : this.cookieHandler.createLogoutCookies()
    };
  }
  
  /**
   * Find session by refresh token
   */
  async findSession(refreshToken: string): Promise<Session | null> {
    const tokenHash = await hashToken(refreshToken);
    return this.store.findByTokenHash(tokenHash);
  }
}
```

### Token Reuse Detection

```typescript
// src/sessions/reuse-detection.ts

import { Session } from './types';
import { SessionStore } from './store';

/**
 * Token reuse detection strategies
 */
export interface ReuseDetector {
  /**
   * Check if a token has been reused after rotation
   * 
   * @param tokenHash - Hash of the provided token
   * @param store - Session store
   * @returns Detection result
   */
  detect(
    tokenHash: string, 
    store: SessionStore
  ): Promise<{
    isReuse: boolean;
    affectedFamily?: string;
    affectedUserId?: string;
  }>;
}

/**
 * Simple reuse detection based on session state
 * 
 * If a token's session is revoked due to rotation,
 * someone is using an old token = potential theft
 */
export class SimpleReuseDetector implements ReuseDetector {
  async detect(tokenHash: string, store: SessionStore) {
    // In a real implementation, you would:
    // 1. Store a history of rotated tokens
    // 2. Check if this token was previously valid but rotated
    // 3. If found, it's a reuse attempt
    
    // Simplified: check if session exists but is revoked due to rotation
    const session = await store.findByTokenHash(tokenHash);
    
    if (session?.isRevoked && session.revokedReason === 'token_rotation') {
      return {
        isReuse: true,
        affectedFamily: session.tokenFamily,
        affectedUserId: session.userId
      };
    }
    
    return { isReuse: false };
  }
}

/**
 * Advanced reuse detection with token history
 * Stores last N token hashes per session
 */
export class HistoryBasedReuseDetector implements ReuseDetector {
  private tokenHistory: Map<string, {
    hashes: string[];
    sessionId: string;
    userId: string;
    family: string;
  }> = new Map();
  
  private maxHistorySize: number;
  
  constructor(maxHistorySize: number = 5) {
    this.maxHistorySize = maxHistorySize;
  }
  
  /**
   * Record a token hash in history
   */
  recordToken(sessionId: string, tokenHash: string, userId: string, family: string): void {
    const key = sessionId;
    const existing = this.tokenHistory.get(key) ?? {
      hashes: [],
      sessionId,
      userId,
      family
    };
    
    existing.hashes.push(tokenHash);
    
    // Trim to max size
    if (existing.hashes.length > this.maxHistorySize) {
      existing.hashes = existing.hashes.slice(-this.maxHistorySize);
    }
    
    this.tokenHistory.set(key, existing);
  }
  
  /**
   * Check if token is in history (was previously valid)
   */
  async detect(tokenHash: string, store: SessionStore) {
    for (const [sessionId, history] of this.tokenHistory) {
      // Check if token is in history but not the current one
      const currentSession = await store.findById(sessionId);
      
      if (currentSession && 
          currentSession.refreshTokenHash !== tokenHash &&
          history.hashes.includes(tokenHash)) {
        return {
          isReuse: true,
          affectedFamily: history.family,
          affectedUserId: history.userId
        };
      }
    }
    
    return { isReuse: false };
  }
}
```

### Exercise 7.2

1. Create `src/sessions/refresh-service.ts` with the RefreshTokenService class
2. Implement the token rotation flow
3. Test that using an old token after rotation fails
4. Verify that token reuse triggers family revocation

---

## 3. Multi-Device Sessions

### Session Manager

```typescript
// src/sessions/manager.ts

import { Session, SessionInfo } from './types';
import { SessionStore } from './store';
import { isSessionValid } from './utils';

/**
 * High-level session management for multi-device support
 */
export class SessionManager {
  private store: SessionStore;
  
  constructor(store: SessionStore) {
    this.store = store;
  }
  
  /**
   * Get all active sessions for a user
   * Returns sanitized info suitable for display
   */
  async getActiveSessions(
    userId: string, 
    currentSessionId?: string
  ): Promise<SessionInfo[]> {
    const sessions = await this.store.findByUserId(userId);
    
    return sessions
      .filter(s => isSessionValid(s))
      .map(s => ({
        id: s.id,
        createdAt: s.createdAt,
        lastUsedAt: s.lastUsedAt,
        userAgent: this.parseUserAgent(s.userAgent),
        ipAddress: this.maskIpAddress(s.ipAddress),
        isCurrent: s.id === currentSessionId
      }))
      .sort((a, b) => b.lastUsedAt.getTime() - a.lastUsedAt.getTime());
  }
  
  /**
   * Revoke a specific session
   */
  async revokeSession(
    userId: string, 
    sessionId: string
  ): Promise<boolean> {
    const session = await this.store.findById(sessionId);
    
    // Verify ownership
    if (!session || session.userId !== userId) {
      return false;
    }
    
    return this.store.revoke(sessionId, 'logout');
  }
  
  /**
   * Revoke all sessions except current
   */
  async revokeOtherSessions(
    userId: string, 
    currentSessionId: string
  ): Promise<number> {
    return this.store.revokeAllForUser(userId, currentSessionId);
  }
  
  /**
   * Revoke all sessions (security action)
   */
  async revokeAllSessions(userId: string): Promise<number> {
    return this.store.revokeAllForUser(userId);
  }
  
  /**
   * Check if a session is valid
   */
  async isSessionActive(sessionId: string): Promise<boolean> {
    const session = await this.store.findById(sessionId);
    return session ? isSessionValid(session) : false;
  }
  
  /**
   * Get session count for a user
   */
  async getSessionCount(userId: string): Promise<{
    active: number;
    total: number;
  }> {
    const sessions = await this.store.findByUserId(userId);
    
    return {
      active: sessions.filter(s => isSessionValid(s)).length,
      total: sessions.length
    };
  }
  
  /**
   * Parse user agent into friendly device description
   */
  private parseUserAgent(userAgent?: string): string | undefined {
    if (!userAgent) return undefined;
    
    // Simple parsing - in production use a proper UA parser
    const ua = userAgent.toLowerCase();
    
    let device = 'Unknown Device';
    let browser = 'Unknown Browser';
    
    // Detect device
    if (ua.includes('iphone')) device = 'iPhone';
    else if (ua.includes('ipad')) device = 'iPad';
    else if (ua.includes('android')) device = 'Android';
    else if (ua.includes('windows')) device = 'Windows';
    else if (ua.includes('macintosh') || ua.includes('mac os')) device = 'Mac';
    else if (ua.includes('linux')) device = 'Linux';
    
    // Detect browser
    if (ua.includes('firefox')) browser = 'Firefox';
    else if (ua.includes('edg/')) browser = 'Edge';
    else if (ua.includes('chrome')) browser = 'Chrome';
    else if (ua.includes('safari')) browser = 'Safari';
    
    return `${browser} on ${device}`;
  }
  
  /**
   * Mask IP address for privacy
   * Shows only first part of IP
   */
  private maskIpAddress(ip?: string): string | undefined {
    if (!ip) return undefined;
    
    // IPv4
    if (ip.includes('.')) {
      const parts = ip.split('.');
      return `${parts[0]}.${parts[1]}.*.*`;
    }
    
    // IPv6
    if (ip.includes(':')) {
      const parts = ip.split(':');
      return `${parts[0]}:${parts[1]}:****`;
    }
    
    return ip;
  }
}
```

### Device Binding

```typescript
// src/sessions/device-binding.ts

import { getSubtle } from '../crypto/universal';
import { encode as base64urlEncode } from '../crypto/base64url';

/**
 * Device fingerprint components
 */
export interface DeviceInfo {
  userAgent: string;
  language?: string;
  timezone?: string;
  screenResolution?: string;
  colorDepth?: number;
  platform?: string;
}

/**
 * Generate a device identifier from device info
 * This creates a stable ID for the same device
 */
export async function generateDeviceId(info: DeviceInfo): Promise<string> {
  const subtle = getSubtle();
  const encoder = new TextEncoder();
  
  // Combine device properties
  const data = [
    info.userAgent,
    info.language ?? '',
    info.timezone ?? '',
    info.screenResolution ?? '',
    String(info.colorDepth ?? ''),
    info.platform ?? ''
  ].join('|');
  
  // Hash to create stable ID
  const hashBuffer = await subtle.digest('SHA-256', encoder.encode(data));
  return base64urlEncode(new Uint8Array(hashBuffer)).substring(0, 16);
}

/**
 * Validate that a request comes from the same device
 */
export async function validateDeviceBinding(
  storedDeviceId: string | undefined,
  currentInfo: DeviceInfo
): Promise<{
  valid: boolean;
  newDeviceId: string;
  deviceChanged: boolean;
}> {
  const currentDeviceId = await generateDeviceId(currentInfo);
  
  if (!storedDeviceId) {
    return {
      valid: true,
      newDeviceId: currentDeviceId,
      deviceChanged: false
    };
  }
  
  const deviceChanged = storedDeviceId !== currentDeviceId;
  
  return {
    valid: !deviceChanged,  // Strict: reject if device changed
    newDeviceId: currentDeviceId,
    deviceChanged
  };
}

/**
 * Collect device info from request headers
 * For use in server-side code
 */
export function collectDeviceInfo(headers: {
  'user-agent'?: string;
  'accept-language'?: string;
}): DeviceInfo {
  return {
    userAgent: headers['user-agent'] ?? 'Unknown',
    language: headers['accept-language']?.split(',')[0]
  };
}
```

### Session Cleanup

```typescript
// src/sessions/cleanup.ts

import { SessionStore } from './store';

/**
 * Session cleanup scheduler
 */
export class SessionCleanup {
  private store: SessionStore;
  private intervalId?: NodeJS.Timeout | number;
  private intervalMs: number;
  
  constructor(store: SessionStore, intervalHours: number = 1) {
    this.store = store;
    this.intervalMs = intervalHours * 60 * 60 * 1000;
  }
  
  /**
   * Start periodic cleanup
   */
  start(): void {
    if (this.intervalId) return;
    
    // Initial cleanup
    this.cleanup().catch(console.error);
    
    // Schedule periodic cleanup
    this.intervalId = setInterval(() => {
      this.cleanup().catch(console.error);
    }, this.intervalMs);
  }
  
  /**
   * Stop periodic cleanup
   */
  stop(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = undefined;
    }
  }
  
  /**
   * Run cleanup manually
   */
  async cleanup(): Promise<{
    deletedCount: number;
    durationMs: number;
  }> {
    const startTime = Date.now();
    const deletedCount = await this.store.deleteExpired();
    const durationMs = Date.now() - startTime;
    
    console.log(`Session cleanup: deleted ${deletedCount} expired sessions in ${durationMs}ms`);
    
    return { deletedCount, durationMs };
  }
}
```

### Session Index (Exports)

```typescript
// src/sessions/index.ts

// Types
export { Session, CreateSessionInput, SessionInfo } from './types';

// Store interface
export { SessionStore } from './store';

// Implementations
export { MemorySessionStore } from './memory-store';

// Services
export { RefreshTokenService, RefreshServiceConfig, RefreshResult } from './refresh-service';
export { SessionManager } from './manager';

// Utilities
export { 
  generateSecureId, 
  generateRefreshToken, 
  hashToken, 
  isSessionValid, 
  calculateExpiryDate 
} from './utils';

// Device binding
export { 
  DeviceInfo, 
  generateDeviceId, 
  validateDeviceBinding, 
  collectDeviceInfo 
} from './device-binding';

// Reuse detection
export { ReuseDetector, SimpleReuseDetector, HistoryBasedReuseDetector } from './reuse-detection';

// Cleanup
export { SessionCleanup } from './cleanup';
```

### Testing Sessions

```typescript
async function testSessions(): Promise<void> {
  console.log('Testing Session Management...\n');
  
  const store = new MemorySessionStore();
  const manager = new SessionManager(store);
  
  // Mock access token creator
  const createAccessToken = async (userId: string) => `access_token_for_${userId}`;
  
  const refreshService = new RefreshTokenService(store, createAccessToken, {
    tokenLifetimeDays: 30,
    maxSessionsPerUser: 3,
    enableReuseDetection: true
  });
  
  // Test 1: Create session
  console.log('Creating session...');
  const { session, accessToken, refreshToken } = await refreshService.createSession({
    userId: 'user_123',
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36',
    ipAddress: '192.168.1.100'
  });
  
  console.log('Session created:', session.id);
  console.log('Token family:', session.tokenFamily);
  console.log('Access token:', accessToken);
  console.log('Refresh token (first 20 chars):', refreshToken.substring(0, 20) + '...');
  
  // Test 2: Refresh tokens
  console.log('\nRefreshing tokens...');
  const refreshResult = await refreshService.refresh({
    refreshToken,
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36'
  });
  
  if (refreshResult.success) {
    console.log('✅ Refresh successful');
    console.log('New access token:', refreshResult.accessToken);
    console.log('New refresh token (first 20 chars):', refreshResult.refreshToken?.substring(0, 20) + '...');
  } else {
    console.log('❌ Refresh failed:', refreshResult.error);
  }
  
  // Test 3: Try to use old token (should fail)
  console.log('\nUsing old token (should fail)...');
  const reuseResult = await refreshService.refresh({ refreshToken });
  
  if (!reuseResult.success) {
    console.log('✅ Old token correctly rejected:', reuseResult.error);
  } else {
    console.log('❌ Old token should have been rejected');
  }
  
  // Test 4: Create multiple sessions
  console.log('\nCreating multiple sessions...');
  const session2 = await refreshService.createSession({
    userId: 'user_123',
    userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari/604.1',
    ipAddress: '10.0.0.50'
  });
  
  const session3 = await refreshService.createSession({
    userId: 'user_123',
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/120.0',
    ipAddress: '172.16.0.25'
  });
  
  console.log('Created session 2:', session2.session.id);
  console.log('Created session 3:', session3.session.id);
  
  // Test 5: List active sessions
  console.log('\nListing active sessions...');
  const activeSessions = await manager.getActiveSessions('user_123', session3.session.id);
  
  for (const s of activeSessions) {
    console.log(`  - ${s.id.substring(0, 8)}... | ${s.userAgent} | ${s.ipAddress} | ${s.isCurrent ? '(current)' : ''}`);
  }
  
  // Test 6: Revoke other sessions
  console.log('\nRevoking other sessions...');
  const revokeCount = await manager.revokeOtherSessions('user_123', session3.session.id);
  console.log('Revoked sessions:', revokeCount);
  
  // Test 7: Verify only current session remains
  const remainingSessions = await manager.getActiveSessions('user_123', session3.session.id);
  console.log('Remaining sessions:', remainingSessions.length);
  console.log('All revoked except current:', remainingSessions.length === 1 && remainingSessions[0].isCurrent);
  
  // Test 8: Session count
  const count = await manager.getSessionCount('user_123');
  console.log('\nSession count:', count);
}

testSessions().catch(console.error);
```

### Exercise 7.3

1. Create `src/sessions/manager.ts` with the SessionManager class
2. Implement `src/sessions/device-binding.ts` for device fingerprinting
3. Create `src/sessions/cleanup.ts` for periodic cleanup
4. Test creating multiple sessions and revoking them selectively

---

## Summary

In this part, you learned:

1. **Session Store Design** — Abstract storage interface with in-memory implementation
2. **Refresh Token Flow** — Token rotation with reuse detection for theft prevention
3. **Multi-Device Sessions** — Managing sessions across devices with user visibility

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
│   └── ...              # (from Part 6)
├── cookies/
│   └── ...              # (from Part 6)
└── sessions/
    ├── types.ts         # Session data models
    ├── store.ts         # Storage interface
    ├── memory-store.ts  # In-memory implementation
    ├── utils.ts         # Helper functions
    ├── refresh-service.ts  # Refresh token lifecycle
    ├── reuse-detection.ts  # Token reuse detection
    ├── manager.ts       # Multi-device management
    ├── device-binding.ts   # Device fingerprinting
    ├── cleanup.ts       # Session cleanup
    └── index.ts         # Public exports
```

### Key Takeaways

- Never store raw refresh tokens — always hash them
- Token rotation invalidates previous tokens on each use
- Token reuse detection catches theft scenarios
- Store abstraction enables different backends
- Periodic cleanup prevents unbounded storage growth
- Device binding adds another layer of security

### Security Checklist

Before moving on, ensure:
- [ ] Refresh tokens are hashed before storage
- [ ] Token rotation works correctly
- [ ] Old tokens are rejected after rotation
- [ ] Token reuse triggers family revocation
- [ ] Sessions can be listed and revoked individually
- [ ] "Logout everywhere" revokes all sessions
- [ ] Expired sessions are cleaned up

### Next Steps

In **Part 8: Putting It Together**, we'll integrate all components into a complete `AuthService`:
- Registration and login flows
- Token refresh with all security features
- Logout and session management
- Complete API surface
