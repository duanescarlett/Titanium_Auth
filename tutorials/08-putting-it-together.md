# Part 8: Putting It Together

Now it's time to integrate all the components we've built into a cohesive authentication service. We'll create an `AuthService` that orchestrates password hashing, JWT creation, fingerprinting, sessions, and token refresh into clean, easy-to-use APIs.

---

## Table of Contents

1. [AuthService Architecture](#1-authservice-architecture)
2. [Registration and Login Flows](#2-registration-and-login-flows)
3. [Token Refresh and Logout](#3-token-refresh-and-logout)

---

## 1. AuthService Architecture

### Design Goals

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AuthService Design Goals                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   1. Single Entry Point                                                      │
│      All auth operations go through AuthService                              │
│      Framework code only interacts with this class                           │
│                                                                              │
│   2. Dependency Injection                                                    │
│      Pluggable user store, session store, key provider                       │
│      Easy to test with mocks                                                 │
│                                                                              │
│   3. Clear Boundaries                                                        │
│      AuthService handles auth logic                                          │
│      Framework handles HTTP (headers, cookies, responses)                    │
│                                                                              │
│   4. Complete Responses                                                      │
│      Returns everything needed: tokens, cookies, errors                      │
│      Framework just forwards to client                                       │
│                                                                              │
│   5. Async Everything                                                        │
│      All crypto operations are async (Web Crypto API)                        │
│      Consistent Promise-based interface                                      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Dependencies and Interfaces

```typescript
// src/auth/interfaces.ts

/**
 * User data required for authentication
 * Implement this to connect your user database
 */
export interface AuthUser {
  id: string;
  email: string;
  passwordHash: string;  // PHC format from password module
  emailVerified?: boolean;
  disabled?: boolean;
  metadata?: Record<string, unknown>;
}

/**
 * User store interface
 * Implement this for your database (PostgreSQL, MongoDB, etc.)
 */
export interface UserStore {
  /**
   * Find user by email (for login)
   */
  findByEmail(email: string): Promise<AuthUser | null>;
  
  /**
   * Find user by ID (for token refresh)
   */
  findById(id: string): Promise<AuthUser | null>;
  
  /**
   * Create a new user (for registration)
   */
  create(data: {
    email: string;
    passwordHash: string;
  }): Promise<AuthUser>;
  
  /**
   * Update user (for password change)
   */
  update(id: string, data: Partial<AuthUser>): Promise<AuthUser | null>;
  
  /**
   * Check if email exists (for registration validation)
   */
  emailExists(email: string): Promise<boolean>;
}

/**
 * Key provider interface
 * Implement this for your key storage strategy
 */
export interface KeyProvider {
  /**
   * Get the current signing key
   */
  getSigningKey(): Promise<{
    privateKey: CryptoKey;
    keyId: string;
  }>;
  
  /**
   * Get a public key by ID (for verification)
   */
  getPublicKey(keyId: string): Promise<CryptoKey | null>;
  
  /**
   * Get all public keys (for JWKS endpoint)
   */
  getAllPublicKeys(): Promise<Array<{
    keyId: string;
    publicKey: CryptoKey;
  }>>;
}

/**
 * Request context passed to auth operations
 */
export interface RequestContext {
  userAgent?: string;
  ipAddress?: string;
  cookieHeader?: string;
  deviceId?: string;
}

/**
 * Standard auth response structure
 */
export interface AuthResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
  };
  cookies?: string[];
}
```

### Configuration

```typescript
// src/auth/config.ts

/**
 * AuthService configuration
 */
export interface AuthConfig {
  /**
   * Access token lifetime in seconds
   * @default 900 (15 minutes)
   */
  accessTokenLifetime: number;
  
  /**
   * Refresh token lifetime in days
   * @default 30
   */
  refreshTokenLifetimeDays: number;
  
  /**
   * Maximum active sessions per user
   * @default 5
   */
  maxSessionsPerUser: number;
  
  /**
   * Issuer claim for JWTs
   * @default 'auth-service'
   */
  issuer: string;
  
  /**
   * Audience claim for JWTs
   * @default undefined
   */
  audience?: string;
  
  /**
   * Enable token fingerprinting
   * @default true
   */
  enableFingerprinting: boolean;
  
  /**
   * Enable refresh token rotation
   * @default true
   */
  enableTokenRotation: boolean;
  
  /**
   * Enable token reuse detection
   * @default true
   */
  enableReuseDetection: boolean;
  
  /**
   * Cookie domain (undefined = current domain)
   */
  cookieDomain?: string;
  
  /**
   * Cookie path
   * @default '/'
   */
  cookiePath: string;
  
  /**
   * Require email verification for login
   * @default false
   */
  requireEmailVerification: boolean;
}

/**
 * Default configuration values
 */
export const DEFAULT_CONFIG: AuthConfig = {
  accessTokenLifetime: 900,           // 15 minutes
  refreshTokenLifetimeDays: 30,
  maxSessionsPerUser: 5,
  issuer: 'auth-service',
  enableFingerprinting: true,
  enableTokenRotation: true,
  enableReuseDetection: true,
  cookiePath: '/',
  requireEmailVerification: false
};

/**
 * Create config with defaults
 */
export function createConfig(overrides: Partial<AuthConfig> = {}): AuthConfig {
  return { ...DEFAULT_CONFIG, ...overrides };
}
```

### Error Codes

```typescript
// src/auth/errors.ts

/**
 * Authentication error codes
 */
export const AuthErrorCodes = {
  // Registration errors
  EMAIL_ALREADY_EXISTS: 'EMAIL_ALREADY_EXISTS',
  INVALID_EMAIL_FORMAT: 'INVALID_EMAIL_FORMAT',
  PASSWORD_TOO_WEAK: 'PASSWORD_TOO_WEAK',
  
  // Login errors
  INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',
  ACCOUNT_DISABLED: 'ACCOUNT_DISABLED',
  EMAIL_NOT_VERIFIED: 'EMAIL_NOT_VERIFIED',
  
  // Token errors
  TOKEN_MISSING: 'TOKEN_MISSING',
  TOKEN_INVALID: 'TOKEN_INVALID',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  TOKEN_REVOKED: 'TOKEN_REVOKED',
  FINGERPRINT_MISMATCH: 'FINGERPRINT_MISMATCH',
  TOKEN_REUSE_DETECTED: 'TOKEN_REUSE_DETECTED',
  
  // Session errors
  SESSION_NOT_FOUND: 'SESSION_NOT_FOUND',
  SESSION_EXPIRED: 'SESSION_EXPIRED',
  
  // General errors
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  VALIDATION_ERROR: 'VALIDATION_ERROR'
} as const;

export type AuthErrorCode = typeof AuthErrorCodes[keyof typeof AuthErrorCodes];

/**
 * Human-readable error messages
 */
export const AuthErrorMessages: Record<AuthErrorCode, string> = {
  EMAIL_ALREADY_EXISTS: 'An account with this email already exists',
  INVALID_EMAIL_FORMAT: 'Please provide a valid email address',
  PASSWORD_TOO_WEAK: 'Password does not meet security requirements',
  INVALID_CREDENTIALS: 'Invalid email or password',
  ACCOUNT_DISABLED: 'This account has been disabled',
  EMAIL_NOT_VERIFIED: 'Please verify your email address',
  TOKEN_MISSING: 'Authentication token is required',
  TOKEN_INVALID: 'Authentication token is invalid',
  TOKEN_EXPIRED: 'Authentication token has expired',
  TOKEN_REVOKED: 'Authentication token has been revoked',
  FINGERPRINT_MISMATCH: 'Security validation failed',
  TOKEN_REUSE_DETECTED: 'Security violation detected. Please log in again',
  SESSION_NOT_FOUND: 'Session not found',
  SESSION_EXPIRED: 'Session has expired',
  INTERNAL_ERROR: 'An internal error occurred',
  VALIDATION_ERROR: 'Validation failed'
};

/**
 * Create an auth error response
 */
export function createError(code: AuthErrorCode): {
  code: string;
  message: string;
} {
  return {
    code,
    message: AuthErrorMessages[code]
  };
}
```

### Exercise 8.1

1. Create `src/auth/interfaces.ts` with the required interfaces
2. Create `src/auth/config.ts` with configuration options
3. Create `src/auth/errors.ts` with error codes and messages
4. Consider what additional configuration your use case might need

---

## 2. Registration and Login Flows

### Input Validation

```typescript
// src/auth/validation.ts

/**
 * Email validation regex (simplified but effective)
 */
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Validate email format
 */
export function isValidEmail(email: string): boolean {
  if (!email || typeof email !== 'string') return false;
  if (email.length > 254) return false;  // RFC 5321
  return EMAIL_REGEX.test(email.toLowerCase().trim());
}

/**
 * Password strength requirements
 */
export interface PasswordRequirements {
  minLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumbers: boolean;
  requireSymbols: boolean;
}

const DEFAULT_PASSWORD_REQUIREMENTS: PasswordRequirements = {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSymbols: false
};

/**
 * Validate password strength
 */
export function validatePassword(
  password: string,
  requirements: Partial<PasswordRequirements> = {}
): {
  valid: boolean;
  errors: string[];
} {
  const reqs = { ...DEFAULT_PASSWORD_REQUIREMENTS, ...requirements };
  const errors: string[] = [];
  
  if (!password || typeof password !== 'string') {
    return { valid: false, errors: ['Password is required'] };
  }
  
  if (password.length < reqs.minLength) {
    errors.push(`Password must be at least ${reqs.minLength} characters`);
  }
  
  if (reqs.requireUppercase && !/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  
  if (reqs.requireLowercase && !/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  
  if (reqs.requireNumbers && !/\d/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  
  if (reqs.requireSymbols && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push('Password must contain at least one symbol');
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Normalize email for comparison
 */
export function normalizeEmail(email: string): string {
  return email.toLowerCase().trim();
}
```

### AuthService Implementation

```typescript
// src/auth/service.ts

import { AuthUser, UserStore, KeyProvider, RequestContext, AuthResponse } from './interfaces';
import { AuthConfig, createConfig } from './config';
import { AuthErrorCodes, createError } from './errors';
import { isValidEmail, validatePassword, normalizeEmail } from './validation';

import { hashPassword, verifyPassword } from '../password';
import { createRS256Token, verifyRS256Token } from '../jwt';
import { TokenFingerprinter } from '../fingerprint';
import { CookieHandler } from '../cookies';
import { SessionStore, Session, RefreshTokenService, SessionManager } from '../sessions';
import { generateRefreshToken, hashToken } from '../sessions/utils';

/**
 * Registration result
 */
export interface RegisterResult {
  user: {
    id: string;
    email: string;
  };
  accessToken: string;
  refreshToken?: string;  // Only if cookies not used
}

/**
 * Login result
 */
export interface LoginResult {
  user: {
    id: string;
    email: string;
  };
  accessToken: string;
  refreshToken?: string;
  sessionId: string;
}

/**
 * Token verification result
 */
export interface VerifyResult {
  userId: string;
  sessionId?: string;
  claims: Record<string, unknown>;
}

/**
 * Refresh result
 */
export interface RefreshResult {
  accessToken: string;
  refreshToken?: string;
}

/**
 * Main authentication service
 * Orchestrates all auth operations
 */
export class AuthService {
  private config: AuthConfig;
  private userStore: UserStore;
  private sessionStore: SessionStore;
  private keyProvider: KeyProvider;
  private fingerprinter: TokenFingerprinter;
  private cookieHandler: CookieHandler;
  private sessionManager: SessionManager;
  
  constructor(
    userStore: UserStore,
    sessionStore: SessionStore,
    keyProvider: KeyProvider,
    config: Partial<AuthConfig> = {}
  ) {
    this.config = createConfig(config);
    this.userStore = userStore;
    this.sessionStore = sessionStore;
    this.keyProvider = keyProvider;
    this.fingerprinter = new TokenFingerprinter({
      cookieDomain: this.config.cookieDomain,
      cookiePath: this.config.cookiePath
    });
    this.cookieHandler = new CookieHandler({
      domain: this.config.cookieDomain,
      path: this.config.cookiePath
    });
    this.sessionManager = new SessionManager(sessionStore);
  }
  
  // ─────────────────────────────────────────────────────────────────────────
  // Registration
  // ─────────────────────────────────────────────────────────────────────────
  
  /**
   * Register a new user
   */
  async register(
    email: string,
    password: string,
    context: RequestContext = {}
  ): Promise<AuthResponse<RegisterResult>> {
    try {
      // Validate email
      const normalizedEmail = normalizeEmail(email);
      if (!isValidEmail(normalizedEmail)) {
        return {
          success: false,
          error: createError(AuthErrorCodes.INVALID_EMAIL_FORMAT)
        };
      }
      
      // Validate password
      const passwordValidation = validatePassword(password);
      if (!passwordValidation.valid) {
        return {
          success: false,
          error: {
            code: AuthErrorCodes.PASSWORD_TOO_WEAK,
            message: passwordValidation.errors.join('. ')
          }
        };
      }
      
      // Check if email exists
      const exists = await this.userStore.emailExists(normalizedEmail);
      if (exists) {
        return {
          success: false,
          error: createError(AuthErrorCodes.EMAIL_ALREADY_EXISTS)
        };
      }
      
      // Hash password
      const passwordHash = await hashPassword(password);
      
      // Create user
      const user = await this.userStore.create({
        email: normalizedEmail,
        passwordHash
      });
      
      // Create session and tokens
      const { accessToken, cookies, session, refreshToken } = await this.createAuthSession(
        user,
        context
      );
      
      return {
        success: true,
        data: {
          user: {
            id: user.id,
            email: user.email
          },
          accessToken,
          refreshToken
        },
        cookies
      };
    } catch (error) {
      console.error('Registration error:', error);
      return {
        success: false,
        error: createError(AuthErrorCodes.INTERNAL_ERROR)
      };
    }
  }
  
  // ─────────────────────────────────────────────────────────────────────────
  // Login
  // ─────────────────────────────────────────────────────────────────────────
  
  /**
   * Login with email and password
   */
  async login(
    email: string,
    password: string,
    context: RequestContext = {}
  ): Promise<AuthResponse<LoginResult>> {
    try {
      const normalizedEmail = normalizeEmail(email);
      
      // Find user
      const user = await this.userStore.findByEmail(normalizedEmail);
      
      if (!user) {
        // Use same error for missing user (prevent enumeration)
        return {
          success: false,
          error: createError(AuthErrorCodes.INVALID_CREDENTIALS)
        };
      }
      
      // Check if disabled
      if (user.disabled) {
        return {
          success: false,
          error: createError(AuthErrorCodes.ACCOUNT_DISABLED)
        };
      }
      
      // Check email verification if required
      if (this.config.requireEmailVerification && !user.emailVerified) {
        return {
          success: false,
          error: createError(AuthErrorCodes.EMAIL_NOT_VERIFIED)
        };
      }
      
      // Verify password
      const passwordValid = await verifyPassword(password, user.passwordHash);
      
      if (!passwordValid) {
        return {
          success: false,
          error: createError(AuthErrorCodes.INVALID_CREDENTIALS)
        };
      }
      
      // Create session and tokens
      const { accessToken, cookies, session, refreshToken } = await this.createAuthSession(
        user,
        context
      );
      
      return {
        success: true,
        data: {
          user: {
            id: user.id,
            email: user.email
          },
          accessToken,
          refreshToken,
          sessionId: session.id
        },
        cookies
      };
    } catch (error) {
      console.error('Login error:', error);
      return {
        success: false,
        error: createError(AuthErrorCodes.INTERNAL_ERROR)
      };
    }
  }
  
  // ─────────────────────────────────────────────────────────────────────────
  // Session Creation (shared by register and login)
  // ─────────────────────────────────────────────────────────────────────────
  
  /**
   * Create a new authenticated session
   */
  private async createAuthSession(
    user: AuthUser,
    context: RequestContext
  ): Promise<{
    accessToken: string;
    refreshToken: string;
    session: Session;
    cookies: string[];
  }> {
    const cookies: string[] = [];
    
    // Check session limit
    if (this.config.maxSessionsPerUser > 0) {
      const activeCount = await this.sessionStore.countActiveForUser(user.id);
      
      if (activeCount >= this.config.maxSessionsPerUser) {
        // Revoke oldest session
        const sessions = await this.sessionStore.findByUserId(user.id);
        const activeSessions = sessions
          .filter(s => !s.isRevoked && s.expiresAt > new Date())
          .sort((a, b) => a.lastUsedAt.getTime() - b.lastUsedAt.getTime());
        
        if (activeSessions.length > 0) {
          await this.sessionStore.revoke(activeSessions[0].id, 'security');
        }
      }
    }
    
    // Generate refresh token
    const refreshToken = generateRefreshToken();
    
    // Create fingerprint
    let fingerprintClaim: Record<string, string> = {};
    if (this.config.enableFingerprinting) {
      const { claim, cookie } = await this.fingerprinter.create();
      fingerprintClaim = claim;
      cookies.push(cookie);
    }
    
    // Create access token
    const { privateKey, keyId } = await this.keyProvider.getSigningKey();
    
    const accessToken = await createRS256Token(
      {
        sub: user.id,
        email: user.email,
        ...fingerprintClaim
      },
      privateKey,
      keyId,
      {
        expiresIn: this.config.accessTokenLifetime,
        issuer: this.config.issuer,
        audience: this.config.audience
      }
    );
    
    // Calculate refresh token expiry
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + this.config.refreshTokenLifetimeDays);
    
    // Create session
    const session = await this.sessionStore.create({
      userId: user.id,
      refreshToken,
      expiresAt,
      userAgent: context.userAgent,
      ipAddress: context.ipAddress,
      deviceId: context.deviceId
    });
    
    // Create refresh token cookie
    const refreshCookie = this.cookieHandler.createRefreshTokenCookie(
      refreshToken,
      this.config.refreshTokenLifetimeDays * 24 * 60 * 60
    );
    cookies.push(refreshCookie);
    
    return {
      accessToken,
      refreshToken,
      session,
      cookies
    };
  }
  
  // ─────────────────────────────────────────────────────────────────────────
  // Token Verification
  // ─────────────────────────────────────────────────────────────────────────
  
  /**
   * Verify an access token
   */
  async verifyAccessToken(
    token: string,
    context: RequestContext = {}
  ): Promise<AuthResponse<VerifyResult>> {
    try {
      if (!token) {
        return {
          success: false,
          error: createError(AuthErrorCodes.TOKEN_MISSING)
        };
      }
      
      // Verify JWT signature and claims
      const result = await verifyRS256Token(token, async (kid) => {
        return this.keyProvider.getPublicKey(kid);
      });
      
      if (!result.valid) {
        const errorCode = result.error === 'TOKEN_EXPIRED' 
          ? AuthErrorCodes.TOKEN_EXPIRED 
          : AuthErrorCodes.TOKEN_INVALID;
        return {
          success: false,
          error: createError(errorCode)
        };
      }
      
      const payload = result.payload!;
      
      // Verify fingerprint if enabled
      if (this.config.enableFingerprinting) {
        const fpResult = await this.fingerprinter.validate(
          context.cookieHeader,
          payload
        );
        
        if (!fpResult.valid) {
          return {
            success: false,
            error: createError(AuthErrorCodes.FINGERPRINT_MISMATCH)
          };
        }
      }
      
      // Verify user still exists and is active
      const user = await this.userStore.findById(payload.sub as string);
      
      if (!user || user.disabled) {
        return {
          success: false,
          error: createError(AuthErrorCodes.TOKEN_REVOKED)
        };
      }
      
      return {
        success: true,
        data: {
          userId: payload.sub as string,
          claims: payload
        }
      };
    } catch (error) {
      console.error('Token verification error:', error);
      return {
        success: false,
        error: createError(AuthErrorCodes.TOKEN_INVALID)
      };
    }
  }
  
  /**
   * Extract token from Authorization header
   */
  extractBearerToken(authHeader: string | undefined): string | null {
    if (!authHeader?.startsWith('Bearer ')) {
      return null;
    }
    return authHeader.slice(7);
  }
}
```

### Testing Registration and Login

```typescript
async function testRegistrationAndLogin(): Promise<void> {
  console.log('Testing Registration and Login...\n');
  
  // Create mock stores
  const userStore = new MockUserStore();
  const sessionStore = new MemorySessionStore();
  const keyProvider = await createMockKeyProvider();
  
  const auth = new AuthService(userStore, sessionStore, keyProvider, {
    accessTokenLifetime: 900,
    refreshTokenLifetimeDays: 30,
    maxSessionsPerUser: 3
  });
  
  // Test Registration
  console.log('1. Registering user...');
  const registerResult = await auth.register(
    'user@example.com',
    'SecurePassword123!',
    { userAgent: 'Test Client', ipAddress: '127.0.0.1' }
  );
  
  if (registerResult.success) {
    console.log('✅ Registration successful');
    console.log('   User ID:', registerResult.data!.user.id);
    console.log('   Access Token (first 50):', registerResult.data!.accessToken.substring(0, 50) + '...');
    console.log('   Cookies:', registerResult.cookies?.length);
  } else {
    console.log('❌ Registration failed:', registerResult.error);
  }
  
  // Test Duplicate Registration
  console.log('\n2. Attempting duplicate registration...');
  const dupResult = await auth.register('user@example.com', 'AnotherPassword123!');
  
  if (!dupResult.success && dupResult.error?.code === 'EMAIL_ALREADY_EXISTS') {
    console.log('✅ Duplicate correctly rejected');
  } else {
    console.log('❌ Should have rejected duplicate');
  }
  
  // Test Login
  console.log('\n3. Logging in...');
  const loginResult = await auth.login(
    'user@example.com',
    'SecurePassword123!',
    { userAgent: 'Test Client', ipAddress: '127.0.0.1' }
  );
  
  if (loginResult.success) {
    console.log('✅ Login successful');
    console.log('   Session ID:', loginResult.data!.sessionId);
  } else {
    console.log('❌ Login failed:', loginResult.error);
  }
  
  // Test Wrong Password
  console.log('\n4. Login with wrong password...');
  const wrongPwResult = await auth.login('user@example.com', 'WrongPassword');
  
  if (!wrongPwResult.success && wrongPwResult.error?.code === 'INVALID_CREDENTIALS') {
    console.log('✅ Wrong password correctly rejected');
  } else {
    console.log('❌ Should have rejected wrong password');
  }
  
  // Test Token Verification
  console.log('\n5. Verifying access token...');
  if (loginResult.success) {
    // Extract fingerprint cookie from login cookies
    const fptCookie = loginResult.cookies?.find(c => c.includes('__Secure-Fpt'));
    const cookieValue = fptCookie?.split(';')[0];
    
    const verifyResult = await auth.verifyAccessToken(
      loginResult.data!.accessToken,
      { cookieHeader: cookieValue }
    );
    
    if (verifyResult.success) {
      console.log('✅ Token verification successful');
      console.log('   User ID:', verifyResult.data!.userId);
    } else {
      console.log('❌ Token verification failed:', verifyResult.error);
    }
  }
}

// Mock implementations for testing
class MockUserStore implements UserStore {
  private users: Map<string, AuthUser> = new Map();
  private emailIndex: Map<string, string> = new Map();
  
  async findByEmail(email: string): Promise<AuthUser | null> {
    const id = this.emailIndex.get(email);
    return id ? this.users.get(id) ?? null : null;
  }
  
  async findById(id: string): Promise<AuthUser | null> {
    return this.users.get(id) ?? null;
  }
  
  async create(data: { email: string; passwordHash: string }): Promise<AuthUser> {
    const id = `user_${Date.now()}`;
    const user: AuthUser = {
      id,
      email: data.email,
      passwordHash: data.passwordHash,
      emailVerified: false,
      disabled: false
    };
    this.users.set(id, user);
    this.emailIndex.set(data.email, id);
    return user;
  }
  
  async update(id: string, data: Partial<AuthUser>): Promise<AuthUser | null> {
    const user = this.users.get(id);
    if (!user) return null;
    const updated = { ...user, ...data };
    this.users.set(id, updated);
    return updated;
  }
  
  async emailExists(email: string): Promise<boolean> {
    return this.emailIndex.has(email);
  }
}

async function createMockKeyProvider(): Promise<KeyProvider> {
  const { generateRS256KeyPair, exportPublicKeyJWK } = await import('../jwt/keys');
  const { privateKey, publicKey } = await generateRS256KeyPair();
  const keyId = 'test-key-1';
  
  return {
    async getSigningKey() {
      return { privateKey, keyId };
    },
    async getPublicKey(kid: string) {
      return kid === keyId ? publicKey : null;
    },
    async getAllPublicKeys() {
      return [{ keyId, publicKey }];
    }
  };
}

testRegistrationAndLogin().catch(console.error);
```

### Exercise 8.2

1. Create `src/auth/validation.ts` with email and password validation
2. Create `src/auth/service.ts` with register and login methods
3. Test registration with various invalid inputs
4. Test login with correct and incorrect credentials
5. Verify that duplicate emails are rejected

---

## 3. Token Refresh and Logout

### Adding Refresh and Logout to AuthService

```typescript
// Add to src/auth/service.ts

export class AuthService {
  // ... previous code ...
  
  // ─────────────────────────────────────────────────────────────────────────
  // Token Refresh
  // ─────────────────────────────────────────────────────────────────────────
  
  /**
   * Refresh tokens using a refresh token
   */
  async refresh(
    refreshToken: string,
    context: RequestContext = {}
  ): Promise<AuthResponse<RefreshResult>> {
    try {
      if (!refreshToken) {
        return {
          success: false,
          error: createError(AuthErrorCodes.TOKEN_MISSING)
        };
      }
      
      // Hash the provided token
      const tokenHash = await hashToken(refreshToken);
      
      // Find session
      const session = await this.sessionStore.findByTokenHash(tokenHash);
      
      if (!session) {
        // Check for token reuse
        if (this.config.enableReuseDetection) {
          // In production, check if this token was previously valid
          // For now, just return invalid
        }
        return {
          success: false,
          error: createError(AuthErrorCodes.TOKEN_INVALID)
        };
      }
      
      // Check if session is revoked
      if (session.isRevoked) {
        // Token reuse detection
        if (this.config.enableReuseDetection && session.revokedReason === 'token_rotation') {
          // Revoke entire family
          await this.sessionStore.revokeTokenFamily(session.tokenFamily);
          return {
            success: false,
            error: createError(AuthErrorCodes.TOKEN_REUSE_DETECTED)
          };
        }
        return {
          success: false,
          error: createError(AuthErrorCodes.TOKEN_REVOKED)
        };
      }
      
      // Check if session is expired
      if (session.expiresAt < new Date()) {
        return {
          success: false,
          error: createError(AuthErrorCodes.SESSION_EXPIRED)
        };
      }
      
      // Get user
      const user = await this.userStore.findById(session.userId);
      
      if (!user || user.disabled) {
        await this.sessionStore.revoke(session.id, 'security');
        return {
          success: false,
          error: createError(AuthErrorCodes.ACCOUNT_DISABLED)
        };
      }
      
      // Generate new tokens
      const newRefreshToken = generateRefreshToken();
      const newTokenHash = await hashToken(newRefreshToken);
      
      // Create fingerprint
      const cookies: string[] = [];
      let fingerprintClaim: Record<string, string> = {};
      
      if (this.config.enableFingerprinting) {
        const { claim, cookie } = await this.fingerprinter.create();
        fingerprintClaim = claim;
        cookies.push(cookie);
      }
      
      // Create new access token
      const { privateKey, keyId } = await this.keyProvider.getSigningKey();
      
      const accessToken = await createRS256Token(
        {
          sub: user.id,
          email: user.email,
          ...fingerprintClaim
        },
        privateKey,
        keyId,
        {
          expiresIn: this.config.accessTokenLifetime,
          issuer: this.config.issuer,
          audience: this.config.audience
        }
      );
      
      // Update session with token rotation
      if (this.config.enableTokenRotation) {
        // Mark old session as rotated (for reuse detection)
        await this.sessionStore.update(session.id, {
          refreshTokenHash: newTokenHash,
          lastUsedAt: new Date(),
          tokenGeneration: session.tokenGeneration + 1,
          userAgent: context.userAgent ?? session.userAgent,
          ipAddress: context.ipAddress ?? session.ipAddress
        });
      }
      
      // Create new refresh token cookie
      const refreshCookie = this.cookieHandler.createRefreshTokenCookie(
        newRefreshToken,
        this.config.refreshTokenLifetimeDays * 24 * 60 * 60
      );
      cookies.push(refreshCookie);
      
      return {
        success: true,
        data: {
          accessToken,
          refreshToken: newRefreshToken
        },
        cookies
      };
    } catch (error) {
      console.error('Refresh error:', error);
      return {
        success: false,
        error: createError(AuthErrorCodes.INTERNAL_ERROR)
      };
    }
  }
  
  /**
   * Extract refresh token from cookie header
   */
  extractRefreshToken(cookieHeader: string | undefined): string | null {
    if (!cookieHeader) return null;
    return this.cookieHandler.getRefreshToken(cookieHeader) ?? null;
  }
  
  // ─────────────────────────────────────────────────────────────────────────
  // Logout
  // ─────────────────────────────────────────────────────────────────────────
  
  /**
   * Logout current session
   */
  async logout(
    refreshToken: string
  ): Promise<AuthResponse<{ success: boolean }>> {
    try {
      if (!refreshToken) {
        return {
          success: true,
          data: { success: true },
          cookies: this.cookieHandler.createLogoutCookies()
        };
      }
      
      const tokenHash = await hashToken(refreshToken);
      const session = await this.sessionStore.findByTokenHash(tokenHash);
      
      if (session) {
        await this.sessionStore.revoke(session.id, 'logout');
      }
      
      return {
        success: true,
        data: { success: true },
        cookies: this.cookieHandler.createLogoutCookies()
      };
    } catch (error) {
      console.error('Logout error:', error);
      // Still return success with logout cookies
      return {
        success: true,
        data: { success: true },
        cookies: this.cookieHandler.createLogoutCookies()
      };
    }
  }
  
  /**
   * Logout all sessions for a user
   */
  async logoutAll(
    userId: string,
    exceptSessionId?: string
  ): Promise<AuthResponse<{ revokedCount: number }>> {
    try {
      const count = await this.sessionStore.revokeAllForUser(userId, exceptSessionId);
      
      return {
        success: true,
        data: { revokedCount: count },
        cookies: exceptSessionId ? undefined : this.cookieHandler.createLogoutCookies()
      };
    } catch (error) {
      console.error('Logout all error:', error);
      return {
        success: false,
        error: createError(AuthErrorCodes.INTERNAL_ERROR)
      };
    }
  }
  
  // ─────────────────────────────────────────────────────────────────────────
  // Session Management
  // ─────────────────────────────────────────────────────────────────────────
  
  /**
   * Get all active sessions for a user
   */
  async getSessions(
    userId: string,
    currentSessionId?: string
  ): Promise<AuthResponse<SessionInfo[]>> {
    try {
      const sessions = await this.sessionManager.getActiveSessions(
        userId,
        currentSessionId
      );
      
      return {
        success: true,
        data: sessions
      };
    } catch (error) {
      console.error('Get sessions error:', error);
      return {
        success: false,
        error: createError(AuthErrorCodes.INTERNAL_ERROR)
      };
    }
  }
  
  /**
   * Revoke a specific session
   */
  async revokeSession(
    userId: string,
    sessionId: string
  ): Promise<AuthResponse<{ success: boolean }>> {
    try {
      const success = await this.sessionManager.revokeSession(userId, sessionId);
      
      if (!success) {
        return {
          success: false,
          error: createError(AuthErrorCodes.SESSION_NOT_FOUND)
        };
      }
      
      return {
        success: true,
        data: { success: true }
      };
    } catch (error) {
      console.error('Revoke session error:', error);
      return {
        success: false,
        error: createError(AuthErrorCodes.INTERNAL_ERROR)
      };
    }
  }
  
  // ─────────────────────────────────────────────────────────────────────────
  // Password Management
  // ─────────────────────────────────────────────────────────────────────────
  
  /**
   * Change password (requires current password)
   */
  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
    revokeOtherSessions: boolean = true
  ): Promise<AuthResponse<{ success: boolean }>> {
    try {
      // Get user
      const user = await this.userStore.findById(userId);
      
      if (!user) {
        return {
          success: false,
          error: createError(AuthErrorCodes.TOKEN_INVALID)
        };
      }
      
      // Verify current password
      const valid = await verifyPassword(currentPassword, user.passwordHash);
      
      if (!valid) {
        return {
          success: false,
          error: createError(AuthErrorCodes.INVALID_CREDENTIALS)
        };
      }
      
      // Validate new password
      const validation = validatePassword(newPassword);
      if (!validation.valid) {
        return {
          success: false,
          error: {
            code: AuthErrorCodes.PASSWORD_TOO_WEAK,
            message: validation.errors.join('. ')
          }
        };
      }
      
      // Hash new password
      const newHash = await hashPassword(newPassword);
      
      // Update user
      await this.userStore.update(userId, { passwordHash: newHash });
      
      // Optionally revoke other sessions
      if (revokeOtherSessions) {
        await this.sessionStore.revokeAllForUser(userId);
      }
      
      return {
        success: true,
        data: { success: true }
      };
    } catch (error) {
      console.error('Change password error:', error);
      return {
        success: false,
        error: createError(AuthErrorCodes.INTERNAL_ERROR)
      };
    }
  }
}
```

### AuthService Index

```typescript
// src/auth/index.ts

// Interfaces
export { 
  AuthUser, 
  UserStore, 
  KeyProvider, 
  RequestContext, 
  AuthResponse 
} from './interfaces';

// Configuration
export { AuthConfig, DEFAULT_CONFIG, createConfig } from './config';

// Errors
export { AuthErrorCodes, AuthErrorMessages, createError, AuthErrorCode } from './errors';

// Validation
export { 
  isValidEmail, 
  validatePassword, 
  normalizeEmail, 
  PasswordRequirements 
} from './validation';

// Service
export { 
  AuthService, 
  RegisterResult, 
  LoginResult, 
  VerifyResult, 
  RefreshResult 
} from './service';
```

### Complete Test Suite

```typescript
async function testCompleteAuthFlow(): Promise<void> {
  console.log('='.repeat(60));
  console.log('Complete Authentication Flow Test');
  console.log('='.repeat(60));
  
  // Setup
  const userStore = new MockUserStore();
  const sessionStore = new MemorySessionStore();
  const keyProvider = await createMockKeyProvider();
  
  const auth = new AuthService(userStore, sessionStore, keyProvider, {
    accessTokenLifetime: 900,
    refreshTokenLifetimeDays: 30,
    maxSessionsPerUser: 3,
    enableFingerprinting: true,
    enableTokenRotation: true
  });
  
  let accessToken: string;
  let refreshToken: string;
  let sessionId: string;
  let cookies: string[];
  let userId: string;
  
  // 1. Registration
  console.log('\n1. REGISTRATION');
  console.log('-'.repeat(40));
  
  const registerResult = await auth.register(
    'test@example.com',
    'SecurePassword123!',
    { userAgent: 'Mozilla/5.0 Chrome/120', ipAddress: '192.168.1.1' }
  );
  
  console.log('Status:', registerResult.success ? '✅ Success' : '❌ Failed');
  
  if (registerResult.success) {
    userId = registerResult.data!.user.id;
    accessToken = registerResult.data!.accessToken;
    cookies = registerResult.cookies!;
    console.log('User ID:', userId);
    console.log('Cookies set:', cookies.length);
  }
  
  // 2. Login
  console.log('\n2. LOGIN');
  console.log('-'.repeat(40));
  
  const loginResult = await auth.login(
    'test@example.com',
    'SecurePassword123!',
    { userAgent: 'Mozilla/5.0 Chrome/120', ipAddress: '192.168.1.1' }
  );
  
  console.log('Status:', loginResult.success ? '✅ Success' : '❌ Failed');
  
  if (loginResult.success) {
    sessionId = loginResult.data!.sessionId;
    accessToken = loginResult.data!.accessToken;
    refreshToken = loginResult.data!.refreshToken!;
    cookies = loginResult.cookies!;
    console.log('Session ID:', sessionId);
  }
  
  // 3. Verify Access Token
  console.log('\n3. TOKEN VERIFICATION');
  console.log('-'.repeat(40));
  
  // Build cookie header from cookies
  const cookieHeader = cookies
    .map(c => c.split(';')[0])
    .join('; ');
  
  const verifyResult = await auth.verifyAccessToken(
    accessToken,
    { cookieHeader }
  );
  
  console.log('Status:', verifyResult.success ? '✅ Valid' : '❌ Invalid');
  if (verifyResult.success) {
    console.log('User ID from token:', verifyResult.data!.userId);
  }
  
  // 4. Token Refresh
  console.log('\n4. TOKEN REFRESH');
  console.log('-'.repeat(40));
  
  const refreshResult = await auth.refresh(
    refreshToken,
    { userAgent: 'Mozilla/5.0 Chrome/120', ipAddress: '192.168.1.1' }
  );
  
  console.log('Status:', refreshResult.success ? '✅ Success' : '❌ Failed');
  
  if (refreshResult.success) {
    const newAccessToken = refreshResult.data!.accessToken;
    const newRefreshToken = refreshResult.data!.refreshToken!;
    console.log('New access token received:', newAccessToken.length > 0);
    console.log('New refresh token received:', newRefreshToken.length > 0);
    
    // Update for next tests
    accessToken = newAccessToken;
    refreshToken = newRefreshToken;
    cookies = refreshResult.cookies!;
  }
  
  // 5. Try Old Refresh Token (should fail after rotation)
  console.log('\n5. TOKEN REUSE DETECTION');
  console.log('-'.repeat(40));
  
  const reuseResult = await auth.refresh(loginResult.data!.refreshToken!);
  console.log('Old token rejected:', !reuseResult.success ? '✅ Yes' : '❌ No');
  if (!reuseResult.success) {
    console.log('Error code:', reuseResult.error?.code);
  }
  
  // 6. Create Multiple Sessions
  console.log('\n6. MULTIPLE SESSIONS');
  console.log('-'.repeat(40));
  
  // Login from different devices
  await auth.login('test@example.com', 'SecurePassword123!', {
    userAgent: 'Mozilla/5.0 iPhone Safari/604',
    ipAddress: '10.0.0.1'
  });
  
  await auth.login('test@example.com', 'SecurePassword123!', {
    userAgent: 'Mozilla/5.0 Android Chrome/120',
    ipAddress: '172.16.0.1'
  });
  
  const sessionsResult = await auth.getSessions(userId);
  
  if (sessionsResult.success) {
    console.log('Active sessions:', sessionsResult.data!.length);
    for (const s of sessionsResult.data!) {
      console.log(`  - ${s.userAgent} | ${s.ipAddress}`);
    }
  }
  
  // 7. Logout All
  console.log('\n7. LOGOUT ALL');
  console.log('-'.repeat(40));
  
  const logoutAllResult = await auth.logoutAll(userId);
  
  console.log('Status:', logoutAllResult.success ? '✅ Success' : '❌ Failed');
  if (logoutAllResult.success) {
    console.log('Sessions revoked:', logoutAllResult.data!.revokedCount);
  }
  
  // Verify all sessions are gone
  const afterLogoutSessions = await auth.getSessions(userId);
  console.log('Remaining sessions:', afterLogoutSessions.data?.length ?? 0);
  
  // 8. Password Change
  console.log('\n8. PASSWORD CHANGE');
  console.log('-'.repeat(40));
  
  // First login again
  const newLogin = await auth.login('test@example.com', 'SecurePassword123!');
  
  if (newLogin.success) {
    const changeResult = await auth.changePassword(
      userId,
      'SecurePassword123!',
      'NewSecurePassword456!'
    );
    
    console.log('Status:', changeResult.success ? '✅ Success' : '❌ Failed');
    
    // Try login with new password
    const newPwLogin = await auth.login('test@example.com', 'NewSecurePassword456!');
    console.log('Login with new password:', newPwLogin.success ? '✅ Success' : '❌ Failed');
    
    // Try login with old password
    const oldPwLogin = await auth.login('test@example.com', 'SecurePassword123!');
    console.log('Login with old password rejected:', !oldPwLogin.success ? '✅ Yes' : '❌ No');
  }
  
  console.log('\n' + '='.repeat(60));
  console.log('Test Complete!');
  console.log('='.repeat(60));
}

testCompleteAuthFlow().catch(console.error);
```

### Exercise 8.3

1. Add the `refresh` and `logout` methods to `AuthService`
2. Implement `logoutAll` for "logout everywhere" functionality
3. Add `changePassword` with proper validation
4. Test the complete flow: register → login → refresh → logout
5. Verify token rotation works correctly

---

## Summary

In this part, you learned:

1. **AuthService Architecture** — Single entry point for all auth operations
2. **Registration and Login** — Secure flows with proper validation
3. **Token Refresh and Logout** — Complete token lifecycle management

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
├── sessions/
│   └── ...              # (from Part 7)
└── auth/
    ├── interfaces.ts    # Core interfaces
    ├── config.ts        # Configuration
    ├── errors.ts        # Error codes
    ├── validation.ts    # Input validation
    ├── service.ts       # AuthService class
    └── index.ts         # Public exports
```

### Key Takeaways

- Single AuthService class handles all auth operations
- Dependency injection enables testing and flexibility
- Consistent error responses with meaningful codes
- Cookie management is handled internally
- Framework-agnostic design for portability

### API Summary

| Method | Purpose |
|--------|---------|
| `register(email, password, context)` | Create new user account |
| `login(email, password, context)` | Authenticate and create session |
| `verifyAccessToken(token, context)` | Validate access token |
| `refresh(refreshToken, context)` | Get new tokens |
| `logout(refreshToken)` | End current session |
| `logoutAll(userId, except?)` | End all user sessions |
| `getSessions(userId, current?)` | List active sessions |
| `revokeSession(userId, sessionId)` | End specific session |
| `changePassword(userId, current, new)` | Update password |

### Next Steps

In **Part 9: Framework Integration**, we'll create adapters for:
- Express.js middleware
- Client-side SDK
- Testing utilities
