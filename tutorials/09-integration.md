# Part 9: Framework Integration

Our AuthService is framework-agnostic by design. In this part, we'll create integration layers for Express.js, build a client-side SDK, and set up testing utilities. These patterns can be adapted to any framework.

---

## Table of Contents

1. [Express.js Integration](#1-expressjs-integration)
2. [Client-Side SDK](#2-client-side-sdk)
3. [Testing Utilities](#3-testing-utilities)

---

## 1. Express.js Integration

### Request Context Extractor

```typescript
// src/integrations/express/context.ts

import { Request } from 'express';
import { RequestContext } from '../../auth/interfaces';

/**
 * Extract authentication context from Express request
 */
export function extractRequestContext(req: Request): RequestContext {
  return {
    userAgent: req.get('user-agent'),
    ipAddress: getClientIP(req),
    cookieHeader: req.get('cookie'),
    deviceId: req.get('x-device-id')
  };
}

/**
 * Get client IP address, handling proxies
 */
function getClientIP(req: Request): string {
  // Check X-Forwarded-For header (set by proxies/load balancers)
  const forwarded = req.get('x-forwarded-for');
  if (forwarded) {
    // Take the first IP (original client)
    return forwarded.split(',')[0].trim();
  }
  
  // Check X-Real-IP header (set by nginx)
  const realIP = req.get('x-real-ip');
  if (realIP) {
    return realIP;
  }
  
  // Fall back to socket address
  return req.socket.remoteAddress ?? 'unknown';
}

/**
 * Extract bearer token from Authorization header
 */
export function extractBearerToken(req: Request): string | null {
  const authHeader = req.get('authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return null;
  }
  return authHeader.slice(7);
}

/**
 * Extract refresh token from cookies
 */
export function extractRefreshToken(req: Request): string | null {
  // Works with cookie-parser middleware
  if (req.cookies?.['__Secure-Ref']) {
    return req.cookies['__Secure-Ref'];
  }
  
  // Manual parsing if no middleware
  const cookieHeader = req.get('cookie');
  if (!cookieHeader) return null;
  
  const match = cookieHeader.match(/__Secure-Ref=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : null;
}
```

### Authentication Middleware

```typescript
// src/integrations/express/middleware.ts

import { Request, Response, NextFunction } from 'express';
import { AuthService } from '../../auth/service';
import { extractRequestContext, extractBearerToken } from './context';
import { AuthErrorCodes } from '../../auth/errors';

/**
 * Extend Express Request with auth data
 */
declare global {
  namespace Express {
    interface Request {
      auth?: {
        userId: string;
        sessionId?: string;
        claims: Record<string, unknown>;
      };
    }
  }
}

/**
 * Options for auth middleware
 */
export interface AuthMiddlewareOptions {
  /**
   * If true, unauthenticated requests are allowed through
   * The route handler should check req.auth
   */
  optional?: boolean;
  
  /**
   * Custom error handler
   */
  onError?: (res: Response, error: { code: string; message: string }) => void;
}

/**
 * Create authentication middleware factory
 */
export function createAuthMiddleware(authService: AuthService) {
  /**
   * Middleware that verifies access tokens
   */
  return function authMiddleware(options: AuthMiddlewareOptions = {}) {
    return async (req: Request, res: Response, next: NextFunction) => {
      try {
        const token = extractBearerToken(req);
        
        if (!token) {
          if (options.optional) {
            return next();
          }
          
          const error = {
            code: AuthErrorCodes.TOKEN_MISSING,
            message: 'Authentication required'
          };
          
          if (options.onError) {
            return options.onError(res, error);
          }
          
          return res.status(401).json({ error });
        }
        
        const context = extractRequestContext(req);
        const result = await authService.verifyAccessToken(token, context);
        
        if (!result.success) {
          if (options.optional) {
            return next();
          }
          
          if (options.onError) {
            return options.onError(res, result.error!);
          }
          
          const status = result.error?.code === AuthErrorCodes.TOKEN_EXPIRED ? 401 : 403;
          return res.status(status).json({ error: result.error });
        }
        
        // Attach auth data to request
        req.auth = result.data;
        
        next();
      } catch (error) {
        console.error('Auth middleware error:', error);
        
        if (options.optional) {
          return next();
        }
        
        res.status(500).json({
          error: {
            code: AuthErrorCodes.INTERNAL_ERROR,
            message: 'Authentication failed'
          }
        });
      }
    };
  };
}

/**
 * Middleware that requires a specific claim value
 */
export function requireClaim(claim: string, value: unknown) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.auth) {
      return res.status(401).json({
        error: {
          code: AuthErrorCodes.TOKEN_MISSING,
          message: 'Authentication required'
        }
      });
    }
    
    if (req.auth.claims[claim] !== value) {
      return res.status(403).json({
        error: {
          code: 'INSUFFICIENT_PERMISSIONS',
          message: 'You do not have permission to access this resource'
        }
      });
    }
    
    next();
  };
}

/**
 * Middleware that requires any of the specified roles
 */
export function requireRole(...roles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.auth) {
      return res.status(401).json({
        error: {
          code: AuthErrorCodes.TOKEN_MISSING,
          message: 'Authentication required'
        }
      });
    }
    
    const userRole = req.auth.claims.role as string | undefined;
    
    if (!userRole || !roles.includes(userRole)) {
      return res.status(403).json({
        error: {
          code: 'INSUFFICIENT_PERMISSIONS',
          message: 'You do not have the required role'
        }
      });
    }
    
    next();
  };
}
```

### Auth Routes

```typescript
// src/integrations/express/routes.ts

import { Router, Request, Response } from 'express';
import { AuthService } from '../../auth/service';
import { extractRequestContext, extractRefreshToken } from './context';
import { createAuthMiddleware } from './middleware';

/**
 * Options for auth routes
 */
export interface AuthRoutesOptions {
  /**
   * Base path for routes
   * @default '/auth'
   */
  basePath?: string;
  
  /**
   * Include refresh token in response body (for non-cookie clients)
   * @default false
   */
  includeRefreshTokenInBody?: boolean;
}

/**
 * Create Express router with auth endpoints
 */
export function createAuthRoutes(
  authService: AuthService,
  options: AuthRoutesOptions = {}
): Router {
  const router = Router();
  const authenticate = createAuthMiddleware(authService);
  const includeRefresh = options.includeRefreshTokenInBody ?? false;
  
  /**
   * POST /register
   * Create a new account
   */
  router.post('/register', async (req: Request, res: Response) => {
    try {
      const { email, password } = req.body;
      
      if (!email || !password) {
        return res.status(400).json({
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Email and password are required'
          }
        });
      }
      
      const context = extractRequestContext(req);
      const result = await authService.register(email, password, context);
      
      if (!result.success) {
        return res.status(400).json({ error: result.error });
      }
      
      // Set cookies
      if (result.cookies) {
        for (const cookie of result.cookies) {
          res.append('Set-Cookie', cookie);
        }
      }
      
      const responseData: Record<string, unknown> = {
        user: result.data!.user,
        accessToken: result.data!.accessToken
      };
      
      if (includeRefresh) {
        responseData.refreshToken = result.data!.refreshToken;
      }
      
      res.status(201).json(responseData);
    } catch (error) {
      console.error('Register error:', error);
      res.status(500).json({
        error: { code: 'INTERNAL_ERROR', message: 'Registration failed' }
      });
    }
  });
  
  /**
   * POST /login
   * Authenticate with credentials
   */
  router.post('/login', async (req: Request, res: Response) => {
    try {
      const { email, password } = req.body;
      
      if (!email || !password) {
        return res.status(400).json({
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Email and password are required'
          }
        });
      }
      
      const context = extractRequestContext(req);
      const result = await authService.login(email, password, context);
      
      if (!result.success) {
        return res.status(401).json({ error: result.error });
      }
      
      // Set cookies
      if (result.cookies) {
        for (const cookie of result.cookies) {
          res.append('Set-Cookie', cookie);
        }
      }
      
      const responseData: Record<string, unknown> = {
        user: result.data!.user,
        accessToken: result.data!.accessToken,
        sessionId: result.data!.sessionId
      };
      
      if (includeRefresh) {
        responseData.refreshToken = result.data!.refreshToken;
      }
      
      res.status(200).json(responseData);
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({
        error: { code: 'INTERNAL_ERROR', message: 'Login failed' }
      });
    }
  });
  
  /**
   * POST /refresh
   * Get new tokens using refresh token
   */
  router.post('/refresh', async (req: Request, res: Response) => {
    try {
      // Get refresh token from cookie or body
      let refreshToken = extractRefreshToken(req);
      
      if (!refreshToken && req.body.refreshToken) {
        refreshToken = req.body.refreshToken;
      }
      
      if (!refreshToken) {
        return res.status(401).json({
          error: { code: 'TOKEN_MISSING', message: 'Refresh token required' }
        });
      }
      
      const context = extractRequestContext(req);
      const result = await authService.refresh(refreshToken, context);
      
      if (!result.success) {
        // Clear cookies on failure
        res.append('Set-Cookie', '__Secure-Ref=; Max-Age=0; Path=/; HttpOnly; Secure');
        res.append('Set-Cookie', '__Secure-Fpt=; Max-Age=0; Path=/; HttpOnly; Secure');
        
        return res.status(401).json({ error: result.error });
      }
      
      // Set new cookies
      if (result.cookies) {
        for (const cookie of result.cookies) {
          res.append('Set-Cookie', cookie);
        }
      }
      
      const responseData: Record<string, unknown> = {
        accessToken: result.data!.accessToken
      };
      
      if (includeRefresh) {
        responseData.refreshToken = result.data!.refreshToken;
      }
      
      res.status(200).json(responseData);
    } catch (error) {
      console.error('Refresh error:', error);
      res.status(500).json({
        error: { code: 'INTERNAL_ERROR', message: 'Token refresh failed' }
      });
    }
  });
  
  /**
   * POST /logout
   * End current session
   */
  router.post('/logout', async (req: Request, res: Response) => {
    try {
      const refreshToken = extractRefreshToken(req) ?? req.body.refreshToken;
      
      const result = await authService.logout(refreshToken);
      
      // Always clear cookies
      if (result.cookies) {
        for (const cookie of result.cookies) {
          res.append('Set-Cookie', cookie);
        }
      }
      
      res.status(200).json({ success: true });
    } catch (error) {
      console.error('Logout error:', error);
      // Still clear cookies on error
      res.append('Set-Cookie', '__Secure-Ref=; Max-Age=0; Path=/; HttpOnly; Secure');
      res.append('Set-Cookie', '__Secure-Fpt=; Max-Age=0; Path=/; HttpOnly; Secure');
      res.status(200).json({ success: true });
    }
  });
  
  /**
   * POST /logout-all
   * End all sessions
   */
  router.post('/logout-all', authenticate(), async (req: Request, res: Response) => {
    try {
      const result = await authService.logoutAll(req.auth!.userId);
      
      if (result.cookies) {
        for (const cookie of result.cookies) {
          res.append('Set-Cookie', cookie);
        }
      }
      
      res.status(200).json({
        success: true,
        revokedCount: result.data?.revokedCount
      });
    } catch (error) {
      console.error('Logout all error:', error);
      res.status(500).json({
        error: { code: 'INTERNAL_ERROR', message: 'Logout failed' }
      });
    }
  });
  
  /**
   * GET /sessions
   * List active sessions
   */
  router.get('/sessions', authenticate(), async (req: Request, res: Response) => {
    try {
      const result = await authService.getSessions(
        req.auth!.userId,
        req.auth!.sessionId
      );
      
      if (!result.success) {
        return res.status(500).json({ error: result.error });
      }
      
      res.status(200).json({ sessions: result.data });
    } catch (error) {
      console.error('Get sessions error:', error);
      res.status(500).json({
        error: { code: 'INTERNAL_ERROR', message: 'Failed to get sessions' }
      });
    }
  });
  
  /**
   * DELETE /sessions/:sessionId
   * Revoke a specific session
   */
  router.delete('/sessions/:sessionId', authenticate(), async (req: Request, res: Response) => {
    try {
      const result = await authService.revokeSession(
        req.auth!.userId,
        req.params.sessionId
      );
      
      if (!result.success) {
        return res.status(404).json({ error: result.error });
      }
      
      res.status(200).json({ success: true });
    } catch (error) {
      console.error('Revoke session error:', error);
      res.status(500).json({
        error: { code: 'INTERNAL_ERROR', message: 'Failed to revoke session' }
      });
    }
  });
  
  /**
   * POST /change-password
   * Update password
   */
  router.post('/change-password', authenticate(), async (req: Request, res: Response) => {
    try {
      const { currentPassword, newPassword } = req.body;
      
      if (!currentPassword || !newPassword) {
        return res.status(400).json({
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Current and new password are required'
          }
        });
      }
      
      const result = await authService.changePassword(
        req.auth!.userId,
        currentPassword,
        newPassword
      );
      
      if (!result.success) {
        return res.status(400).json({ error: result.error });
      }
      
      res.status(200).json({ success: true });
    } catch (error) {
      console.error('Change password error:', error);
      res.status(500).json({
        error: { code: 'INTERNAL_ERROR', message: 'Failed to change password' }
      });
    }
  });
  
  /**
   * GET /me
   * Get current user info
   */
  router.get('/me', authenticate(), async (req: Request, res: Response) => {
    res.status(200).json({
      userId: req.auth!.userId,
      claims: req.auth!.claims
    });
  });
  
  return router;
}
```

### Express App Setup

```typescript
// src/integrations/express/index.ts

export { extractRequestContext, extractBearerToken, extractRefreshToken } from './context';
export { createAuthMiddleware, requireClaim, requireRole, AuthMiddlewareOptions } from './middleware';
export { createAuthRoutes, AuthRoutesOptions } from './routes';

// Example usage:
/*
import express from 'express';
import { AuthService } from '../../auth';
import { createAuthRoutes, createAuthMiddleware } from './index';

const app = express();
app.use(express.json());

// Setup auth service
const authService = new AuthService(userStore, sessionStore, keyProvider);

// Mount auth routes
app.use('/auth', createAuthRoutes(authService));

// Create middleware
const authenticate = createAuthMiddleware(authService);

// Protected route
app.get('/api/protected', authenticate(), (req, res) => {
  res.json({ userId: req.auth!.userId });
});

// Optional auth route
app.get('/api/optional', authenticate({ optional: true }), (req, res) => {
  if (req.auth) {
    res.json({ userId: req.auth.userId });
  } else {
    res.json({ message: 'Anonymous user' });
  }
});

// Role-based route
app.get('/api/admin', authenticate(), requireRole('admin'), (req, res) => {
  res.json({ message: 'Admin only content' });
});
*/
```

### Exercise 9.1

1. Create `src/integrations/express/context.ts` for request context extraction
2. Create `src/integrations/express/middleware.ts` with auth middleware
3. Create `src/integrations/express/routes.ts` with all auth endpoints
4. Test with a real Express app

---

## 2. Client-Side SDK

### Auth Client

```typescript
// src/integrations/client/auth-client.ts

/**
 * Configuration for AuthClient
 */
export interface AuthClientConfig {
  /**
   * Base URL for auth endpoints
   * @example 'https://api.example.com/auth'
   */
  baseUrl: string;
  
  /**
   * Storage for tokens (localStorage, sessionStorage, or custom)
   * @default localStorage
   */
  storage?: Storage;
  
  /**
   * Key for storing access token
   * @default 'auth_access_token'
   */
  accessTokenKey?: string;
  
  /**
   * Automatically refresh tokens before expiry
   * @default true
   */
  autoRefresh?: boolean;
  
  /**
   * Seconds before expiry to trigger refresh
   * @default 60
   */
  refreshThreshold?: number;
  
  /**
   * Called when auth state changes
   */
  onAuthChange?: (isAuthenticated: boolean) => void;
  
  /**
   * Called when session expires or is revoked
   */
  onSessionExpired?: () => void;
  
  /**
   * Custom fetch function (for testing or middleware)
   */
  fetch?: typeof fetch;
}

/**
 * User data returned from auth endpoints
 */
export interface AuthUser {
  id: string;
  email: string;
}

/**
 * Decoded JWT payload
 */
export interface TokenPayload {
  sub: string;
  email?: string;
  exp: number;
  iat: number;
  [key: string]: unknown;
}

/**
 * Client-side authentication SDK
 */
export class AuthClient {
  private config: Required<AuthClientConfig>;
  private refreshTimer?: ReturnType<typeof setTimeout>;
  private refreshPromise?: Promise<boolean>;
  
  constructor(config: AuthClientConfig) {
    this.config = {
      baseUrl: config.baseUrl.replace(/\/$/, ''),
      storage: config.storage ?? (typeof localStorage !== 'undefined' ? localStorage : new MemoryStorage()),
      accessTokenKey: config.accessTokenKey ?? 'auth_access_token',
      autoRefresh: config.autoRefresh ?? true,
      refreshThreshold: config.refreshThreshold ?? 60,
      onAuthChange: config.onAuthChange ?? (() => {}),
      onSessionExpired: config.onSessionExpired ?? (() => {}),
      fetch: config.fetch ?? fetch.bind(globalThis)
    };
    
    // Setup auto-refresh if authenticated
    if (this.config.autoRefresh && this.isAuthenticated()) {
      this.scheduleRefresh();
    }
  }
  
  // ─────────────────────────────────────────────────────────────────────────
  // Authentication Methods
  // ─────────────────────────────────────────────────────────────────────────
  
  /**
   * Register a new account
   */
  async register(email: string, password: string): Promise<{
    success: boolean;
    user?: AuthUser;
    error?: { code: string; message: string };
  }> {
    try {
      const response = await this.request('/register', {
        method: 'POST',
        body: JSON.stringify({ email, password })
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        return { success: false, error: data.error };
      }
      
      // Store token
      this.setAccessToken(data.accessToken);
      this.scheduleRefresh();
      this.config.onAuthChange(true);
      
      return { success: true, user: data.user };
    } catch (error) {
      return {
        success: false,
        error: { code: 'NETWORK_ERROR', message: 'Failed to connect to server' }
      };
    }
  }
  
  /**
   * Login with credentials
   */
  async login(email: string, password: string): Promise<{
    success: boolean;
    user?: AuthUser;
    error?: { code: string; message: string };
  }> {
    try {
      const response = await this.request('/login', {
        method: 'POST',
        body: JSON.stringify({ email, password })
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        return { success: false, error: data.error };
      }
      
      this.setAccessToken(data.accessToken);
      this.scheduleRefresh();
      this.config.onAuthChange(true);
      
      return { success: true, user: data.user };
    } catch (error) {
      return {
        success: false,
        error: { code: 'NETWORK_ERROR', message: 'Failed to connect to server' }
      };
    }
  }
  
  /**
   * Logout current session
   */
  async logout(): Promise<void> {
    try {
      await this.request('/logout', { method: 'POST' });
    } catch {
      // Ignore errors, still clear local state
    }
    
    this.clearAuth();
  }
  
  /**
   * Logout all sessions
   */
  async logoutAll(): Promise<{
    success: boolean;
    revokedCount?: number;
  }> {
    try {
      const response = await this.authenticatedRequest('/logout-all', {
        method: 'POST'
      });
      
      const data = await response.json();
      this.clearAuth();
      
      return { success: true, revokedCount: data.revokedCount };
    } catch {
      this.clearAuth();
      return { success: false };
    }
  }
  
  /**
   * Refresh access token
   */
  async refresh(): Promise<boolean> {
    // Prevent concurrent refreshes
    if (this.refreshPromise) {
      return this.refreshPromise;
    }
    
    this.refreshPromise = this.doRefresh();
    
    try {
      return await this.refreshPromise;
    } finally {
      this.refreshPromise = undefined;
    }
  }
  
  private async doRefresh(): Promise<boolean> {
    try {
      const response = await this.request('/refresh', {
        method: 'POST'
      });
      
      if (!response.ok) {
        this.clearAuth();
        this.config.onSessionExpired();
        return false;
      }
      
      const data = await response.json();
      this.setAccessToken(data.accessToken);
      this.scheduleRefresh();
      
      return true;
    } catch {
      return false;
    }
  }
  
  // ─────────────────────────────────────────────────────────────────────────
  // Token Management
  // ─────────────────────────────────────────────────────────────────────────
  
  /**
   * Get the current access token
   */
  getAccessToken(): string | null {
    return this.config.storage.getItem(this.config.accessTokenKey);
  }
  
  /**
   * Check if user is authenticated
   */
  isAuthenticated(): boolean {
    const token = this.getAccessToken();
    if (!token) return false;
    
    const payload = this.decodeToken(token);
    if (!payload) return false;
    
    // Check if token is expired
    return payload.exp * 1000 > Date.now();
  }
  
  /**
   * Get current user from token
   */
  getCurrentUser(): { id: string; email?: string } | null {
    const token = this.getAccessToken();
    if (!token) return null;
    
    const payload = this.decodeToken(token);
    if (!payload) return null;
    
    return {
      id: payload.sub,
      email: payload.email as string | undefined
    };
  }
  
  /**
   * Decode JWT payload (without verification)
   */
  decodeToken(token: string): TokenPayload | null {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;
      
      const payload = parts[1];
      const decoded = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
      return JSON.parse(decoded);
    } catch {
      return null;
    }
  }
  
  private setAccessToken(token: string): void {
    this.config.storage.setItem(this.config.accessTokenKey, token);
  }
  
  private clearAuth(): void {
    this.config.storage.removeItem(this.config.accessTokenKey);
    
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = undefined;
    }
    
    this.config.onAuthChange(false);
  }
  
  private scheduleRefresh(): void {
    if (!this.config.autoRefresh) return;
    
    const token = this.getAccessToken();
    if (!token) return;
    
    const payload = this.decodeToken(token);
    if (!payload) return;
    
    // Calculate time until refresh
    const expiresAt = payload.exp * 1000;
    const refreshAt = expiresAt - (this.config.refreshThreshold * 1000);
    const delay = refreshAt - Date.now();
    
    if (delay <= 0) {
      // Token is about to expire, refresh now
      this.refresh();
      return;
    }
    
    // Clear existing timer
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
    }
    
    // Schedule refresh
    this.refreshTimer = setTimeout(() => {
      this.refresh();
    }, delay);
  }
  
  // ─────────────────────────────────────────────────────────────────────────
  // Session Management
  // ─────────────────────────────────────────────────────────────────────────
  
  /**
   * Get active sessions
   */
  async getSessions(): Promise<{
    success: boolean;
    sessions?: Array<{
      id: string;
      createdAt: string;
      lastUsedAt: string;
      userAgent?: string;
      ipAddress?: string;
      isCurrent: boolean;
    }>;
    error?: { code: string; message: string };
  }> {
    try {
      const response = await this.authenticatedRequest('/sessions');
      
      if (!response.ok) {
        const data = await response.json();
        return { success: false, error: data.error };
      }
      
      const data = await response.json();
      return { success: true, sessions: data.sessions };
    } catch (error) {
      return {
        success: false,
        error: { code: 'NETWORK_ERROR', message: 'Failed to get sessions' }
      };
    }
  }
  
  /**
   * Revoke a specific session
   */
  async revokeSession(sessionId: string): Promise<{
    success: boolean;
    error?: { code: string; message: string };
  }> {
    try {
      const response = await this.authenticatedRequest(`/sessions/${sessionId}`, {
        method: 'DELETE'
      });
      
      if (!response.ok) {
        const data = await response.json();
        return { success: false, error: data.error };
      }
      
      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: { code: 'NETWORK_ERROR', message: 'Failed to revoke session' }
      };
    }
  }
  
  // ─────────────────────────────────────────────────────────────────────────
  // Password Management
  // ─────────────────────────────────────────────────────────────────────────
  
  /**
   * Change password
   */
  async changePassword(currentPassword: string, newPassword: string): Promise<{
    success: boolean;
    error?: { code: string; message: string };
  }> {
    try {
      const response = await this.authenticatedRequest('/change-password', {
        method: 'POST',
        body: JSON.stringify({ currentPassword, newPassword })
      });
      
      if (!response.ok) {
        const data = await response.json();
        return { success: false, error: data.error };
      }
      
      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: { code: 'NETWORK_ERROR', message: 'Failed to change password' }
      };
    }
  }
  
  // ─────────────────────────────────────────────────────────────────────────
  // HTTP Helpers
  // ─────────────────────────────────────────────────────────────────────────
  
  /**
   * Make a request to auth endpoint
   */
  private request(path: string, options: RequestInit = {}): Promise<Response> {
    return this.config.fetch(`${this.config.baseUrl}${path}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      },
      credentials: 'include'  // Include cookies
    });
  }
  
  /**
   * Make an authenticated request
   */
  async authenticatedRequest(path: string, options: RequestInit = {}): Promise<Response> {
    const token = this.getAccessToken();
    
    if (!token) {
      throw new Error('Not authenticated');
    }
    
    const response = await this.request(path, {
      ...options,
      headers: {
        ...options.headers,
        'Authorization': `Bearer ${token}`
      }
    });
    
    // Handle token expiry
    if (response.status === 401) {
      const refreshed = await this.refresh();
      
      if (refreshed) {
        // Retry with new token
        return this.request(path, {
          ...options,
          headers: {
            ...options.headers,
            'Authorization': `Bearer ${this.getAccessToken()}`
          }
        });
      }
    }
    
    return response;
  }
  
  /**
   * Create a fetch wrapper that adds auth headers
   * Use this for API calls outside of auth
   */
  createAuthFetch(): typeof fetch {
    return async (input: RequestInfo | URL, init?: RequestInit) => {
      const token = this.getAccessToken();
      
      if (!token || !this.isAuthenticated()) {
        throw new Error('Not authenticated');
      }
      
      const headers = new Headers(init?.headers);
      headers.set('Authorization', `Bearer ${token}`);
      
      const response = await this.config.fetch(input, {
        ...init,
        headers,
        credentials: 'include'
      });
      
      // Handle token expiry
      if (response.status === 401) {
        const refreshed = await this.refresh();
        
        if (refreshed) {
          headers.set('Authorization', `Bearer ${this.getAccessToken()}`);
          return this.config.fetch(input, {
            ...init,
            headers,
            credentials: 'include'
          });
        }
      }
      
      return response;
    };
  }
}

/**
 * In-memory storage for non-browser environments
 */
class MemoryStorage implements Storage {
  private data: Map<string, string> = new Map();
  
  get length(): number {
    return this.data.size;
  }
  
  clear(): void {
    this.data.clear();
  }
  
  getItem(key: string): string | null {
    return this.data.get(key) ?? null;
  }
  
  key(index: number): string | null {
    const keys = Array.from(this.data.keys());
    return keys[index] ?? null;
  }
  
  removeItem(key: string): void {
    this.data.delete(key);
  }
  
  setItem(key: string, value: string): void {
    this.data.set(key, value);
  }
}
```

### React Integration Hook

```typescript
// src/integrations/client/react.ts

import { useState, useEffect, useCallback, createContext, useContext, ReactNode } from 'react';
import { AuthClient, AuthClientConfig, AuthUser } from './auth-client';

/**
 * Auth context value
 */
interface AuthContextValue {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: { id: string; email?: string } | null;
  login: (email: string, password: string) => Promise<{ success: boolean; error?: any }>;
  register: (email: string, password: string) => Promise<{ success: boolean; error?: any }>;
  logout: () => Promise<void>;
  refresh: () => Promise<boolean>;
  client: AuthClient;
}

const AuthContext = createContext<AuthContextValue | null>(null);

/**
 * Auth provider component
 */
export function AuthProvider({
  children,
  config
}: {
  children: ReactNode;
  config: AuthClientConfig;
}) {
  const [client] = useState(() => new AuthClient(config));
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [user, setUser] = useState<{ id: string; email?: string } | null>(null);
  
  // Initialize auth state
  useEffect(() => {
    const checkAuth = () => {
      const authenticated = client.isAuthenticated();
      setIsAuthenticated(authenticated);
      setUser(authenticated ? client.getCurrentUser() : null);
      setIsLoading(false);
    };
    
    checkAuth();
    
    // Update on storage changes (for multi-tab sync)
    const handleStorage = (e: StorageEvent) => {
      if (e.key === config.accessTokenKey) {
        checkAuth();
      }
    };
    
    window.addEventListener('storage', handleStorage);
    return () => window.removeEventListener('storage', handleStorage);
  }, [client, config.accessTokenKey]);
  
  const login = useCallback(async (email: string, password: string) => {
    const result = await client.login(email, password);
    if (result.success) {
      setIsAuthenticated(true);
      setUser(client.getCurrentUser());
    }
    return result;
  }, [client]);
  
  const register = useCallback(async (email: string, password: string) => {
    const result = await client.register(email, password);
    if (result.success) {
      setIsAuthenticated(true);
      setUser(client.getCurrentUser());
    }
    return result;
  }, [client]);
  
  const logout = useCallback(async () => {
    await client.logout();
    setIsAuthenticated(false);
    setUser(null);
  }, [client]);
  
  const refresh = useCallback(async () => {
    const success = await client.refresh();
    if (!success) {
      setIsAuthenticated(false);
      setUser(null);
    }
    return success;
  }, [client]);
  
  return (
    <AuthContext.Provider value={{
      isAuthenticated,
      isLoading,
      user,
      login,
      register,
      logout,
      refresh,
      client
    }}>
      {children}
    </AuthContext.Provider>
  );
}

/**
 * Hook to access auth context
 */
export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

/**
 * Hook for protected routes
 */
export function useRequireAuth(redirectTo: string = '/login') {
  const { isAuthenticated, isLoading } = useAuth();
  
  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      // In a real app, use your router's navigation
      window.location.href = redirectTo;
    }
  }, [isAuthenticated, isLoading, redirectTo]);
  
  return { isAuthenticated, isLoading };
}
```

### Client SDK Index

```typescript
// src/integrations/client/index.ts

export { AuthClient, AuthClientConfig, AuthUser, TokenPayload } from './auth-client';
export { AuthProvider, useAuth, useRequireAuth } from './react';

// Usage example:
/*
// In your app root
import { AuthProvider } from '@your-auth/client';

function App() {
  return (
    <AuthProvider config={{ baseUrl: 'https://api.example.com/auth' }}>
      <YourApp />
    </AuthProvider>
  );
}

// In components
import { useAuth } from '@your-auth/client';

function LoginForm() {
  const { login, isLoading } = useAuth();
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    const result = await login(email, password);
    if (result.success) {
      navigate('/dashboard');
    } else {
      setError(result.error.message);
    }
  };
  
  // ...
}

function ProtectedPage() {
  const { isAuthenticated, isLoading, user } = useAuth();
  useRequireAuth('/login');
  
  if (isLoading) return <Loading />;
  
  return <div>Welcome, {user?.email}</div>;
}
*/
```

### Exercise 9.2

1. Create `src/integrations/client/auth-client.ts` with the AuthClient class
2. Create `src/integrations/client/react.ts` with React hooks
3. Test automatic token refresh
4. Implement multi-tab session sync

---

## 3. Testing Utilities

### Mock Factories

```typescript
// src/testing/mocks.ts

import { AuthUser, UserStore, KeyProvider, SessionStore, Session } from '../auth/interfaces';
import { generateRS256KeyPair } from '../jwt/keys';
import { hashPassword } from '../password';
import { generateSecureId, hashToken } from '../sessions/utils';

/**
 * Create a mock user for testing
 */
export async function createMockUser(overrides: Partial<AuthUser> = {}): Promise<AuthUser> {
  const passwordHash = await hashPassword('TestPassword123!');
  
  return {
    id: overrides.id ?? `user_${generateSecureId(8)}`,
    email: overrides.email ?? `test_${Date.now()}@example.com`,
    passwordHash: overrides.passwordHash ?? passwordHash,
    emailVerified: overrides.emailVerified ?? true,
    disabled: overrides.disabled ?? false,
    ...overrides
  };
}

/**
 * In-memory user store for testing
 */
export class MockUserStore implements UserStore {
  private users: Map<string, AuthUser> = new Map();
  private emailIndex: Map<string, string> = new Map();
  
  async findByEmail(email: string): Promise<AuthUser | null> {
    const id = this.emailIndex.get(email.toLowerCase());
    return id ? this.users.get(id) ?? null : null;
  }
  
  async findById(id: string): Promise<AuthUser | null> {
    return this.users.get(id) ?? null;
  }
  
  async create(data: { email: string; passwordHash: string }): Promise<AuthUser> {
    const id = `user_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    const user: AuthUser = {
      id,
      email: data.email.toLowerCase(),
      passwordHash: data.passwordHash,
      emailVerified: false,
      disabled: false
    };
    this.users.set(id, user);
    this.emailIndex.set(user.email, id);
    return user;
  }
  
  async update(id: string, data: Partial<AuthUser>): Promise<AuthUser | null> {
    const user = this.users.get(id);
    if (!user) return null;
    
    const updated = { ...user, ...data };
    this.users.set(id, updated);
    
    // Update email index if email changed
    if (data.email && data.email !== user.email) {
      this.emailIndex.delete(user.email);
      this.emailIndex.set(data.email.toLowerCase(), id);
    }
    
    return updated;
  }
  
  async emailExists(email: string): Promise<boolean> {
    return this.emailIndex.has(email.toLowerCase());
  }
  
  // Test helpers
  addUser(user: AuthUser): void {
    this.users.set(user.id, user);
    this.emailIndex.set(user.email.toLowerCase(), user.id);
  }
  
  clear(): void {
    this.users.clear();
    this.emailIndex.clear();
  }
  
  getAll(): AuthUser[] {
    return Array.from(this.users.values());
  }
}

/**
 * In-memory session store for testing
 */
export class MockSessionStore implements SessionStore {
  private sessions: Map<string, Session> = new Map();
  private tokenIndex: Map<string, string> = new Map();
  
  async create(input: {
    userId: string;
    refreshToken: string;
    expiresAt: Date;
    userAgent?: string;
    ipAddress?: string;
  }): Promise<Session> {
    const id = generateSecureId();
    const tokenHash = await hashToken(input.refreshToken);
    const now = new Date();
    
    const session: Session = {
      id,
      userId: input.userId,
      refreshTokenHash: tokenHash,
      createdAt: now,
      expiresAt: input.expiresAt,
      lastUsedAt: now,
      userAgent: input.userAgent,
      ipAddress: input.ipAddress,
      isRevoked: false,
      tokenFamily: generateSecureId(),
      tokenGeneration: 1
    };
    
    this.sessions.set(id, session);
    this.tokenIndex.set(tokenHash, id);
    
    return session;
  }
  
  async findById(sessionId: string): Promise<Session | null> {
    return this.sessions.get(sessionId) ?? null;
  }
  
  async findByTokenHash(tokenHash: string): Promise<Session | null> {
    const id = this.tokenIndex.get(tokenHash);
    return id ? this.sessions.get(id) ?? null : null;
  }
  
  async findByUserId(userId: string): Promise<Session[]> {
    return Array.from(this.sessions.values()).filter(s => s.userId === userId);
  }
  
  async update(sessionId: string, updates: Partial<Session>): Promise<Session | null> {
    const session = this.sessions.get(sessionId);
    if (!session) return null;
    
    if (updates.refreshTokenHash && updates.refreshTokenHash !== session.refreshTokenHash) {
      this.tokenIndex.delete(session.refreshTokenHash);
      this.tokenIndex.set(updates.refreshTokenHash, sessionId);
    }
    
    const updated = { ...session, ...updates };
    this.sessions.set(sessionId, updated);
    return updated;
  }
  
  async revoke(sessionId: string, reason: Session['revokedReason']): Promise<boolean> {
    const session = this.sessions.get(sessionId);
    if (!session) return false;
    
    session.isRevoked = true;
    session.revokedReason = reason;
    this.tokenIndex.delete(session.refreshTokenHash);
    
    return true;
  }
  
  async revokeAllForUser(userId: string, exceptSessionId?: string): Promise<number> {
    let count = 0;
    for (const session of this.sessions.values()) {
      if (session.userId === userId && session.id !== exceptSessionId && !session.isRevoked) {
        await this.revoke(session.id, 'security');
        count++;
      }
    }
    return count;
  }
  
  async revokeTokenFamily(tokenFamily: string): Promise<number> {
    let count = 0;
    for (const session of this.sessions.values()) {
      if (session.tokenFamily === tokenFamily && !session.isRevoked) {
        await this.revoke(session.id, 'security');
        count++;
      }
    }
    return count;
  }
  
  async deleteExpired(): Promise<number> {
    const now = new Date();
    let count = 0;
    for (const [id, session] of this.sessions) {
      if (session.expiresAt < now || session.isRevoked) {
        this.tokenIndex.delete(session.refreshTokenHash);
        this.sessions.delete(id);
        count++;
      }
    }
    return count;
  }
  
  async countActiveForUser(userId: string): Promise<number> {
    const now = new Date();
    return Array.from(this.sessions.values()).filter(
      s => s.userId === userId && !s.isRevoked && s.expiresAt > now
    ).length;
  }
  
  // Test helpers
  clear(): void {
    this.sessions.clear();
    this.tokenIndex.clear();
  }
  
  getAll(): Session[] {
    return Array.from(this.sessions.values());
  }
}

/**
 * Create a mock key provider for testing
 */
export async function createMockKeyProvider(): Promise<KeyProvider> {
  const { privateKey, publicKey } = await generateRS256KeyPair();
  const keyId = 'test-key-' + Date.now();
  
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

/**
 * Create all mocks needed for AuthService
 */
export async function createTestContext() {
  const userStore = new MockUserStore();
  const sessionStore = new MockSessionStore();
  const keyProvider = await createMockKeyProvider();
  
  return {
    userStore,
    sessionStore,
    keyProvider,
    cleanup() {
      userStore.clear();
      sessionStore.clear();
    }
  };
}
```

### Test Helpers

```typescript
// src/testing/helpers.ts

import { AuthService } from '../auth/service';
import { createTestContext, MockUserStore, MockSessionStore } from './mocks';
import { AuthConfig } from '../auth/config';

/**
 * Create an AuthService instance for testing
 */
export async function createTestAuthService(
  config: Partial<AuthConfig> = {}
): Promise<{
  authService: AuthService;
  userStore: MockUserStore;
  sessionStore: MockSessionStore;
  cleanup: () => void;
}> {
  const { userStore, sessionStore, keyProvider, cleanup } = await createTestContext();
  
  const authService = new AuthService(userStore, sessionStore, keyProvider, {
    accessTokenLifetime: 900,
    refreshTokenLifetimeDays: 30,
    maxSessionsPerUser: 5,
    enableFingerprinting: false,  // Simpler for testing
    enableTokenRotation: true,
    enableReuseDetection: true,
    ...config
  });
  
  return { authService, userStore, sessionStore, cleanup };
}

/**
 * Register and login a test user, returning tokens
 */
export async function loginTestUser(
  authService: AuthService,
  email: string = 'test@example.com',
  password: string = 'TestPassword123!'
): Promise<{
  userId: string;
  accessToken: string;
  refreshToken: string;
  sessionId: string;
}> {
  // Register
  const registerResult = await authService.register(email, password, {
    userAgent: 'Test Agent',
    ipAddress: '127.0.0.1'
  });
  
  if (!registerResult.success) {
    throw new Error(`Registration failed: ${registerResult.error?.message}`);
  }
  
  // Login to get session info
  const loginResult = await authService.login(email, password, {
    userAgent: 'Test Agent',
    ipAddress: '127.0.0.1'
  });
  
  if (!loginResult.success) {
    throw new Error(`Login failed: ${loginResult.error?.message}`);
  }
  
  return {
    userId: loginResult.data!.user.id,
    accessToken: loginResult.data!.accessToken,
    refreshToken: loginResult.data!.refreshToken!,
    sessionId: loginResult.data!.sessionId
  };
}

/**
 * Wait for a specified time (for testing timeouts)
 */
export function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Generate a unique email for testing
 */
export function uniqueEmail(): string {
  return `test_${Date.now()}_${Math.random().toString(36).slice(2)}@example.com`;
}
```

### Example Test Suite

```typescript
// src/testing/example.test.ts

import { describe, it, expect, beforeEach, afterEach } from 'vitest';  // or jest
import { createTestAuthService, loginTestUser, uniqueEmail } from './helpers';
import { AuthErrorCodes } from '../auth/errors';

describe('AuthService', () => {
  let authService: Awaited<ReturnType<typeof createTestAuthService>>['authService'];
  let cleanup: () => void;
  
  beforeEach(async () => {
    const context = await createTestAuthService();
    authService = context.authService;
    cleanup = context.cleanup;
  });
  
  afterEach(() => {
    cleanup();
  });
  
  describe('Registration', () => {
    it('should register a new user', async () => {
      const email = uniqueEmail();
      const result = await authService.register(email, 'SecurePassword123!');
      
      expect(result.success).toBe(true);
      expect(result.data?.user.email).toBe(email);
      expect(result.data?.accessToken).toBeDefined();
    });
    
    it('should reject duplicate emails', async () => {
      const email = uniqueEmail();
      
      await authService.register(email, 'SecurePassword123!');
      const result = await authService.register(email, 'AnotherPassword123!');
      
      expect(result.success).toBe(false);
      expect(result.error?.code).toBe(AuthErrorCodes.EMAIL_ALREADY_EXISTS);
    });
    
    it('should reject weak passwords', async () => {
      const result = await authService.register(uniqueEmail(), 'weak');
      
      expect(result.success).toBe(false);
      expect(result.error?.code).toBe(AuthErrorCodes.PASSWORD_TOO_WEAK);
    });
    
    it('should reject invalid email formats', async () => {
      const result = await authService.register('not-an-email', 'SecurePassword123!');
      
      expect(result.success).toBe(false);
      expect(result.error?.code).toBe(AuthErrorCodes.INVALID_EMAIL_FORMAT);
    });
  });
  
  describe('Login', () => {
    it('should login with correct credentials', async () => {
      const email = uniqueEmail();
      const password = 'SecurePassword123!';
      
      await authService.register(email, password);
      const result = await authService.login(email, password);
      
      expect(result.success).toBe(true);
      expect(result.data?.sessionId).toBeDefined();
    });
    
    it('should reject wrong password', async () => {
      const email = uniqueEmail();
      
      await authService.register(email, 'SecurePassword123!');
      const result = await authService.login(email, 'WrongPassword123!');
      
      expect(result.success).toBe(false);
      expect(result.error?.code).toBe(AuthErrorCodes.INVALID_CREDENTIALS);
    });
    
    it('should reject non-existent user', async () => {
      const result = await authService.login('nonexistent@example.com', 'Password123!');
      
      expect(result.success).toBe(false);
      expect(result.error?.code).toBe(AuthErrorCodes.INVALID_CREDENTIALS);
    });
  });
  
  describe('Token Refresh', () => {
    it('should refresh with valid token', async () => {
      const { refreshToken } = await loginTestUser(authService);
      
      const result = await authService.refresh(refreshToken);
      
      expect(result.success).toBe(true);
      expect(result.data?.accessToken).toBeDefined();
      expect(result.data?.refreshToken).toBeDefined();
    });
    
    it('should reject invalid token', async () => {
      const result = await authService.refresh('invalid-token');
      
      expect(result.success).toBe(false);
      expect(result.error?.code).toBe(AuthErrorCodes.TOKEN_INVALID);
    });
    
    it('should reject used token after rotation', async () => {
      const { refreshToken } = await loginTestUser(authService);
      
      // Use token once
      await authService.refresh(refreshToken);
      
      // Try to use it again
      const result = await authService.refresh(refreshToken);
      
      expect(result.success).toBe(false);
    });
  });
  
  describe('Logout', () => {
    it('should logout current session', async () => {
      const { refreshToken } = await loginTestUser(authService);
      
      const result = await authService.logout(refreshToken);
      
      expect(result.success).toBe(true);
      expect(result.cookies).toBeDefined();
      expect(result.cookies!.some(c => c.includes('Max-Age=0'))).toBe(true);
    });
    
    it('should reject token after logout', async () => {
      const { refreshToken } = await loginTestUser(authService);
      
      await authService.logout(refreshToken);
      const result = await authService.refresh(refreshToken);
      
      expect(result.success).toBe(false);
    });
  });
  
  describe('Session Management', () => {
    it('should list active sessions', async () => {
      const { userId } = await loginTestUser(authService);
      
      // Login again to create second session
      const email = (await authService['userStore'].findById(userId))!.email;
      await authService.login(email, 'TestPassword123!');
      
      const result = await authService.getSessions(userId);
      
      expect(result.success).toBe(true);
      expect(result.data!.length).toBe(2);
    });
    
    it('should revoke all sessions', async () => {
      const { userId } = await loginTestUser(authService);
      
      const result = await authService.logoutAll(userId);
      
      expect(result.success).toBe(true);
      
      const sessions = await authService.getSessions(userId);
      expect(sessions.data!.length).toBe(0);
    });
  });
});
```

### Testing Index

```typescript
// src/testing/index.ts

export { 
  createMockUser, 
  MockUserStore, 
  MockSessionStore, 
  createMockKeyProvider, 
  createTestContext 
} from './mocks';

export { 
  createTestAuthService, 
  loginTestUser, 
  delay, 
  uniqueEmail 
} from './helpers';
```

### Exercise 9.3

1. Create `src/testing/mocks.ts` with mock implementations
2. Create `src/testing/helpers.ts` with test utilities
3. Write tests for registration edge cases
4. Write tests for token refresh with rotation
5. Test the session limit enforcement

---

## Summary

In this part, you learned:

1. **Express.js Integration** — Middleware, routes, and request context extraction
2. **Client-Side SDK** — AuthClient with auto-refresh and React hooks
3. **Testing Utilities** — Mock stores and test helpers

### Files Created

```
src/
├── auth/
│   └── ...              # (from Part 8)
├── integrations/
│   ├── express/
│   │   ├── context.ts   # Request context extraction
│   │   ├── middleware.ts # Auth middleware
│   │   ├── routes.ts    # Auth routes
│   │   └── index.ts     # Express exports
│   └── client/
│       ├── auth-client.ts # Client SDK
│       ├── react.ts     # React hooks
│       └── index.ts     # Client exports
└── testing/
    ├── mocks.ts         # Mock implementations
    ├── helpers.ts       # Test utilities
    └── index.ts         # Testing exports
```

### Integration Patterns

| Framework | Pattern |
|-----------|---------|
| Express.js | Middleware + Route handlers |
| Fastify | Plugin + Decorators |
| Hono | Middleware |
| Next.js | API routes + Middleware |
| React | Context + Hooks |
| Vue | Composables + Plugin |
| Angular | Service + Guards |

### Key Takeaways

- Framework integrations are thin wrappers around AuthService
- Client SDK handles token storage and auto-refresh
- Testing utilities make it easy to write comprehensive tests
- Same patterns can be adapted to any framework

### Next Steps

In **Part 10: Production Readiness**, we'll cover:
- Security audit checklist
- Performance optimization
- Monitoring and logging
- Deployment considerations
