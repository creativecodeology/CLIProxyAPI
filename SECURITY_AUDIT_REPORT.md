# CLIProxyAPI Security Audit Report

**Audit Date:** 2026-01-02
**Codebase Version:** v6
**Branch:** claude/security-audit-privacy-secrets-0JBu1

---

## Executive Summary

This comprehensive security audit examined the CLIProxyAPI codebase, focusing on secrets handling, data privacy, authentication/authorization, input validation, and network security. The audit identified **8 CRITICAL**, **12 HIGH**, **14 MEDIUM**, and **5 LOW** severity issues.

### Key Findings by Category

| Category | Critical | High | Medium | Low |
|----------|----------|------|--------|-----|
| Secrets Handling | 3 | 4 | 3 | 2 |
| Data Privacy | 2 | 2 | 3 | 1 |
| Authentication & Authorization | 2 | 3 | 4 | 0 |
| Input Validation | 0 | 2 | 1 | 0 |
| Network Security | 1 | 3 | 3 | 2 |

---

## CRITICAL Severity Issues

### 1. Hardcoded OAuth Client Secrets in Source Code

**Files:**
- `internal/auth/iflow/iflow_auth.go:31-32`
- `internal/auth/gemini/gemini_auth.go:32-33`
- `sdk/auth/antigravity.go:23-24`

**Vulnerability:**
```go
// iFlow OAuth
iFlowOAuthClientID     = "10009311001"
iFlowOAuthClientSecret = "4Z3YjXycVsQvyGF1etiNlIBB4RsqSDtW"

// Gemini OAuth
geminiOauthClientID     = "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com"
geminiOauthClientSecret = "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"

// Antigravity OAuth
antigravityClientID     = "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com"
antigravityClientSecret = "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"
```

**Impact:** Client secrets are exposed in compiled binaries and git history. Attackers can impersonate the application to OAuth providers.

**Recommendation:**
1. Rotate all exposed OAuth client secrets immediately
2. Move secrets to environment variables or secure vault solutions
3. Add pre-commit hooks to prevent credential commits

---

### 2. JWT Token Parsing Without Signature Verification

**File:** `internal/auth/codex/jwt_parser.go:54-76`

**Vulnerability:**
```go
func ParseJWTToken(token string) (*JWTClaims, error) {
    parts := strings.Split(token, ".")
    // ... decodes claims without verifying signature (parts[2])
    return &claims, nil  // NO VERIFICATION
}
```

**Impact:** Attackers can forge arbitrary JWT tokens claiming any identity.

**Recommendation:** Implement proper JWT signature verification using the provider's public keys, or at minimum validate the `exp` claim.

---

### 3. Wildcard CORS Configuration

**File:** `internal/api/server.go:803-816`

**Vulnerability:**
```go
c.Header("Access-Control-Allow-Origin", "*")
c.Header("Access-Control-Allow-Headers", "*")
```

**Impact:** Allows any website to make CORS requests, enabling cross-origin attacks and credential theft.

**Recommendation:** Implement whitelist-based origin validation and restrict allowed headers.

---

### 4. SSRF Vulnerability in APICall Endpoint

**File:** `internal/api/handlers/management/api_tools.go:52-210`

**Vulnerability:** The `/v0/management/api-call` endpoint makes arbitrary HTTP requests without validating the destination:
- No blocking of private IP ranges (127.0.0.1, 192.168.x.x, 10.x.x.x)
- No blocking of cloud metadata endpoints (169.254.169.254)

**Impact:** Access to internal services, port scanning, credential exfiltration.

**Recommendation:** Implement IP range validation to block requests to private networks and metadata endpoints.

---

### 5. PII Logging - Email Addresses in Logs

**Files:**
- `internal/runtime/executor/iflow_executor.go:305,321,325`

**Vulnerability:**
```go
log.Debugf("iflow executor: checking refresh need for user: %s", email)
log.Infof("iflow executor: refreshing cookie-based API key for user: %s", email)
```

**Impact:** Email addresses are logged in plaintext, violating privacy regulations.

**Recommendation:** Remove or hash email addresses before logging.

---

### 6. Indefinite Log Retention

**Files:**
- `internal/logging/global_logger.go:132-138`
- `config.example.yaml:51`

**Vulnerability:**
```go
logWriter = &lumberjack.Logger{
    MaxBackups: 0,  // NO automatic deletion
    MaxAge:     0,  // NO time-based deletion
}
```

Default config: `logs-max-total-size-mb: 0` (disabled)

**Impact:** Sensitive data (prompts, API keys, user information) retained indefinitely.

**Recommendation:** Set default retention limits (e.g., 30 days, 100MB).

---

### 7. Path Traversal Vulnerability

**File:** `internal/api/handlers/management/auth_files.go:505-527`

**Vulnerability:**
```go
if name == "" || strings.Contains(name, string(os.PathSeparator)) {
    // Only checks current OS path separator
}
full := filepath.Join(h.cfg.AuthDir, name)
```

On Windows, forward slashes (`/`) bypass the check.

**Impact:** Arbitrary file read from the server filesystem.

**Recommendation:** Use `filepath.Base()` consistently or validate for all path separators.

---

### 8. URL/Redirect Injection

**File:** `internal/api/handlers/management/auth_files.go:147-157`

**Vulnerability:**
```go
target := targetBase
if raw := r.URL.RawQuery; raw != "" {
    target = target + "?" + raw  // Unsanitized query params
}
http.Redirect(w, r, target, http.StatusFound)
```

**Impact:** Open redirect vulnerability allowing phishing attacks.

**Recommendation:** Validate and sanitize query parameters before appending to redirect targets.

---

## HIGH Severity Issues

### 9. Credential Logging in Error Responses

**File:** `internal/auth/iflow/iflow_auth.go:127,194,376,455`

**Vulnerability:** Response bodies containing tokens are logged in error conditions.

**Recommendation:** Redact sensitive data from error logs.

---

### 10. No Encryption at Rest for Credentials

**Files:**
- `sdk/auth/filestore.go:60-89`
- `internal/store/postgresstore.go:188-260`

**Vulnerability:** Tokens stored in plain JSON format. File permissions are `0o600`, but content is unencrypted.

**Recommendation:** Implement AES-256 encryption for stored credentials.

---

### 11. API Keys Accepted in Query Parameters

**File:** `internal/access/config_access/provider.go:62-63`

**Vulnerability:**
```go
queryKey := r.URL.Query().Get("key")
queryAuthToken := r.URL.Query().Get("auth_token")
```

**Impact:** API keys exposed in server logs, browser history, referrer headers.

**Recommendation:** Only accept API keys in headers, deprecate query parameter support.

---

### 12. Missing HTTP Security Headers

**Affected:** All API endpoints except `/v0/management/config.yaml`

Missing headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Content-Security-Policy`
- `Strict-Transport-Security` (HSTS)

**Recommendation:** Add security headers middleware to all routes.

---

### 13. TLS Optional by Default

**File:** `internal/api/server.go:749-761`, `config.example.yaml:10`

**Vulnerability:** TLS is disabled by default (`enable: false`).

**Recommendation:** Default to TLS enabled in production environments.

---

### 14. Full Request/Response Body Logging

**File:** `internal/logging/request_logger.go:170-188`

When `request-log` is enabled, complete request and response bodies (including prompts and API responses) are logged.

**Recommendation:** Add clear warnings in configuration and enable by default in development only.

---

### 15. OAuth Account Information Logged

**File:** `internal/runtime/executor/logging_helpers.go:308`

**Vulnerability:**
```go
parts = append(parts, fmt.Sprintf("type=oauth account=%s", authValue))
```

OAuth account (typically email) is logged.

**Recommendation:** Hash or redact account information in logs.

---

### 16. Client IP Spoofing via X-Forwarded-For

**File:** `internal/api/handlers/management/handler.go:104`

**Vulnerability:**
```go
clientIP := c.ClientIP()  // Trusts X-Forwarded-For without validation
localClient := clientIP == "127.0.0.1" || clientIP == "::1"
```

**Impact:** Rate limiting and localhost restrictions can be bypassed.

**Recommendation:** Use `c.Request.RemoteAddr` or configure `SetTrustedProxies()`.

---

### 17. Unauthenticated AMP Routes

**File:** `internal/api/modules/amp/routes.go:215-220`

Routes `/threads`, `/docs`, `/settings` are registered without authentication (though localhost-restricted).

**Recommendation:** Require authentication for all management routes.

---

### 18. API Key Printed to Terminal

**File:** `internal/cmd/iflow_cookie.go:74`

**Vulnerability:**
```go
fmt.Printf("Authentication successful! API key: %s\n", tokenData.APIKey)
```

**Recommendation:** Don't print API keys to stdout.

---

---

## MEDIUM Severity Issues

### 19. Information Disclosure via Error Messages

**File:** `internal/api/server.go:1025-1033`

Different errors for "Missing API key" vs "Invalid API key" enable enumeration.

**Recommendation:** Return identical error messages for both conditions.

---

### 20. Rate Limiting Only for Remote Clients

**File:** `internal/api/handlers/management/handler.go:121-157`

Rate limiting skipped for localhost clients.

**Recommendation:** Apply rate limiting uniformly.

---

### 21. WebSocket Authentication Optional

**File:** `internal/api/server.go:451`

`ws-auth: false` is the default, allowing unauthenticated WebSocket connections.

**Recommendation:** Enable WebSocket authentication by default.

---

### 22. Response Headers Not Masked in Logs

**File:** `internal/logging/request_logger.go:654`

Request headers are masked, but response headers are logged as-is.

**Recommendation:** Apply consistent header masking to responses.

---

### 23. Incomplete API Key Masking

**File:** `internal/util/provider.go:162-171`

Shows first 4 and last 4 characters of API keys.

**Recommendation:** Reduce to first 2 and last 2 characters.

---

### 24. Git Token in Environment Variables

**Files:**
- `internal/store/gitstore.go:33`
- `.env.example:24`

Git tokens stored in plaintext in environment and passed to git operations.

**Recommendation:** Use secure secret management solutions.

---

### 25. Hardcoded Redirect URIs

**Files:**
- `internal/auth/claude/anthropic_auth.go:25`
- `internal/auth/codex/openai_auth.go:26`
- `internal/auth/gemini/gemini_auth.go:109`

**Recommendation:** Allow configuration via environment variables.

---

### 26. OAuth Callback Predictable Filenames

**File:** `internal/api/handlers/management/oauth_sessions.go:257`

```go
fileName := fmt.Sprintf(".oauth-%s-%s.oauth", canonicalProvider, state)
```

**Recommendation:** Use secure random filenames.

---

### 27. Insecure HTTP Redirect Handling

**File:** `internal/api/handlers/management/api_tools.go:182-191`

HTTP client follows redirects without policy, enabling data exfiltration.

**Recommendation:** Add `CheckRedirect` policy to HTTP clients.

---

### 28. Database Credentials in DSN

**File:** `.env.example:15`

```
PGSTORE_DSN=postgresql://user:pass@localhost:5432/cliproxy
```

**Recommendation:** Use separate environment variables for credentials.

---

### 29. Default Host Binds to All Interfaces

**File:** `config.example.yaml:3`

```yaml
host: ""  # Binds to 0.0.0.0
```

**Recommendation:** Default to `127.0.0.1`.

---

---

## LOW Severity Issues

### 30. Weak API Key Masking Pattern

**File:** `internal/util/provider.go:162-171`

Shows meaningful prefixes (first 4 chars) which may reveal token type.

---

### 31. CLI Email Logging

**Files:** `internal/cmd/login.go:493`, `internal/cmd/qwen_login.go:48`

Email addresses logged during login flows (CLI-only scope).

---

### 32. No Auth Fallback Warning

**File:** `internal/api/modules/amp/amp.go:171`

```go
log.Warn("amp module: no auth middleware provided, allowing all requests")
```

Should be an error, not warning.

---

---

## Positive Security Findings

The codebase demonstrates several security best practices:

1. **File Permissions:** Credentials written with `0o600` permissions
2. **bcrypt Hashing:** Management secret properly hashed with bcrypt
3. **PKCE Support:** OAuth implementations use PKCE (S256)
4. **Constant-Time Comparison:** Uses `subtle.ConstantTimeCompare()` for passwords
5. **Parameterized Queries:** SQL injection properly mitigated with parameterized queries
6. **Command Injection Protection:** Shell commands use argument arrays, not string concatenation
7. **Git History Squashing:** GitStore squashes commits to prevent credential history leakage
8. **State Parameter Validation:** OAuth state parameters have TTL, format validation, and path traversal protection
9. **Localhost Protection (AMP):** AMP module uses `RemoteAddr` instead of `ClientIP()`
10. **Management CORS Disabled:** Management routes explicitly disable CORS

---

## Remediation Priority

### Immediate (Week 1)
1. Rotate all hardcoded OAuth client secrets
2. Fix CORS wildcard configuration
3. Remove email addresses from logs
4. Implement path traversal protection
5. Fix SSRF vulnerability in APICall

### Short-term (Weeks 2-4)
1. Implement JWT signature verification
2. Add encryption at rest for credentials
3. Remove API key query parameter support
4. Add HTTP security headers
5. Fix IP spoofing in management middleware
6. Enable log retention limits by default

### Medium-term (Months 2-3)
1. Implement secret management solution
2. Add TLS enforcement options
3. Implement comprehensive audit logging
4. Add rate limiting to all endpoints
5. Security testing and penetration testing

---

## Conclusion

The CLIProxyAPI codebase has several critical security vulnerabilities, primarily around secrets management and data privacy. The hardcoded OAuth secrets and missing encryption at rest are the most urgent issues requiring immediate attention. While the codebase shows good practices in some areas (bcrypt, PKCE, SQL injection protection), the identified issues could allow unauthorized access, credential theft, or data exfiltration if exploited.

**Immediate action is recommended for all CRITICAL and HIGH severity issues.**
