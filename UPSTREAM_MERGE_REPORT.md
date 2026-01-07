# Upstream Merge Report - boxboat/okta-nginx

**Date**: December 16, 2025  
**Commits Merged**: 61 commits  
**Version Range**: 511b272 → 91920a6

## Executive Summary

This merge brings in **substantial improvements and modernization** from the upstream repository. The changes include major version updates, architectural improvements, new features, and better configuration management. The codebase has been significantly refactored with 1,010 additions and 9,530 deletions (net reduction due to vendor directory cleanup).

---

## 🔄 Dependency Management - CRITICAL CHANGE

### Migration from Dep to Go Modules
- **REMOVED**: `Gopkg.lock` and `Gopkg.toml` (old Go dependency tool)
- **ADDED**: `go.mod` and `go.sum` (modern Go modules)
- **REMOVED**: Entire `vendor/` directory (9,000+ lines removed)
- Dependencies now managed via Go modules standard

### Updated Dependencies
- **Okta JWT Verifier**: Upgraded to `v2.1.0` (from v1.x)
- **Masterminds/sprig**: Now at `v3.3.0` (template functions)
- **lestrrat-go/jwx**: Upgraded to `v2.0.21` (JWT/JWX library)
- **Security patch**: `golang.org/x/crypto` updated to `0.31.0`

---

## 🐳 Docker & Infrastructure Updates

### Version Upgrades
- **Go**: `1.10.3` → `1.23.4` (major version jump - 13 versions!)
- **Alpine**: `3.8` → `3.21`
- **Nginx**: `1.14.0` → `1.26.2`

### Dockerfile Improvements
- Added `CGO_ENABLED=0` for static binary compilation
- Added `curl` and `jq` tools to runtime image
- Updated build paths to use `/root/okta-nginx` instead of GOPATH structure

### CI/CD - GitHub Actions
**NEW FILE**: `.github/workflows/docker.yaml`
- Automated Docker image builds on push to develop, master, and tags
- **Images now published to GitHub Container Registry (ghcr.io)**
- **No longer publishing to Docker Hub** (breaking change for deployment)
- Automatic tagging: branch commits, version tags, and latest
- Multi-platform build support using buildx

---

## 🎯 Major Feature Additions

### 1. **ID Token Instead of Access Token** (Breaking Change)
- **Changed from Access Token to ID Token** for authentication
- This is a fundamental change in the OAuth2 flow implementation
- Better suited for user authentication (ID tokens contain user claims)
- Access tokens are now only used internally

### 2. **Multiple Server Support**
- Can now configure multiple NGINX server blocks
- Use numbered environment variables: `_2`, `_3`, etc.
- Each server can have independent:
  - `LISTEN_N`, `SERVER_NAME_N`, `PROXY_PASS_N`
  - `LOCATIONS_PROTECTED_N`, `LOCATIONS_UNPROTECTED_N`
  - `LOGIN_REDIRECT_URL_N`, `COOKIE_DOMAIN_N`, `COOKIE_NAME_N`
  - `PROXY_SET_HEADER_NAMES_N`, `PROXY_SET_HEADER_VALUES_N`
  - `VALIDATE_CLAIMS_TEMPLATE_N`

### 3. **Protected vs Unprotected Locations**
**NEW TEMPLATES**: 
- `stage/etc/nginx/templates/proxy-pass-protected.conf`
- `stage/etc/nginx/templates/proxy-pass-unprotected.conf`

Environment Variables:
- `LOCATIONS_PROTECTED` - Comma-separated list (defaults to `/`)
- `LOCATIONS_UNPROTECTED` - Comma-separated list for public paths
- Allows mixed public/private content on same server

### 4. **Custom Header Injection from JWT Claims**
- `PROXY_SET_HEADER_NAMES` - Comma-separated header names
- `PROXY_SET_HEADER_VALUES` - Go template expressions against claims
- Example: Pass user groups to backend: `{{.groups}}`
- Enables claim-based header forwarding to upstream servers

### 5. **Claims Validation with Go Templates**
- `VALIDATE_CLAIMS_TEMPLATE` - Go template that must return "true" or "1"
- Uses Sprig template functions for complex logic
- Example: `{{if or (has "default" .groups) (has "admin" .groups)}}true{{else}}false{{end}}`
- More flexible than previous boolean claim validation

### 6. **Configurable OAuth Scopes**
- `AUTH_SCOPE` - Defaults to `openid profile`
- Allows customization of scopes requested from Okta
- Must include `openid` for authentication to work

### 7. **Custom Endpoint Configuration**
- `ENDPOINT_AUTHORIZE` - Override authorization endpoint
- `ENDPOINT_TOKEN` - Override token endpoint  
- `ENDPOINT_LOGOUT` - Override logout endpoint
- Defaults to `${ISSUER}/v1/{authorize,token,logout}`
- Enables custom authorization server configurations

### 8. **Logout Functionality**
- **NEW**: Logout endpoint at `/sso/logout` (or `${SSO_PATH}/logout`)
- `LOGOUT_REDIRECT_URL` - Where to redirect after logout
- Properly clears cookies and redirects to Okta logout

### 9. **Dynamic Configuration Updates**
- `UPDATE_SCRIPT` - Path to executable script for config updates
- `UPDATE_PERIOD_SECONDS` - How often to run update script (default: 60)
- Enables dynamic config refresh without container restart
- Script receives `true` on first run, `false` on subsequent runs

### 10. **Post-Login URL Redirect**
- `APP_POST_LOGIN_URL` - Redirect to app-specific URL after auth
- Original URL preserved in `state` query parameter
- Useful for custom post-authentication flows

### 11. **Cookie Domain Configuration**
- `COOKIE_DOMAIN` - Set to enable cookies across subdomains
- Validates that redirect URLs match configured domain
- Prevents open redirect vulnerabilities

### 12. **WebSocket Support**
- Proper handling of WebSocket upgrade requests
- Connection upgrade headers properly forwarded
- Maintains authentication for WebSocket connections

---

## 🔒 Security & Proxy Improvements

### Enhanced Request Detection
**NEW FILE**: `stage/etc/nginx/conf.d/detect.conf`
- Smart detection of `X-Forwarded-*` headers
- Maps for: `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Port`, `X-Forwarded-Proto`
- Differentiates between trusted and untrusted sources
- Prevents header injection from untrusted clients

### Real IP Detection Updates
**UPDATED**: `stage/etc/nginx/conf.d/real-ip.conf`
- Improved trusted proxy detection
- Better handling of load balancer scenarios
- Added `X-Forwarded-Port` support

### Proxy Headers
**UPDATED**: `stage/etc/nginx/includes/proxy-headers.conf`
- Uses detected headers from trust mapping
- Proper WebSocket upgrade header handling
- Improved `X-Forwarded-User` handling

---

## 📝 Configuration & Environment Variables

### New Required Variables
- **`AUDIENCE`** - Audience for token validation (e.g., `api://default`)

### New Optional Variables (16 new options)
1. `APP_POST_LOGIN_URL` - Post-auth redirect
2. `AUTH_SCOPE` - OAuth scopes (default: `openid profile`)
3. `COOKIE_DOMAIN` - Multi-domain cookie support
4. `ENDPOINT_AUTHORIZE` - Custom authorization endpoint
5. `ENDPOINT_LOGOUT` - Custom logout endpoint
6. `ENDPOINT_TOKEN` - Custom token endpoint
7. `LOCATIONS_PROTECTED` - Protected location blocks
8. `LOCATIONS_UNPROTECTED` - Unprotected location blocks
9. `LOGOUT_REDIRECT_URL` - Post-logout redirect
10. `PROXY_SET_HEADER_NAMES` - Custom headers from claims
11. `PROXY_SET_HEADER_VALUES` - Header values (Go templates)
12. `REQUEST_TIMEOUT` - Increased default from 5 to 30 seconds
13. `SERVER_NAME` - NGINX server_name directive
14. `UPDATE_PERIOD_SECONDS` - Config refresh interval
15. `UPDATE_SCRIPT` - Dynamic config update script
16. `VALIDATE_CLAIMS_TEMPLATE` - Go template for claim validation

### Updated Variables
- `INJECT_REFRESH_JS` - Now refreshes **ID tokens** (was Access tokens)
- `COOKIE_NAME` - Now holds **ID Token** (was Authorization token)
- `LOGIN_REDIRECT_URL` - Must now include callback path (documented requirement)

---

## 🏗️ Architecture & Code Changes

### server.go - Major Refactor (531 lines changed)
Key improvements:
1. Switched from Access Tokens to ID Tokens
2. Added metadata endpoint discovery
3. Improved error handling and logging
4. Template caching for performance
5. Cookie domain validation
6. Logout handler implementation
7. Support for custom endpoints
8. Configurable OAuth scopes
9. Enhanced claim validation
10. Header injection from claims

### NGINX Configuration Generation
**NEW FILE**: `stage/usr/local/bin/generate.sh` (156 lines)
- Dynamically generates NGINX config from environment variables
- Supports multiple server configurations
- Template-based configuration system
- Handles protected/unprotected locations
- Generates custom header configurations

### Container Entrypoint Improvements
**UPDATED**: `stage/usr/local/bin/run.sh` (108 lines changed)
- Runs configuration generation at startup
- Monitors both `okta-nginx` and `nginx` processes
- Handles optional UPDATE_SCRIPT execution
- Periodic config refresh support
- Improved process management and error handling

### JavaScript Refresh Token Updates
**UPDATED**: `stage/var/okta-nginx/refresh.js` (51 lines changed)
- Now refreshes ID tokens instead of access tokens
- Improved timing and expiration handling
- Better error handling

---

## 🗑️ Removed Files/Features

### Vendor Directory (Completely Removed)
- All vendored dependencies removed (9,000+ lines)
- Now using Go modules for dependency management

### Removed Configuration Files
- `stage/etc/nginx/includes/default-server.conf` (deprecated)
- `stage/etc/nginx/includes/refresh-js.conf` (reorganized)

### Removed Template
- Old `proxy-pass.conf` split into protected/unprotected versions

---

## ⚠️ Breaking Changes & Migration Considerations

### 1. **Docker Image Location** ⚠️ CRITICAL
- **OLD**: Docker Hub (if you were using it)
- **NEW**: `ghcr.io/boxboat/okta-nginx`
- **Action Required**: Update deployment manifests/scripts

### 2. **Access Token → ID Token** ⚠️ IMPORTANT
- Backend services expecting access tokens will receive ID tokens
- Token claims structure may differ
- **Action Required**: Verify token validation in upstream services

### 3. **Okta JWT Verifier v1 → v2**
- Major library version upgrade
- API changes in JWT validation
- **Action Required**: Test authentication flow thoroughly

### 4. **New Required Environment Variable**
- `AUDIENCE` is now required
- **Action Required**: Add to your `vars.env` file

### 5. **Go Version Requirement**
- Minimum Go 1.23 for building from source
- **Action Required**: Update build environments

### 6. **Cookie Behavior Changes**
- Cookie now contains ID token instead of access token
- Cookie domain validation more strict
- **Action Required**: Test with your domain configuration

### 7. **REQUEST_TIMEOUT Default Change**
- Changed from 5 seconds to 30 seconds
- May affect timeouts in your environment
- **Action Required**: Adjust if needed for your use case

---

## ✅ Testing Recommendations

### Critical Tests Required
1. **Authentication Flow**
   - Test login/logout with your Okta configuration
   - Verify ID token is properly issued and validated
   - Check cookie persistence and domain settings

2. **Token Refresh**
   - Verify automatic token refresh (if `INJECT_REFRESH_JS=true`)
   - Test token expiration handling

3. **Multiple Server Configuration** (if using)
   - Test each server block independently
   - Verify cookie domains work across servers

4. **Protected vs Unprotected Locations** (if using)
   - Verify protected paths require authentication
   - Verify unprotected paths are accessible

5. **Custom Headers** (if using)
   - Test `PROXY_SET_HEADER_*` configuration
   - Verify claims are properly extracted and forwarded

6. **Claims Validation** (if using)
   - Test `VALIDATE_CLAIMS_TEMPLATE` with various users
   - Verify unauthorized users are properly blocked

7. **WebSocket Connections** (if using)
   - Test WebSocket upgrade with authentication

---

## 📋 Action Items

### Immediate (Before Deploying)
- [ ] Add `AUDIENCE` environment variable to configuration
- [ ] Update Docker image references to `ghcr.io/boxboat/okta-nginx`
- [ ] Review and test ID token vs access token change
- [ ] Update `vars.env` with new optional variables as needed
- [ ] Test authentication flow in staging environment

### Post-Deployment Monitoring
- [ ] Monitor authentication success/failure rates
- [ ] Check for token refresh issues
- [ ] Verify upstream services handle new token format
- [ ] Monitor REQUEST_TIMEOUT behavior (now 30s default)

### Optional Enhancements to Consider
- [ ] Implement `LOCATIONS_UNPROTECTED` for public paths
- [ ] Configure `PROXY_SET_HEADER_*` to pass claims to backend
- [ ] Set up `VALIDATE_CLAIMS_TEMPLATE` for authorization
- [ ] Configure multiple servers if needed
- [ ] Set up `UPDATE_SCRIPT` for dynamic config updates
- [ ] Configure custom logout redirect URL

---

## 📊 Statistics Summary

- **Total Commits**: 61
- **Files Changed**: 104
- **Lines Added**: 1,010
- **Lines Removed**: 9,530 (mostly vendor directory cleanup)
- **Net Change**: -8,520 lines (cleaner, more maintainable)
- **New Files**: 5 (workflows, templates, configs)
- **Removed Files**: 82 (all vendor dependencies)
- **Major Version Bumps**: Go, Nginx, Alpine, JWT libraries

---

## 🔗 Key Commit References

- **`4fddd00`** - Migration to Go modules (foundational change)
- **`4fe7432`** - Switch to ID Token and update script support
- **`101dbf8`** - Multiple servers support
- **`1c8017c`** - Protected/unprotected locations
- **`55c04e7`** - Custom header injection from claims
- **`0d70207`** - Go template-based claims validation
- **`91920a6`** - Latest: Publish to GHCR only

---

## 📚 Additional Resources

- Original Repository: https://github.com/boxboat/okta-nginx
- Docker Images: https://github.com/boxboat/okta-nginx/pkgs/container/okta-nginx
- Okta OIDC Documentation: https://developer.okta.com/docs/api/resources/oidc
- Sprig Template Functions: http://masterminds.github.io/sprig/

---

## ⚡ Quick Start for Updated Configuration

```bash
# Updated vars.env example
export AUDIENCE="api://default"                    # NEW - Required
export CLIENT_ID="xxxxxx"
export CLIENT_SECRET="xxxxx"
export COOKIE_DOMAIN="example.com"                 # NEW - Optional
export ISSUER="https://xxxxx.oktapreview.com/oauth2/default"
export LOGIN_REDIRECT_URL="http://localhost:8080/sso/authorization-code/callback"
export PROXY_PASS="http://upstream:8080"

# Optional new features
export LOCATIONS_PROTECTED="/, /api/*"             # NEW
export LOCATIONS_UNPROTECTED="/health, /public/*" # NEW
export PROXY_SET_HEADER_NAMES="X-User-Groups"     # NEW
export PROXY_SET_HEADER_VALUES="{{.groups}}"      # NEW
export VALIDATE_CLAIMS_TEMPLATE='{{if has "admin" .groups}}true{{else}}false{{end}}' # NEW
```

---

**Report Generated**: December 16, 2025  
**Merge Status**: ✅ Complete - No Conflicts  
**Next Step**: Review and push to origin/master


