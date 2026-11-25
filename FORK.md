# UNDER Dispatch Fork of Ollie TMS

This is a modified fork of the open-source [Ollie TMS](https://github.com/olliefms/ollie) by olliefms, licensed under AGPL-3.0.

**Upstream:** https://github.com/olliefms/ollie  
**Base version:** v2.10.0  
**License:** AGPL-3.0 (preserved from upstream)

## Modifications

This fork replaces Ollie's native authentication system with Firebase Authentication for integration with UNDER's existing authentication infrastructure. Changes are intentionally contained to minimize merge conflicts with future upstream updates.

### Authentication Changes

**Fleet Portal (`/fleet`):**
- Replaced email/password login with Firebase ID token verification
- Removed first-run setup wizard (`/fleet/setup`) — bootstrap owner via `OLLIE_BOOTSTRAP_OWNER_EMAIL` env var
- Removed password reset flows
- **Kept:** API key authentication for machine clients (MCP, scripts)
- Server verifies Firebase ID tokens via Google's public JWKS (no service account required)
- Users are mapped to existing `fleet_user` records by email
- Unknown emails are rejected with clear error message

**Driver PWA (`/driver`):**
- Replaced PIN/passkey authentication with Firebase
- Drivers map to existing driver records by email (and phone if Firebase phone auth is used)
- Remains an installable PWA

**OAuth for MCP:**
- Kept non-interactive auth (API keys, existing OAuth for Claude/MCP clients)
- Human consent steps now use Firebase sign-in instead of Ollie passwords

**New: `/elearning` Section:**
- Protected static content requiring Firebase authentication
- Uses secure HttpOnly session cookies (24-hour TTL) for browser navigation
- Serves Russian dispatch training materials at `https://dispatch.under.kg/elearning/`
- Server-side protection: unauthenticated requests redirect to Firebase login
- Easily extensible: add more HTML/assets to `static/elearning/`

### Implementation Details

**Key files modified:**
- `src/firebase.rs` — New: Firebase ID token verification via JWKS
- `src/config.rs` — Added Firebase env vars (`FIREBASE_PROJECT_ID`, `FIREBASE_API_KEY`, `FIREBASE_AUTH_DOMAIN`, `FIREBASE_APP_ID`, `OLLIE_BOOTSTRAP_OWNER_EMAIL`)
- `src/lib.rs` — Added `FirebaseAuth` to `AppState`, added `elearning_sessions` store
- `src/api/fleet_portal/auth.rs` — Firebase login replaces password login
- `src/api/fleet_portal/middleware.rs` — Verifies Firebase tokens (falls back to Ollie JWT for API keys)
- `src/api/driver_portal/auth.rs` — Firebase login replaces PIN/passkey
- `src/api/driver_portal/middleware.rs` — Verifies Firebase tokens
- `src/api/elearning.rs` — New: `/elearning` routes with cookie-based session auth
- `static/elearning/` — New: Protected training content (Russian dispatch guide)
- `static/fleet/pages/login-firebase.js` — New: Firebase SDK integration for fleet UI
- `Cargo.toml` — Added `rsa` dev-dependency for Firebase tests

**Preserved for upstream merge compatibility:**
- Database schema unchanged
- Core business logic (loads, trips, facilities, etc.) unchanged
- API surface mostly unchanged (login request/response shapes differ)
- Blob storage, AI pipeline, MCP server unchanged

### Configuration

Required environment variables (in addition to upstream Ollie's variables):

```bash
# Firebase Configuration (required)
FIREBASE_PROJECT_ID=your-project-id
FIREBASE_API_KEY=your-public-api-key
FIREBASE_AUTH_DOMAIN=your-project.firebaseapp.com
FIREBASE_APP_ID=1:123456789:web:abcdef

# Bootstrap owner (optional, only used when no fleet users exist)
OLLIE_BOOTSTRAP_OWNER_EMAIL=owner@example.com

# Existing Ollie vars still required
DRIVER_JWT_SECRET=... # 32+ bytes
FLEET_JWT_SECRET=... # 32+ bytes
DRIVER_RP_ID=localhost # (unused with Firebase, but still required by config)
DRIVER_RP_ORIGIN=http://localhost:3000 # (unused with Firebase, but still required by config)
OLLIE_PUBLIC_BASE_URL=https://dispatch.under.kg
# ... plus DATA_DIR, OLLAMA_*, ORS_API_KEY, etc.
```

### Deployment Steps

1. **Build the Docker image from this branch:**
   ```bash
   git clone https://github.com/getelementbyiq/ollie
   cd ollie
   git checkout cursor/firebase-auth-9e81
   docker build -t dispatch-under:latest .
   ```

2. **Update `docker-compose.yml`:**
   ```yaml
   services:
     ollie:
       image: dispatch-under:latest  # Instead of ghcr.io/olliefms/ollie:2.10.0
       environment:
         FIREBASE_PROJECT_ID: "your-project-id"
         FIREBASE_API_KEY: "your-public-api-key"
         FIREBASE_AUTH_DOMAIN: "your-project.firebaseapp.com"
         FIREBASE_APP_ID: "1:123456789:web:abcdef"
         OLLIE_BOOTSTRAP_OWNER_EMAIL: "owner@under.kg"  # First-time only
         # ... existing vars
   ```

3. **Configure Firebase Console** (https://console.firebase.google.com):
   - **Enable sign-in providers:** Google, Email/Password, (optionally Phone)
   - **Add authorized domain:** `dispatch.under.kg`
   - **No service account secret needed** — the server verifies tokens via public JWKS

4. **Deploy:**
   ```bash
   docker-compose down
   docker-compose up -d
   ```

5. **Bootstrap the owner** (first deployment only):
   - Set `OLLIE_BOOTSTRAP_OWNER_EMAIL` to the owner's Firebase email
   - Sign in via Firebase with that email
   - The server auto-creates the owner account on first login
   - Remove the env var after first successful login

6. **Add more fleet users:**
   - Log in as owner
   - Navigate to User Management in the fleet UI
   - Add users by email (no passwords — they sign in via Firebase)

### Risks & Considerations

- **Breaking change:** Existing password-based logins no longer work. All users must switch to Firebase.
- **Existing data preserved:** No destructive migrations. Driver/fleet user records stay intact.
- **Upstream merges:** Auth changes are isolated, but future upstream auth updates will conflict. Recommend keeping this branch as a long-lived fork rather than attempting to merge upstream auth changes.
- **Dependency on Firebase:** Outage of Google's authentication service affects login (but not API keys).
- **Session cookies for /elearning:** 24-hour TTL, stored in-memory. Server restart clears all sessions.

### Testing

The Firebase verification module includes unit tests with locally-generated RSA keys:
```bash
cargo test firebase
```

Integration tests use test Firebase credentials and are skipped by default (require real Firebase project setup).

### License & Attribution

This fork preserves the original AGPL-3.0 license. All modifications are also AGPL-3.0.

**Original work:** Copyright © olliefms contributors  
**Fork modifications:** Copyright © 2026 UNDER  

As required by AGPL-3.0: this modified version's source code is available at https://github.com/getelementbyiq/ollie (branch `cursor/firebase-auth-9e81`), and any network users of this modified software can access the complete corresponding source.
