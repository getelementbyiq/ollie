# Firebase Authentication Setup for UNDER Dispatch Fork

This fork of Ollie TMS uses Firebase Authentication instead of the native password system. See [`FORK.md`](FORK.md) for the full list of changes.

## Quick Start

### 1. Environment Variables

Add these to your `.env` or `docker-compose.yml`:

```bash
# Firebase (required)
FIREBASE_PROJECT_ID=your-project-id
FIREBASE_API_KEY=your-web-api-key
FIREBASE_AUTH_DOMAIN=your-project.firebaseapp.com
FIREBASE_APP_ID=1:123456789:web:abcdef

# Bootstrap owner (optional, one-time use)
OLLIE_BOOTSTRAP_OWNER_EMAIL=owner@under.kg

# Existing Ollie secrets (still required)
DRIVER_JWT_SECRET=your-32+-byte-secret
FLEET_JWT_SECRET=your-32+-byte-secret
DRIVER_RP_ID=localhost  # Unused but required
DRIVER_RP_ORIGIN=http://localhost:3000  # Unused but required
OLLIE_PUBLIC_BASE_URL=https://dispatch.under.kg
# ... plus DATA_DIR, OLLAMA_*, etc.
```

### 2. Firebase Console Setup

1. Go to https://console.firebase.google.com
2. Select your project (or create one)
3. **Authentication** → **Sign-in method**:
   - Enable **Google** provider
   - Enable **Email/Password** provider
   - (Optional) Enable **Phone** provider for driver phone auth
4. **Authentication** → **Settings** → **Authorized domains**:
   - Add `dispatch.under.kg` (or your domain)
   - `localhost` is pre-authorized for development

**No service account credentials needed** — the server verifies Firebase ID tokens via Google's public JWKS.

### 3. First Deployment

**Bootstrap the owner account:**

1. Set `OLLIE_BOOTSTRAP_OWNER_EMAIL` to the owner's Firebase email
2. Deploy the server
3. Navigate to `https://dispatch.under.kg/fleet/`
4. Sign in with Firebase using that email
5. The server auto-creates the owner account on first login
6. **Remove** `OLLIE_BOOTSTRAP_OWNER_EMAIL` from env after success

**Without the bootstrap email set:** the first Firebase user to log in will be rejected (unknown email). You must add users through the owner's account.

### 4. Add More Users

1. Log in as owner
2. Navigate to **User Management** in the fleet UI
3. Add users by **email only** (no passwords)
4. Users sign in via Firebase with that email
5. Assign roles (Owner, FleetManager, Dispatcher, etc.) as needed

### 5. Driver Setup

Drivers sign in via Firebase instead of PIN/passkey:

1. Driver records must have an `email` field (and optionally `phone` for phone auth)
2. Drivers navigate to `https://dispatch.under.kg/driver/`
3. Sign in with Firebase (email or phone)
4. The server maps to the driver record by email or phone

**Driver PWA still works:** remains installable on mobile devices.

### 6. E-Learning Section

A new protected `/elearning` section serves training materials:

- **URL:** `https://dispatch.under.kg/elearning/`
- **Auth:** Firebase login → 24-hour session cookie
- **Content:** Russian dispatch training guide (expandable)
- **To add more:** Place HTML/assets in `static/elearning/index.html`

Access from the fleet UI: **E-Learning** link in the sidebar nav.

## API Authentication

### Fleet Portal

**Human users:** Firebase ID token in `Authorization: Bearer <firebase-token>` header.

**Machine clients (MCP, scripts):** API keys still work:
```bash
curl -H "Authorization: Bearer olld_..." https://dispatch.under.kg/fleet/api/v1/loads
```

Create API keys in the fleet UI under **Account → API Keys**.

### Driver Portal

**Human drivers:** Firebase ID token only.

**No API keys for drivers** — the driver surface is mobile-app only.

### OAuth for MCP (Claude, etc.)

The OAuth flow for MCP clients (`POST /fleet/mcp`) works unchanged, but human consent steps now use Firebase sign-in instead of Ollie passwords.

## Development

### Local Development

```bash
# Set Firebase test project credentials
export FIREBASE_PROJECT_ID=test-project-dev
export FIREBASE_API_KEY=test-key
export FIREBASE_AUTH_DOMAIN=test-project-dev.firebaseapp.com
export FIREBASE_APP_ID=1:test:web:test

# Other required vars
export DRIVER_JWT_SECRET=dev-secret-32-bytes-or-longer!
export FLEET_JWT_SECRET=dev-fleet-secret-32-bytes!!
export DRIVER_RP_ID=localhost
export DRIVER_RP_ORIGIN=http://localhost:3000

# Run
cargo run
```

Access at:
- Fleet: http://localhost:3000/fleet/
- Driver: http://localhost:3000/driver/
- E-Learning: http://localhost:3000/elearning/

### Testing

```bash
# Unit tests (includes Firebase JWKS verification tests)
cargo test

# Firebase-specific tests only
cargo test firebase
```

The Firebase tests use locally-generated RSA keys (no real Firebase project needed).

## Production Deployment

### Docker

**Build from this branch:**

```bash
git clone https://github.com/getelementbyiq/ollie
cd ollie
git checkout cursor/firebase-auth-9e81
docker build -t dispatch-under:firebase .
```

**Run:**

```bash
docker run -d \
  -p 3000:3000 \
  -v $(pwd)/data:/data \
  -e FIREBASE_PROJECT_ID=your-project \
  -e FIREBASE_API_KEY=your-key \
  -e FIREBASE_AUTH_DOMAIN=your-project.firebaseapp.com \
  -e FIREBASE_APP_ID=1:123:web:abc \
  -e OLLIE_BOOTSTRAP_OWNER_EMAIL=owner@under.kg \
  -e DRIVER_JWT_SECRET=your-secret \
  -e FLEET_JWT_SECRET=your-secret \
  -e DRIVER_RP_ID=localhost \
  -e DRIVER_RP_ORIGIN=http://localhost:3000 \
  -e OLLIE_PUBLIC_BASE_URL=https://dispatch.under.kg \
  dispatch-under:firebase
```

**Docker Compose:**

```yaml
services:
  ollie:
    image: dispatch-under:firebase
    ports:
      - "3000:3000"
    volumes:
      - ./data:/data
    environment:
      FIREBASE_PROJECT_ID: your-project
      FIREBASE_API_KEY: your-key
      FIREBASE_AUTH_DOMAIN: your-project.firebaseapp.com
      FIREBASE_APP_ID: 1:123:web:abc
      OLLIE_BOOTSTRAP_OWNER_EMAIL: owner@under.kg  # Remove after first login
      DRIVER_JWT_SECRET: your-secret
      FLEET_JWT_SECRET: your-secret
      DRIVER_RP_ID: localhost
      DRIVER_RP_ORIGIN: http://localhost:3000
      OLLIE_PUBLIC_BASE_URL: https://dispatch.under.kg
      # ... plus OLLAMA_*, ORS_API_KEY, etc.
    restart: unless-stopped
```

### Behind Caddy/Nginx

The server expects to run behind a reverse proxy at `OLLIE_PUBLIC_BASE_URL`. Example Caddyfile:

```
dispatch.under.kg {
    reverse_proxy localhost:3000
}
```

## Troubleshooting

### "Invalid Firebase token or user not found"

**Cause:** The email from the Firebase token doesn't match any fleet_user or driver record.

**Fix:**
- For fleet users: Log in as owner, add the user by email in User Management
- For drivers: Ensure the driver record has the correct `email` field set
- For bootstrap: Verify `OLLIE_BOOTSTRAP_OWNER_EMAIL` matches the Firebase email exactly

### "Authentication failed" on /elearning

**Cause:** Session cookie missing or expired (24-hour TTL).

**Fix:** Sign in again at `/elearning/login`.

### Firebase popup blocked

**Cause:** Browser blocking pop-up windows.

**Fix:** Allow popups for `dispatch.under.kg` in browser settings.

### "Unauthorized domain"

**Cause:** The domain is not authorized in Firebase Console.

**Fix:** Add your domain to **Authentication → Settings → Authorized domains**.

## Security Notes

- **Firebase tokens are short-lived** (1 hour by default). The Firebase SDK refreshes them automatically.
- **Session cookies for /elearning are HttpOnly and SameSite=Lax** — not accessible to JavaScript.
- **API keys remain bearer tokens** — protect them like passwords. Rotate them in the fleet UI.
- **No passwords stored** — Firebase handles all credential storage.
- **OLLIE_BOOTSTRAP_OWNER_EMAIL is a first-run escape hatch only** — remove it after the owner account is created.

## Migration from Upstream Ollie

If you have an existing Ollie deployment with password-based logins:

1. **Back up your data** (`./data` directory).
2. **Note existing user emails** from the fleet user table.
3. **Deploy the Firebase fork** with `OLLIE_BOOTSTRAP_OWNER_EMAIL` set to an existing owner's email.
4. **Owner logs in via Firebase** — the existing record is reused (matched by email).
5. **Other users log in via Firebase** — they must already exist in the `fleet_user` table with the correct email.
6. **Existing driver PIN/passkey data is unused** — drivers must switch to Firebase.

**No data loss:** All fleet_user and driver records remain intact. Only the authentication method changes.

## License

This fork preserves the original AGPL-3.0 license. See [`FORK.md`](FORK.md) for attribution details.
