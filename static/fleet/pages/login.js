import { saveToken } from '../utils/auth.js';
import { loadMe, API_BASE, AUTH_BASE } from '../utils/api.js';
import { clearEventsRefresh } from './events.js';

// ─── Firebase Integration ────────────────────────────────────

let firebaseApp = null;
let firebaseAuth = null;

async function initFirebase() {
  if (firebaseApp) return;
  
  // Fetch Firebase config from server
  const resp = await fetch(`${API_BASE}/firebase-config`);
  const config = await resp.json();
  
  // Dynamically import Firebase SDK
  const { initializeApp } = await import('https://www.gstatic.com/firebasejs/10.7.1/firebase-app.js');
  const { getAuth } = await import('https://www.gstatic.com/firebasejs/10.7.1/firebase-auth.js');
  
  firebaseApp = initializeApp({
    apiKey: config.api_key,
    authDomain: config.auth_domain,
    projectId: config.project_id,
    appId: config.app_id,
  });
  
  firebaseAuth = getAuth(firebaseApp);
}

// ─── View/Auth toggle ────────────────────────────────────────

export function showLogin() {
  document.getElementById('login-view').hidden = false;
  document.getElementById('app-shell').hidden = true;
  const loginPane = document.getElementById('login-pane');
  if (loginPane) loginPane.hidden = false;
  clearEventsRefresh();
}

export async function showLoginOrSetup() {
  // Firebase-based auth: no setup wizard, always show Firebase login
  showLogin();
}

export function showApp() {
  document.getElementById('login-view').hidden = true;
  document.getElementById('app-shell').hidden = false;
}

function showAlert(el, cls, msg) {
  el.className = `alert ${cls}`;
  el.textContent = msg;
  el.hidden = false;
}

// ─── Firebase Login ──────────────────────────────────────────
// `enterApp` is supplied by app.js (it owns the router/render dispatch).

export function initLoginForm(enterApp) {
  const btn = document.getElementById('firebase-signin-btn');
  if (!btn) return;

  btn.addEventListener('click', async () => {
    const alertEl = document.getElementById('login-alert');
    btn.disabled = true;
    btn.textContent = 'Signing in…';
    alertEl.hidden = true;

    try {
      await initFirebase();
      const { signInWithPopup, GoogleAuthProvider } = await import('https://www.gstatic.com/firebasejs/10.7.1/firebase-auth.js');
      
      const provider = new GoogleAuthProvider();
      const result = await signInWithPopup(firebaseAuth, provider);
      const idToken = await result.user.getIdToken();
      
      // Send Firebase token to server (server returns it as passthrough)
      const resp = await fetch(`${AUTH_BASE}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id_token: idToken }),
      });
      
      if (resp.ok) {
        const data = await resp.json();
        saveToken(data.token);
        await loadMe();
        enterApp();
        return;
      }

      if (resp.status === 401) {
        showAlert(alertEl, 'alert--error', 'Your email is not authorized. Contact your administrator.');
        return;
      }
      
      showAlert(alertEl, 'alert--error', 'Authentication failed. Please try again.');
    } catch (error) {
      console.error('Firebase login error:', error);
      if (error.code === 'auth/popup-closed-by-user') {
        showAlert(alertEl, 'alert--warning', 'Sign-in cancelled.');
      } else if (error.code === 'auth/popup-blocked') {
        showAlert(alertEl, 'alert--error', 'Pop-up blocked. Please allow pop-ups for this site.');
      } else {
        showAlert(alertEl, 'alert--error', 'Sign-in failed. Please try again.');
      }
    } finally {
      btn.disabled = false;
      btn.textContent = 'Sign in with Google';
    }
  });
}

// Setup wizard removed — use OLLIE_BOOTSTRAP_OWNER_EMAIL env var
export function initSetupForm(enterApp) {
  // No-op: setup wizard removed in Firebase fork
}
