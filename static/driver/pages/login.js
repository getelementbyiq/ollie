import { saveToken, getFirebaseConfig } from '../utils/auth.js';
import { navigate } from '../app.js';

let firebaseApp = null;
let firebaseAuth = null;

async function initFirebase() {
  if (firebaseApp) return;
  
  const config = await getFirebaseConfig();
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

export function renderLogin(container) {
  const html = `
    <div class="login-screen">
      <img class="login-icon" src="/driver/icon-192.png" alt="" />
      <div class="login-header">
        <h1>Driver Portal</h1>
        <p class="subtitle">Sign in with your UNDER account</p>
      </div>
      <div class="card login-card">
        <button id="firebase-signin-btn" class="btn btn-primary">Sign in with Google</button>
        <p id="login-error" class="error-msg" hidden></p>
        <div id="login-loading" hidden>
          <div class="spinner"></div>
          <p>Signing in...</p>
        </div>
        <p class="login-help">
          Your email or phone must be registered by dispatch.
        </p>
      </div>
    </div>
  `;

  container.innerHTML = html;

  const signInBtn = container.querySelector('#firebase-signin-btn');
  const errorEl = container.querySelector('#login-error');
  const loadingDiv = container.querySelector('#login-loading');

  function showError(msg) {
    errorEl.textContent = msg;
    errorEl.hidden = false;
  }

  function hideError() {
    errorEl.hidden = true;
  }

  function setLoading(on) {
    loadingDiv.hidden = !on;
    signInBtn.hidden = on;
  }

  signInBtn.addEventListener('click', async () => {
    setLoading(true);
    hideError();
    
    try {
      await initFirebase();
      const { signInWithPopup, GoogleAuthProvider } = await import('https://www.gstatic.com/firebasejs/10.7.1/firebase-auth.js');
      
      const provider = new GoogleAuthProvider();
      const result = await signInWithPopup(firebaseAuth, provider);
      const idToken = await result.user.getIdToken();
      
      // Send Firebase token to server
      const resp = await fetch('/driver/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id_token: idToken }),
      });
      
      if (resp.ok) {
        const data = await resp.json();
        saveToken(data.token);
        navigate('/driver/trips');
        return;
      }

      if (resp.status === 401) {
        showError('Your account is not authorized. Contact dispatch.');
        return;
      }
      
      showError('Authentication failed. Please try again.');
    } catch (error) {
      console.error('Firebase login error:', error);
      if (error.code === 'auth/popup-closed-by-user') {
        showError('Sign-in cancelled.');
      } else if (error.code === 'auth/popup-blocked') {
        showError('Pop-up blocked. Please allow pop-ups.');
      } else {
        showError('Sign-in failed. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  });
}
