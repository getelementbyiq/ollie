// Firebase-based login for fleet portal
import { saveToken } from '../utils/auth.js';
import { loadMe } from '../utils/api.js';

let firebaseApp = null;
let firebaseAuth = null;

export async function initFirebase() {
  if (firebaseApp) return;
  
  // Fetch Firebase config from server
  const resp = await fetch('/fleet/api/v1/firebase-config');
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

export async function signInWithFirebase() {
  await initFirebase();
  const { signInWithPopup, GoogleAuthProvider } = await import('https://www.gstatic.com/firebasejs/10.7.1/firebase-auth.js');
  
  const provider = new GoogleAuthProvider();
  const result = await signInWithPopup(firebaseAuth, provider);
  const idToken = await result.user.getIdToken();
  
  // Send Firebase token to server (server returns it back as passthrough)
  const resp = await fetch('/fleet/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id_token: idToken }),
  });
  
  if (!resp.ok) {
    throw new Error('Authentication failed');
  }
  
  const data = await resp.json();
  return data.token;
}

export async function signOutFromFirebase() {
  if (firebaseAuth) {
    await firebaseAuth.signOut();
  }
}
