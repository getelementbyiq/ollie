const TOKEN_KEY = 'driver_token';

export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export function isAuthenticated() {
  return !!getToken();
}

export function saveToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearAuth() {
  localStorage.removeItem(TOKEN_KEY);
}

// Fetch Firebase config from server
export async function getFirebaseConfig() {
  const resp = await fetch('/driver/api/v1/firebase-config');
  return await resp.json();
}
