import { isAuthenticated, clearAuth } from '../utils/auth.js';
import { apiFetch } from '../utils/api.js';
import { renderAppBar } from '../components/app-bar.js';
import { renderBottomNav } from '../components/bottom-nav.js';
import { navigate } from '../app.js';
import { getAppVersion } from '../utils/version.js';

export async function renderAccount(container) {
  if (!isAuthenticated()) {
    window.location.replace('/driver');
    return;
  }
  container.replaceChildren();

  const page = document.createElement('div');
  page.className = 'page-with-nav';
  page.appendChild(renderAppBar({ title: 'Account' }));

  const body = document.createElement('div');
  body.className = 'account-body';

  // Profile card
  const profileCard = document.createElement('div');
  profileCard.className = 'account-card';

  const nameEl = document.createElement('div');
  nameEl.className = 'account-name';
  nameEl.textContent = 'Loading…';
  profileCard.appendChild(nameEl);

  const phoneEl = document.createElement('div');
  phoneEl.className = 'account-phone';
  profileCard.appendChild(phoneEl);

  const statusEl = document.createElement('span');
  statusEl.className = 'badge';
  profileCard.appendChild(statusEl);

  body.appendChild(profileCard);

  // Actions
  const actionsList = document.createElement('div');
  actionsList.className = 'account-settings';

  const signOutRow = document.createElement('div');
  signOutRow.className = 'account-row';
  const signOutBtn = document.createElement('button');
  signOutBtn.type = 'button';
  signOutBtn.className = 'btn btn-danger-text';
  signOutBtn.textContent = 'Sign out';
  signOutBtn.addEventListener('click', () => {
    clearAuth();
    navigate('/driver');
  });
  signOutRow.appendChild(signOutBtn);
  actionsList.appendChild(signOutRow);

  body.appendChild(actionsList);

  // App version
  const versionDiv = document.createElement('div');
  versionDiv.className = 'account-version';
  versionDiv.textContent = `Version ${getAppVersion()}`;
  body.appendChild(versionDiv);

  page.appendChild(body);
  page.appendChild(renderBottomNav());
  container.appendChild(page);

  // Load driver info
  try {
    const me = await apiFetch('/me');
    nameEl.textContent = me.name;
    phoneEl.textContent = me.phone || me.email || '';
    
    const statusMap = {
      active: { text: 'Active', cls: 'badge--success' },
      inactive: { text: 'Inactive', cls: 'badge--muted' },
    };
    const st = statusMap[me.status] || { text: me.status, cls: 'badge--muted' };
    statusEl.textContent = st.text;
    statusEl.className = `badge ${st.cls}`;
  } catch (err) {
    console.error('Failed to load account:', err);
    nameEl.textContent = 'Error loading account';
  }
}
