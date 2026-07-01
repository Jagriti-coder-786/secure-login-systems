/* ==========================================================================
   ShieldAuth Client Application Logic (Single Page Application State Manager)
   ========================================================================== */

// Client State
let currentUser = null;
let mfaPendingToken = null;
let activeMfaSetupData = null;

// Initialize Event Listeners, Routing and Session Status
window.addEventListener('DOMContentLoaded', () => {
  // Navigation & Tab Switching
  document.getElementById('tab-login').addEventListener('click', () => switchAuthTab('login'));
  document.getElementById('tab-signup').addEventListener('click', () => switchAuthTab('signup'));

  // Password Visibility Toggles
  document.getElementById('btn-toggle-login-pass').addEventListener('click', () => togglePasswordVisibility('login-password'));
  document.getElementById('btn-toggle-signup-pass').addEventListener('click', () => togglePasswordVisibility('signup-password'));
  document.getElementById('btn-toggle-reset-pass').addEventListener('click', () => togglePasswordVisibility('reset-password'));

  // Live Password Strength calculations
  document.getElementById('signup-password').addEventListener('input', (e) => checkPasswordStrength(e.target.value, 'signup'));
  document.getElementById('reset-password').addEventListener('input', (e) => checkPasswordStrength(e.target.value, 'reset'));

  // Authentication & Verification Form Handlers
  document.getElementById('login-form').addEventListener('submit', handleLogin);
  document.getElementById('signup-form').addEventListener('submit', handleSignup);
  document.getElementById('mfa-form').addEventListener('submit', handleMfaVerify);
  document.getElementById('mfa-recovery-form').addEventListener('submit', handleMfaRecoveryVerify);
  document.getElementById('forgot-form').addEventListener('submit', handleForgotPasswordRequest);
  document.getElementById('reset-form').addEventListener('submit', handlePasswordReset);

  // MFA Recovery switching buttons
  document.getElementById('btn-mfa-use-recovery').addEventListener('click', () => toggleMfaRecovery(true));
  document.getElementById('btn-mfa-use-otp').addEventListener('click', () => toggleMfaRecovery(false));

  // Dashboard Control Panels
  document.getElementById('btn-logout').addEventListener('click', handleLogout);
  document.getElementById('btn-toggle-mfa').addEventListener('click', triggerMfaToggle);
  document.getElementById('btn-mfa-confirm-setup').addEventListener('click', confirmMfaSetup);
  document.getElementById('btn-mfa-confirm-disable').addEventListener('click', confirmMfaDisable);
  document.getElementById('btn-mfa-cancel-setup').addEventListener('click', cancelMfaSetup);
  document.getElementById('btn-revoke-others').addEventListener('click', handleRevokeAllOthers);
  document.getElementById('btn-refresh-logs').addEventListener('click', loadSecurityLogs);

  // Initialize Routing & Check Auth
  initRouting();
  checkSessionStatus();
});

// Hash-based simple router
function initRouting() {
  const handleRoute = () => {
    const hash = window.location.hash || '#auth';
    
    if (hash.startsWith('#reset-password')) {
      const urlParams = new URLSearchParams(hash.substring(hash.indexOf('?')));
      const token = urlParams.get('token');
      if (token) {
        document.getElementById('reset-token').value = token;
        navigateTo('reset-password');
        return;
      }
    }

    if (hash === '#forgot-password') {
      navigateTo('forgot-password');
    } else if (hash === '#dashboard' && currentUser) {
      navigateTo('dashboard');
    } else if (hash === '#auth' || !currentUser) {
      window.location.hash = '#auth';
      navigateTo('auth');
    }
  };

  window.addEventListener('hashchange', handleRoute);
  handleRoute(); // Execute once on boot
}

// Navigation Helper
function navigateTo(viewId) {
  // Hide all views
  document.querySelectorAll('.view').forEach(view => {
    view.classList.remove('active');
  });

  // Show selected view
  const targetView = document.getElementById(`${viewId}-view`);
  if (targetView) {
    targetView.classList.add('active');
  }
}

// Switch Login/Signup Tab
function switchAuthTab(tab) {
  const loginForm = document.getElementById('login-form');
  const signupForm = document.getElementById('signup-form');
  const tabLogin = document.getElementById('tab-login');
  const tabSignup = document.getElementById('tab-signup');
  const subtitle = document.getElementById('auth-subtitle');

  if (tab === 'login') {
    loginForm.classList.add('active-form');
    signupForm.classList.remove('active-form');
    tabLogin.classList.add('active');
    tabSignup.classList.remove('active');
    subtitle.textContent = 'Welcome back! Access your secure account.';
  } else {
    signupForm.classList.add('active-form');
    loginForm.classList.remove('active-form');
    tabSignup.classList.add('active');
    tabLogin.classList.remove('active');
    subtitle.textContent = 'Create a secure ShieldAuth identity.';
  }
}

// Password Visibility Toggle
function togglePasswordVisibility(inputId) {
  const input = document.getElementById(inputId);
  const button = input.nextElementSibling;
  const icon = button.querySelector('i');

  if (input.type === 'password') {
    input.type = 'text';
    icon.classList.remove('fa-eye');
    icon.classList.add('fa-eye-slash');
  } else {
    input.type = 'password';
    icon.classList.remove('fa-eye-slash');
    icon.classList.add('fa-eye');
  }
}

// ==================== Password Strength & Policy Validation ====================
function checkPasswordStrength(password, prefix = 'signup') {
  const bar = document.getElementById(`${prefix}-strength-bar`);
  const text = document.getElementById(`${prefix}-strength-text`);
  
  // Indicators
  const reqs = {
    length: password.length >= 8,
    upper: /[A-Z]/.test(password),
    lower: /[a-z]/.test(password),
    number: /\d/.test(password),
    special: /\W/.test(password)
  };

  // Update requirement visuals
  Object.keys(reqs).forEach(key => {
    const element = document.getElementById(`req-${prefix}-${key}`);
    const icon = element.querySelector('i');
    if (reqs[key]) {
      element.className = 'valid';
      icon.className = 'fa-solid fa-circle-check';
    } else {
      element.className = 'invalid';
      icon.className = 'fa-solid fa-circle-xmark';
    }
  });

  // Calculate score
  let score = 0;
  if (password.length > 0) score += 1;
  if (password.length >= 8) score += 1;
  if (reqs.upper && reqs.lower) score += 1;
  if (reqs.number) score += 1;
  if (reqs.special) score += 1;

  // Render Strength meter
  bar.style.width = `${(score / 5) * 100}%`;
  
  if (score === 0) {
    bar.style.backgroundColor = 'transparent';
    text.textContent = 'Password Strength: None';
  } else if (score <= 2) {
    bar.style.backgroundColor = 'var(--danger)';
    text.textContent = 'Password Strength: Weak ⚠️';
  } else if (score <= 4) {
    bar.style.backgroundColor = 'var(--warning)';
    text.textContent = 'Password Strength: Moderate ⚡';
  } else {
    bar.style.backgroundColor = 'var(--success)';
    text.textContent = 'Password Strength: Secure (Very Strong) 🔒';
  }

  return score === 5;
}

// ==================== Fetch API Wrapper with CSRF / Credentials ====================
async function apiCall(endpoint, method = 'GET', data = null) {
  const config = {
    method,
    headers: {
      'Content-Type': 'application/json',
    }
  };

  if (data) {
    config.body = JSON.stringify(data);
  }

  try {
    const res = await fetch(endpoint, config);
    const responseData = await res.json();
    if (!res.ok) {
      throw { status: res.status, error: responseData.error || 'Request failed' };
    }
    return responseData;
  } catch (err) {
    throw err.error ? err : { status: 500, error: 'Network error or connection lost' };
  }
}

// ==================== Toast Notifications Handler ====================
function showToast(message, type = 'success') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  
  let iconClass = 'fa-circle-info';
  if (type === 'success') iconClass = 'fa-circle-check';
  if (type === 'error') iconClass = 'fa-circle-exclamation';

  toast.innerHTML = `
    <i class="fa-solid ${iconClass}"></i>
    <div class="toast-content">${escapeHTML(message)}</div>
  `;

  container.appendChild(toast);

  // Automatically remove toast after 4 seconds
  setTimeout(() => {
    toast.classList.add('removing');
    toast.addEventListener('animationend', () => {
      toast.remove();
    });
  }, 4000);
}

// Escape HTML to prevent XSS in notifications
function escapeHTML(str) {
  return str.replace(/[&<>'"]/g, 
    tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)
  );
}

// ==================== Authentication Event Handlers ====================

// Check Session Status on Page Load
async function checkSessionStatus() {
  try {
    const res = await apiCall('/api/user/profile');
    currentUser = res;
    showToast(`Session restored. Welcome, ${currentUser.username}!`, 'info');
    window.location.hash = '#dashboard';
    navigateTo('dashboard');
    loadDashboardData();
  } catch (err) {
    currentUser = null;
    if (window.location.hash === '#dashboard') {
      window.location.hash = '#auth';
    }
  }
}

// Handle Sign Up
async function handleSignup(e) {
  e.preventDefault();
  const username = document.getElementById('signup-username').value;
  const email = document.getElementById('signup-email').value;
  const password = document.getElementById('signup-password').value;

  if (!checkPasswordStrength(password)) {
    showToast('Password is too weak. Please satisfy all requirements.', 'error');
    return;
  }

  try {
    const res = await apiCall('/api/auth/signup', 'POST', { username, email, password });
    showToast(res.message, 'success');
    switchAuthTab('login');
    document.getElementById('signup-form').reset();
  } catch (err) {
    showToast(err.error, 'error');
  }
}

// Handle Log In
async function handleLogin(e) {
  e.preventDefault();
  const username = document.getElementById('login-username').value;
  const password = document.getElementById('login-password').value;

  try {
    const res = await apiCall('/api/auth/login', 'POST', { username, password });
    
    // Check if 2FA verification is required
    if (res.mfa_required) {
      mfaPendingToken = res.mfa_token;
      showToast('Two-factor authentication required.', 'info');
      navigateTo('mfa-verify');
      document.getElementById('mfa-code').focus();
    } else {
      currentUser = res.user;
      showToast('Login successful!', 'success');
      window.location.hash = '#dashboard';
      navigateTo('dashboard');
      loadDashboardData();
      document.getElementById('login-form').reset();
    }
  } catch (err) {
    showToast(err.error, 'error');
  }
}

// Handle MFA Verification Code Submission
async function handleMfaVerify(e) {
  e.preventDefault();
  const code = document.getElementById('mfa-code').value;

  try {
    const res = await apiCall('/api/auth/mfa/verify', 'POST', { mfa_token: mfaPendingToken, code });
    currentUser = res.user;
    mfaPendingToken = null;
    showToast('2FA code verified. Access granted.', 'success');
    window.location.hash = '#dashboard';
    navigateTo('dashboard');
    loadDashboardData();
    document.getElementById('mfa-form').reset();
  } catch (err) {
    showToast(err.error, 'error');
  }
}

// Handle 2FA Recovery Code Login
async function handleMfaRecoveryVerify(e) {
  e.preventDefault();
  const recovery_code = document.getElementById('mfa-recovery-code').value;

  try {
    const res = await apiCall('/api/auth/mfa/recovery-login', 'POST', { mfa_token: mfaPendingToken, recovery_code });
    currentUser = res.user;
    mfaPendingToken = null;
    showToast(`Recovery code matches. ${res.codes_left} recovery codes remaining.`, 'success');
    window.location.hash = '#dashboard';
    navigateTo('dashboard');
    loadDashboardData();
    document.getElementById('mfa-recovery-form').reset();
    toggleMfaRecovery(false); // Toggle view back to OTP input
  } catch (err) {
    showToast(err.error, 'error');
  }
}

// Toggle between OTP and Recovery code screen during login
function toggleMfaRecovery(useRecovery) {
  const mfaForm = document.getElementById('mfa-form');
  const recoveryForm = document.getElementById('mfa-recovery-form');
  
  if (useRecovery) {
    mfaForm.classList.add('hidden');
    recoveryForm.classList.remove('hidden');
    document.getElementById('mfa-recovery-code').focus();
  } else {
    mfaForm.classList.remove('hidden');
    recoveryForm.classList.add('hidden');
    document.getElementById('mfa-code').focus();
  }
}

// Handle Forgot Password Form Submission
async function handleForgotPasswordRequest(e) {
  e.preventDefault();
  const email = document.getElementById('forgot-email').value;

  try {
    const res = await apiCall('/api/auth/reset-password/request', 'POST', { email });
    showToast(res.message, 'success');
    
    // Check if reset details were exposed in simulation mode (for sandbox testing)
    if (res.demo_reset_link) {
      const simBox = document.getElementById('simulation-message');
      const simLink = document.getElementById('demo-reset-url');
      simBox.classList.remove('hidden');
      simLink.href = res.demo_reset_link;
      simLink.textContent = res.demo_reset_link;
    }
  } catch (err) {
    showToast(err.error, 'error');
  }
}

// Handle Password Reset Execution
async function handlePasswordReset(e) {
  e.preventDefault();
  const token = document.getElementById('reset-token').value;
  const password = document.getElementById('reset-password').value;

  try {
    const res = await apiCall('/api/auth/reset-password/reset', 'POST', { token, password });
    showToast(res.message, 'success');
    window.location.hash = '#auth';
    navigateTo('auth');
    document.getElementById('reset-form').reset();
    document.getElementById('simulation-message').classList.add('hidden');
  } catch (err) {
    showToast(err.error, 'error');
  }
}

// Handle Log Out
async function handleLogout() {
  try {
    await apiCall('/api/auth/logout', 'POST');
    currentUser = null;
    showToast('Logged out successfully.', 'info');
    window.location.hash = '#auth';
    navigateTo('auth');
  } catch (err) {
    showToast(err.error, 'error');
  }
}

// ==================== Dashboard Data Renderers ====================

function loadDashboardData() {
  if (!currentUser) return;
  loadUserProfile();
  loadActiveSessions();
  loadSecurityLogs();
}

async function loadUserProfile() {
  try {
    const profile = await apiCall('/api/user/profile');
    currentUser = profile; // Update local cache
    
    document.getElementById('dash-username').textContent = profile.username;
    document.getElementById('dash-email').textContent = profile.email;
    
    const badge = document.getElementById('mfa-status-badge');
    const toggleBtn = document.getElementById('btn-toggle-mfa');
    
    if (profile.two_factor_enabled) {
      badge.textContent = 'Active (Highly Protected)';
      badge.className = 'badge badge-success';
      toggleBtn.innerHTML = '<i class="fa-solid fa-toggle-off"></i> Disable 2FA';
      toggleBtn.className = 'btn btn-outline';
    } else {
      badge.textContent = 'Disabled (Low Protection)';
      badge.className = 'badge badge-danger';
      toggleBtn.innerHTML = '<i class="fa-solid fa-toggle-on"></i> Configure 2FA';
      toggleBtn.className = 'btn btn-primary';
    }
  } catch (err) {
    showToast('Error loading user profile details.', 'error');
  }
}

async function loadActiveSessions() {
  const container = document.getElementById('sessions-container');
  try {
    const sessions = await apiCall('/api/user/sessions');
    container.innerHTML = '';

    sessions.forEach(sess => {
      const item = document.createElement('div');
      item.className = 'session-item';
      
      const details = parseUserAgent(sess.user_agent);
      const isCurrent = sess.is_current;
      const createdDate = new Date(sess.created_at).toLocaleString();

      item.innerHTML = `
        <div class="session-info">
          <div class="session-icon">
            <i class="${details.icon}"></i>
          </div>
          <div class="session-details">
            <h5>
              ${escapeHTML(details.browser)} on ${escapeHTML(details.os)}
              ${isCurrent ? '<span class="badge badge-success">Current Session</span>' : ''}
            </h5>
            <p>IP Address: ${escapeHTML(sess.ip_address)} • Signed in: ${createdDate}</p>
          </div>
        </div>
        ${!isCurrent ? `<button class="btn btn-outline btn-xs btn-danger" onclick="revokeSession('${sess.id}')">Revoke</button>` : ''}
      `;

      container.appendChild(item);
    });
  } catch (err) {
    showToast('Error loading active login sessions.', 'error');
  }
}

async function loadSecurityLogs() {
  const container = document.getElementById('logs-container');
  try {
    const logs = await apiCall('/api/user/logs');
    container.innerHTML = '';

    if (logs.length === 0) {
      container.innerHTML = `<tr><td colspan="5" style="text-align:center;">No logs recorded yet.</td></tr>`;
      return;
    }

    logs.forEach(log => {
      const tr = document.createElement('tr');
      const timestamp = new Date(log.timestamp).toLocaleString();
      const uaDetails = parseUserAgent(log.user_agent || '');
      
      let badgeClass = 'badge-success';
      if (['LOGIN_FAILURE', 'LOCKOUT', 'LOCKOUT_BLOCKED', 'MFA_VERIFY_FAILURE', 'MFA_RECOVERY_FAILURE', 'MFA_DISABLE_ATTEMPT_FAIL'].includes(log.event_type)) {
        badgeClass = 'badge-danger';
      } else if (['PASSWORD_RESET_REQUEST', 'MFA_DISABLED'].includes(log.event_type)) {
        badgeClass = 'badge-warning';
      }

      tr.innerHTML = `
        <td><span class="badge ${badgeClass}">${escapeHTML(log.event_type)}</span></td>
        <td><code>${escapeHTML(log.ip_address || 'Unknown')}</code></td>
        <td><i class="${uaDetails.icon}"></i> ${escapeHTML(uaDetails.browser)} (${escapeHTML(uaDetails.os)})</td>
        <td>${escapeHTML(log.details)}</td>
        <td>${timestamp}</td>
      `;

      container.appendChild(tr);
    });
  } catch (err) {
    showToast('Error loading security logs.', 'error');
  }
}

// Revoke specific session ID
async function revokeSession(sessId) {
  try {
    const res = await apiCall('/api/user/sessions/revoke', 'POST', { sessionId: sessId });
    showToast(res.message, 'success');
    loadDashboardData();
  } catch (err) {
    showToast(err.error, 'error');
  }
}

// Revoke all other sessions
async function handleRevokeAllOthers() {
  if (!confirm('Are you sure you want to log out of all other devices and applications?')) return;
  try {
    const res = await apiCall('/api/user/sessions/revoke-others', 'POST');
    showToast(res.message, 'success');
    loadDashboardData();
  } catch (err) {
    showToast(err.error, 'error');
  }
}

// ==================== 2FA / MFA Setup Flow Controllers ====================

function triggerMfaToggle() {
  const isEnabled = currentUser.two_factor_enabled;
  const setupFlow = document.getElementById('mfa-setup-flow');
  const disableFlow = document.getElementById('mfa-disable-flow');

  if (isEnabled) {
    disableFlow.classList.toggle('hidden');
    setupFlow.classList.add('hidden');
    document.getElementById('mfa-disable-password').focus();
  } else {
    if (setupFlow.classList.contains('hidden')) {
      initializeMfaSetup();
    } else {
      setupFlow.classList.add('hidden');
    }
    disableFlow.classList.add('hidden');
  }
}

async function initializeMfaSetup() {
  try {
    const res = await apiCall('/api/auth/mfa/setup', 'POST');
    activeMfaSetupData = res;

    // Display QR Code & Secret
    document.getElementById('mfa-qr-code').src = res.qr_code;
    document.getElementById('mfa-secret-key').textContent = res.secret;

    // Display Recovery Codes
    const codesContainer = document.getElementById('mfa-recovery-codes');
    codesContainer.innerHTML = '';
    res.recovery_codes.forEach(code => {
      const codeDiv = document.createElement('div');
      codeDiv.className = 'recovery-code';
      codeDiv.textContent = code;
      codesContainer.appendChild(codeDiv);
    });

    // Reveal container
    document.getElementById('mfa-setup-flow').classList.remove('hidden');
    document.getElementById('mfa-setup-code').focus();
  } catch (err) {
    showToast(err.error, 'error');
  }
}

async function confirmMfaSetup() {
  const code = document.getElementById('mfa-setup-code').value;
  if (!code) {
    showToast('Please enter the 6-digit confirmation code.', 'error');
    return;
  }

  try {
    const res = await apiCall('/api/auth/mfa/enable', 'POST', { code });
    showToast(res.message, 'success');
    
    // Clean states and update profile
    document.getElementById('mfa-setup-flow').classList.add('hidden');
    document.getElementById('mfa-setup-code').value = '';
    activeMfaSetupData = null;
    loadDashboardData();
  } catch (err) {
    showToast(err.error, 'error');
  }
}

async function confirmMfaDisable() {
  const password = document.getElementById('mfa-disable-password').value;
  if (!password) {
    showToast('Please input password to confirm.', 'error');
    return;
  }

  try {
    const res = await apiCall('/api/auth/mfa/disable', 'POST', { password });
    showToast(res.message, 'success');
    
    // Clear and hide disable pane
    document.getElementById('mfa-disable-flow').classList.add('hidden');
    document.getElementById('mfa-disable-password').value = '';
    loadDashboardData();
  } catch (err) {
    showToast(err.error, 'error');
  }
}

function cancelMfaSetup() {
  document.getElementById('mfa-setup-flow').classList.add('hidden');
  document.getElementById('mfa-disable-flow').classList.add('hidden');
  document.getElementById('mfa-disable-password').value = '';
}

// ==================== User Agent Parser Helper ====================
function parseUserAgent(ua) {
  let browser = 'Other Browser';
  let os = 'Unknown OS';
  let icon = 'fa-solid fa-laptop';

  if (ua.includes('Firefox/')) {
    browser = 'Firefox';
  } else if (ua.includes('Edg/')) {
    browser = 'Microsoft Edge';
  } else if (ua.includes('Chrome/')) {
    browser = 'Google Chrome';
  } else if (ua.includes('Safari/')) {
    browser = 'Safari';
  }

  if (ua.includes('Windows NT')) {
    os = 'Windows';
    icon = 'fa-brands fa-windows';
  } else if (ua.includes('Macintosh') || ua.includes('Mac OS X')) {
    os = 'macOS';
    icon = 'fa-brands fa-apple';
  } else if (ua.includes('Linux')) {
    os = 'Linux';
    icon = 'fa-brands fa-linux';
  } else if (ua.includes('Android')) {
    os = 'Android';
    icon = 'fa-brands fa-android';
  } else if (ua.includes('iPhone') || ua.includes('iPad')) {
    os = 'iOS';
    icon = 'fa-brands fa-apple';
  }

  return { browser, os, icon };
}
