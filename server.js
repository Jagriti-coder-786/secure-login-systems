require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const crypto = require('crypto');
const path = require('path');

const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_jwt_secret_for_dev_mode_only_12345';
const COOKIE_SECRET = process.env.COOKIE_SECRET || 'fallback_cookie_secret_for_dev_mode_only_12345';

// Security Headers with Helmet
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"], // Allow inline JS for SPA event handlers
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:"], // data: is required for QR code images
        connectSrc: ["'self'"],
      },
    },
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(COOKIE_SECRET));

// Serve static frontend files
app.use(express.static(path.join(__dirname, 'public')));

// Rate Limiting
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
  message: { error: 'Too many requests from this IP, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 15, // Limit each IP to 15 authentication attempts
  message: { error: 'Too many authentication attempts, please try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', generalLimiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/signup', authLimiter);

// ---------------------------------------------
// Authentication & Session Middleware
// ---------------------------------------------
async function authenticateToken(req, res, next) {
  const token = req.signedCookies.token;
  if (!token) {
    return res.status(401).json({ error: 'Access denied. Please log in.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Verify session state in database to support revoking
    const session = await db.getSession(decoded.sessionId);
    if (!session) {
      res.clearCookie('token');
      return res.status(401).json({ error: 'Session expired or revoked.' });
    }

    req.user = {
      id: decoded.id,
      username: decoded.username,
      sessionId: decoded.sessionId,
    };
    next();
  } catch (err) {
    res.clearCookie('token');
    return res.status(401).json({ error: 'Invalid session token.' });
  }
}

// Password Validator Helper
function validatePasswordStrength(password) {
  const minLength = 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasNonalphas = /\W/.test(password);
  return password.length >= minLength && hasUpperCase && hasLowerCase && hasNumbers && hasNonalphas;
}

// ---------------------------------------------
// Authentication Routes
// ---------------------------------------------

// Sign Up
app.post('/api/auth/signup', async (req, res) => {
  const { username, email, password } = req.body;
  const ip = req.ip;
  const ua = req.get('User-Agent');

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  const cleanUsername = username.trim();
  const cleanEmail = email.trim().toLowerCase();

  // Username validation: Alphanumeric, 3-20 chars
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(cleanUsername)) {
    return res.status(400).json({ error: 'Username must be 3-20 characters long and contain only letters, numbers, or underscores.' });
  }

  // Email validation
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }

  // Password validation
  if (!validatePasswordStrength(password)) {
    return res.status(400).json({ error: 'Password does not meet safety criteria (Min 8 chars, including uppercase, lowercase, numbers, and special characters).' });
  }

  try {
    // Check if user exists
    const existingUser = await db.getUserByUsername(cleanUsername);
    if (existingUser) {
      return res.status(400).json({ error: 'Username is already taken.' });
    }

    const existingEmail = await db.getUserByEmail(cleanEmail);
    if (existingEmail) {
      return res.status(400).json({ error: 'Email is already registered.' });
    }

    // Hash password
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Save to Database
    const result = await db.createUser(cleanUsername, cleanEmail, passwordHash);
    const userId = result.lastID;

    // Log security event
    await db.logSecurityEvent(userId, 'SIGNUP', ip, ua, `User ${cleanUsername} registered successfully.`);

    return res.status(201).json({ message: 'User registered successfully. You can now log in.' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Database error occurred during registration.' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip;
  const ua = req.get('User-Agent');

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  const cleanUsername = username.trim();

  try {
    // 1. Brute force check
    const lockoutRecord = await db.getFailedLogins(cleanUsername);
    if (lockoutRecord && lockoutRecord.locked_until) {
      const lockTime = new Date(lockoutRecord.locked_until);
      const now = new Date();
      if (lockTime > now) {
        const remainingMinutes = Math.ceil((lockTime - now) / (1000 * 60));
        await db.logSecurityEvent(null, 'LOCKOUT_BLOCKED', ip, ua, `Attempted login on locked account: ${cleanUsername}`);
        return res.status(423).json({ error: `This account is temporarily locked due to excessive failed attempts. Try again in ${remainingMinutes} minutes.` });
      } else {
        // Lockout expired, clear record
        await db.resetFailedLogins(cleanUsername);
      }
    }

    // 2. Authenticate credentials
    const user = await db.getUserByUsername(cleanUsername);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      // Failed login attempt
      await db.recordFailedLogin(cleanUsername);
      await db.logSecurityEvent(user ? user.id : null, 'LOGIN_FAILURE', ip, ua, `Failed login attempt for username: ${cleanUsername}`);
      
      // Fetch updated failed attempts to customize response message
      const updatedRecord = await db.getFailedLogins(cleanUsername);
      const attemptsLeft = 5 - (updatedRecord ? updatedRecord.attempts : 1);
      
      if (attemptsLeft <= 0) {
        return res.status(423).json({ error: 'Incorrect credentials. Account has been locked for 15 minutes.' });
      } else {
        return res.status(401).json({ error: `Incorrect credentials. ${attemptsLeft} attempts remaining before account lockout.` });
      }
    }

    // 3. Clear failed logins on successful authentication
    await db.resetFailedLogins(cleanUsername);

    // 4. Check if 2FA is enabled
    if (user.two_factor_enabled) {
      // Create a temporary pre-auth JWT token containing user id.
      // This token will only be authorized to access the verification API endpoint.
      const mfaToken = jwt.sign({ id: user.id, username: user.username, mfa_pending: true }, JWT_SECRET, { expiresIn: '5m' });
      return res.status(200).json({ mfa_required: true, mfa_token: mfaToken });
    }

    // 5. Complete login (No 2FA)
    const sessionId = crypto.randomUUID();
    const sessionExpiry = new Date();
    sessionExpiry.setDate(sessionExpiry.getDate() + 1); // 1 day session length

    await db.createSession(sessionId, user.id, ip, ua, sessionExpiry.toISOString());

    const token = jwt.sign({ id: user.id, username: user.username, sessionId }, JWT_SECRET, { expiresIn: '1d' });

    res.cookie('token', token, {
      httpOnly: true,
      secure: false, // Set to true in prod with HTTPS
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000,
      signed: true,
    });

    await db.logSecurityEvent(user.id, 'LOGIN_SUCCESS', ip, ua, 'Successfully logged in.');

    return res.status(200).json({ message: 'Login successful.', user: { id: user.id, username: user.username } });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error during login authentication.' });
  }
});

// Verify 2FA TOTP code on login
app.post('/api/auth/mfa/verify', async (req, res) => {
  const { mfa_token, code } = req.body;
  const ip = req.ip;
  const ua = req.get('User-Agent');

  if (!mfa_token || !code) {
    return res.status(400).json({ error: 'MFA token and verification code are required.' });
  }

  try {
    const decoded = jwt.verify(mfa_token, JWT_SECRET);
    if (!decoded.mfa_pending) {
      return res.status(400).json({ error: 'Invalid MFA verification sequence.' });
    }

    const user = await db.getUserById(decoded.id);
    if (!user || !user.two_factor_enabled || !user.two_factor_secret) {
      return res.status(400).json({ error: '2FA is not enabled for this account.' });
    }

    // Verify code
    const verified = speakeasy.totp.verify({
      secret: user.two_factor_secret,
      encoding: 'base32',
      token: code,
      window: 1, // Allow 30s drift window before/after
    });

    if (!verified) {
      await db.logSecurityEvent(user.id, 'MFA_VERIFY_FAILURE', ip, ua, 'Failed 2FA validation during login.');
      return res.status(401).json({ error: 'Invalid authenticator code. Please check your app.' });
    }

    // Complete login
    const sessionId = crypto.randomUUID();
    const sessionExpiry = new Date();
    sessionExpiry.setDate(sessionExpiry.getDate() + 1);

    await db.createSession(sessionId, user.id, ip, ua, sessionExpiry.toISOString());

    const token = jwt.sign({ id: user.id, username: user.username, sessionId }, JWT_SECRET, { expiresIn: '1d' });

    res.cookie('token', token, {
      httpOnly: true,
      secure: false,
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000,
      signed: true,
    });

    await db.logSecurityEvent(user.id, 'LOGIN_SUCCESS', ip, ua, 'Successfully logged in with 2FA.');

    return res.status(200).json({ message: 'Login successful.', user: { id: user.id, username: user.username } });
  } catch (err) {
    console.error(err);
    return res.status(401).json({ error: 'Session token has expired or is invalid.' });
  }
});

// Verify login with 2FA recovery codes
app.post('/api/auth/mfa/recovery-login', async (req, res) => {
  const { mfa_token, recovery_code } = req.body;
  const ip = req.ip;
  const ua = req.get('User-Agent');

  if (!mfa_token || !recovery_code) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  try {
    const decoded = jwt.verify(mfa_token, JWT_SECRET);
    if (!decoded.mfa_pending) {
      return res.status(400).json({ error: 'Invalid verification token.' });
    }

    const user = await db.getUserById(decoded.id);
    if (!user || !user.two_factor_enabled || !user.two_factor_recovery_codes) {
      return res.status(400).json({ error: 'Recovery codes are not available.' });
    }

    const recoveryCodes = JSON.parse(user.two_factor_recovery_codes);
    const codeIndex = recoveryCodes.indexOf(recovery_code.trim());

    if (codeIndex === -1) {
      await db.logSecurityEvent(user.id, 'MFA_RECOVERY_FAILURE', ip, ua, 'Failed 2FA login recovery code attempt.');
      return res.status(401).json({ error: 'Invalid recovery code.' });
    }

    // Code matches. Consume the code (prevent replay attacks)
    recoveryCodes.splice(codeIndex, 1);
    await db.updateUser2FA(user.id, user.two_factor_secret, 1, JSON.stringify(recoveryCodes));

    // Complete login
    const sessionId = crypto.randomUUID();
    const sessionExpiry = new Date();
    sessionExpiry.setDate(sessionExpiry.getDate() + 1);

    await db.createSession(sessionId, user.id, ip, ua, sessionExpiry.toISOString());

    const token = jwt.sign({ id: user.id, username: user.username, sessionId }, JWT_SECRET, { expiresIn: '1d' });

    res.cookie('token', token, {
      httpOnly: true,
      secure: false,
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000,
      signed: true,
    });

    await db.logSecurityEvent(user.id, 'LOGIN_SUCCESS', ip, ua, 'Successfully logged in using backup recovery code.');

    return res.status(200).json({
      message: 'Login successful.',
      user: { id: user.id, username: user.username },
      codes_left: recoveryCodes.length
    });
  } catch (err) {
    console.error(err);
    return res.status(401).json({ error: 'Session token has expired or is invalid.' });
  }
});

// Setup 2FA - Generates QR Code (Protected)
app.post('/api/auth/mfa/setup', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const username = req.user.username;

  try {
    const user = await db.getUserById(userId);
    if (!user) return res.status(404).json({ error: 'User not found.' });

    // Generate secret
    const secret = speakeasy.generateSecret({
      name: `SecureAuthApp:${username}`,
      issuer: 'SecureAuthApp',
    });

    // Generate QR code data URL
    QRCode.toDataURL(secret.otpauth_url, async (err, dataUrl) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to generate QR Code' });
      }

      // Generate 5 new recovery codes
      const recoveryCodes = [];
      for (let i = 0; i < 5; i++) {
        recoveryCodes.push(crypto.randomBytes(4).toString('hex').toUpperCase()); // XXXX-XXXX format can be done, but standard hex is easier
      }

      // Save secret temporarily but do not enable 2FA until user verifies setup code
      await db.updateUser2FA(userId, secret.base32, 0, JSON.stringify(recoveryCodes));

      res.status(200).json({
        secret: secret.base32,
        qr_code: dataUrl,
        recovery_codes: recoveryCodes,
      });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error setting up 2FA.' });
  }
});

// Enable 2FA - Verify OTP code & toggle active (Protected)
app.post('/api/auth/mfa/enable', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const { code } = req.body;
  const ip = req.ip;
  const ua = req.get('User-Agent');

  if (!code) {
    return res.status(400).json({ error: 'Verification code is required.' });
  }

  try {
    const user = await db.getUserById(userId);
    if (!user || !user.two_factor_secret) {
      return res.status(400).json({ error: 'MFA setup is not initialized.' });
    }

    const verified = speakeasy.totp.verify({
      secret: user.two_factor_secret,
      encoding: 'base32',
      token: code,
      window: 1,
    });

    if (!verified) {
      return res.status(400).json({ error: 'Invalid code. Setup verification failed.' });
    }

    // Activate 2FA in database
    await db.updateUser2FA(userId, user.two_factor_secret, 1, user.two_factor_recovery_codes);
    await db.logSecurityEvent(userId, 'MFA_ENABLED', ip, ua, 'Multi-factor Authentication has been enabled.');

    res.status(200).json({ message: 'Multi-factor Authentication successfully enabled.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error enabling 2FA.' });
  }
});

// Disable 2FA (Protected)
app.post('/api/auth/mfa/disable', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const { password } = req.body;
  const ip = req.ip;
  const ua = req.get('User-Agent');

  if (!password) {
    return res.status(400).json({ error: 'Password confirmation is required to disable 2FA.' });
  }

  try {
    const user = await db.getUserById(userId);
    if (!user) return res.status(404).json({ error: 'User not found.' });

    // Confirm password
    const passMatch = await bcrypt.compare(password, user.password_hash);
    if (!passMatch) {
      await db.logSecurityEvent(userId, 'MFA_DISABLE_ATTEMPT_FAIL', ip, ua, 'Failed password verify when attempting to disable 2FA.');
      return res.status(401).json({ error: 'Incorrect password.' });
    }

    // Disable
    await db.updateUser2FA(userId, null, 0, null);
    await db.logSecurityEvent(userId, 'MFA_DISABLED', ip, ua, 'Multi-factor Authentication has been disabled.');

    res.status(200).json({ message: '2FA successfully disabled.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error disabling 2FA.' });
  }
});

// Temporary memory store for password reset tokens (for simulation)
const resetTokens = new Map();

// Password Reset Request
app.post('/api/auth/reset-password/request', async (req, res) => {
  const { email } = req.body;
  const ip = req.ip;
  const ua = req.get('User-Agent');

  if (!email) {
    return res.status(400).json({ error: 'Email address is required.' });
  }

  try {
    const user = await db.getUserByEmail(email.trim().toLowerCase());
    
    // Always return a generic success message to prevent user enumeration attacks
    const successMsg = 'If the email exists in our records, a secure password reset link has been generated.';
    
    if (!user) {
      // Simulate delays to prevent timing attacks
      await new Promise(resolve => setTimeout(resolve, Math.random() * 500 + 200));
      return res.status(200).json({ message: successMsg });
    }

    // Generate high entropy token
    const token = crypto.randomBytes(32).toString('hex');
    const expiry = Date.now() + 15 * 60 * 1000; // 15 mins

    resetTokens.set(token, {
      userId: user.id,
      expiry,
    });

    await db.logSecurityEvent(user.id, 'PASSWORD_RESET_REQUEST', ip, ua, 'Password reset request submitted.');

    // In a real application, we would email this link.
    // For demonstration, we provide it in the API response so the user can copy/paste or click it easily in the demo.
    const resetLink = `http://localhost:${PORT}/#reset-password?token=${token}`;

    return res.status(200).json({
      message: successMsg,
      // DEMO-ONLY: Reveal link in response to enable local browser test flow
      demo_reset_link: resetLink,
      demo_token: token
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error initiating password reset.' });
  }
});

// Password Reset Action
app.post('/api/auth/reset-password/reset', async (req, res) => {
  const { token, password } = req.body;
  const ip = req.ip;
  const ua = req.get('User-Agent');

  if (!token || !password) {
    return res.status(400).json({ error: 'Token and new password are required.' });
  }

  if (!validatePasswordStrength(password)) {
    return res.status(400).json({ error: 'Password does not meet safety criteria (Min 8 chars, uppercase, lowercase, numbers, special characters).' });
  }

  const tokenData = resetTokens.get(token);
  if (!tokenData) {
    return res.status(400).json({ error: 'Invalid or expired password reset token.' });
  }

  if (Date.now() > tokenData.expiry) {
    resetTokens.delete(token);
    return res.status(400).json({ error: 'Password reset token has expired (15 minutes limit exceeded).' });
  }

  try {
    const saltRounds = 12;
    const newHash = await bcrypt.hash(password, saltRounds);

    await db.updateUserPassword(tokenData.userId, newHash);
    await db.resetFailedLogins(tokenData.userId); // Reset lockout logs
    await db.logSecurityEvent(tokenData.userId, 'PASSWORD_RESET_SUCCESS', ip, ua, 'Password successfully reset.');

    // Invalidate the token
    resetTokens.delete(token);

    return res.status(200).json({ message: 'Password successfully reset. You can now log in.' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error processing password reset.' });
  }
});

// Log out
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const sessionId = req.user.sessionId;
  const ip = req.ip;
  const ua = req.get('User-Agent');

  try {
    await db.revokeSession(sessionId, userId);
    await db.logSecurityEvent(userId, 'LOGOUT', ip, ua, 'User logged out.');
  } catch (err) {
    console.error('Session revoke during logout failed', err);
  }

  res.clearCookie('token');
  return res.status(200).json({ message: 'Logged out successfully.' });
});

// ---------------------------------------------
// User & Dashboard Routes (Protected)
// ---------------------------------------------

// Get Profile Info
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found.' });

    res.status(200).json({
      username: user.username,
      email: user.email,
      two_factor_enabled: !!user.two_factor_enabled,
      created_at: user.created_at,
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error fetching user profile.' });
  }
});

// Get Active Sessions
app.get('/api/user/sessions', authenticateToken, async (req, res) => {
  try {
    const sessions = await db.getUserActiveSessions(req.user.id);
    // Annotate the current session
    const annotated = sessions.map(sess => ({
      ...sess,
      is_current: sess.id === req.user.sessionId,
    }));
    res.status(200).json(annotated);
  } catch (err) {
    res.status(500).json({ error: 'Server error fetching sessions.' });
  }
});

// Revoke a Session
app.post('/api/user/sessions/revoke', authenticateToken, async (req, res) => {
  const { sessionId } = req.body;
  const userId = req.user.id;
  const ip = req.ip;
  const ua = req.get('User-Agent');

  if (!sessionId) {
    return res.status(400).json({ error: 'Session ID is required.' });
  }

  try {
    await db.revokeSession(sessionId, userId);
    await db.logSecurityEvent(userId, 'SESSION_REVOKED', ip, ua, `Revoked session ID: ${sessionId.substring(0, 8)}...`);

    // If revoking current session, clear cookie
    if (sessionId === req.user.sessionId) {
      res.clearCookie('token');
      return res.status(200).json({ message: 'Current session revoked. Logging out.', logged_out: true });
    }

    res.status(200).json({ message: 'Session successfully revoked.' });
  } catch (err) {
    res.status(500).json({ error: 'Server error revoking session.' });
  }
});

// Revoke all other sessions
app.post('/api/user/sessions/revoke-others', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const sessionId = req.user.sessionId;
  const ip = req.ip;
  const ua = req.get('User-Agent');

  try {
    await db.revokeAllOtherSessions(sessionId, userId);
    await db.logSecurityEvent(userId, 'SESSIONS_REVOKED_ALL_OTHERS', ip, ua, 'Revoked all other active sessions.');
    res.status(200).json({ message: 'All other sessions successfully revoked.' });
  } catch (err) {
    res.status(500).json({ error: 'Server error revoking other sessions.' });
  }
});

// Get Security Logs
app.get('/api/user/logs', authenticateToken, async (req, res) => {
  try {
    const logs = await db.getSecurityLogs(req.user.id);
    res.status(200).json(logs);
  } catch (err) {
    res.status(500).json({ error: 'Server error fetching audit logs.' });
  }
});

// Development-only testing endpoints
if (process.env.NODE_ENV === 'development' || !process.env.NODE_ENV) {
  app.get('/api/test/totp', (req, res) => {
    const { secret } = req.query;
    if (!secret) return res.status(400).json({ error: 'Secret parameter is required.' });
    try {
      const token = speakeasy.totp({
        secret: secret,
        encoding: 'base32'
      });
      res.json({ token });
    } catch (err) {
      res.status(500).json({ error: 'Failed to generate token' });
    }
  });
}

// Start Server
app.listen(PORT, () => {
  console.log(`Secure Auth server running on http://localhost:${PORT}`);
});
