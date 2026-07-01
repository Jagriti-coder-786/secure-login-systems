# ShieldAuth — Advanced Secure Login System

A production-grade, feature-rich secure authentication system built with **Node.js**, **Express**, and **SQLite**. It implements every modern security best practice in one clean, visually stunning package.

---

## ✨ Features

| Feature | Details |
|---|---|
| 🔐 Password Hashing | **bcryptjs** with 12 salt rounds |
| 🛡️ Security Headers | **Helmet.js** (CSP, HSTS, X-Frame-Options, etc.) |
| 🚫 Rate Limiting | IP-based via `express-rate-limit` (15 auth attempts / 15 min) |
| 🔒 Account Lockout | Locked for **15 minutes** after 5 consecutive failed logins |
| 📱 Two-Factor Auth | **TOTP / RFC 6238** (Google Authenticator, Authy compatible) |
| 🔑 Backup Recovery | One-time-use backup recovery codes generated on 2FA setup |
| 🍪 Secure Sessions | **JWT** via `HttpOnly + SameSite=Strict + Signed` cookies |
| 🖥️ Session Management | View & revoke active sessions per device |
| 📜 Audit Logs | Full security event log (logins, failures, lockouts, MFA changes) |
| 🔁 Password Reset | Token-based reset flow with 15-minute expiry |
| 🛡️ SQL Injection Safe | All queries use parameterized statements |
| 🎨 Modern UI | Glassmorphism dark theme, animated backgrounds, toast notifications |

---

## 🚀 Getting Started

### Prerequisites
- [Node.js](https://nodejs.org/) v18 or later

### Installation

```bash
# Clone the repository
git clone https://github.com/<your-username>/secure-login-system.git
cd secure-login-system

# Install dependencies
npm install
```

### Configuration

Copy the `.env.example` to `.env` and update with your own secrets:

```bash
cp .env.example .env
```

`.env` format:
```
PORT=3000
NODE_ENV=development
JWT_SECRET=your_strong_random_jwt_secret_here
COOKIE_SECRET=your_strong_random_cookie_secret_here
```

> ⚠️ **Never commit your `.env` file.** It is included in `.gitignore`.

### Run

```bash
npm start
```

Open your browser at **http://localhost:3000**

---

## 🗂️ Project Structure

```
secure-login-system/
├── server.js           # Main Express server, routes, security middleware
├── database.js         # SQLite helper, schemas, parameterized queries
├── package.json
├── .env.example        # Safe template for environment variables
├── .gitignore
└── public/
    ├── index.html      # Single-page application (SPA) HTML
    ├── css/
    │   └── style.css   # Glassmorphism UI design system
    └── js/
        └── app.js      # Client-side SPA logic, API calls, dashboard
```

---

## 🔒 Security Architecture

### Password Security
- Passwords are hashed with **bcrypt** using 12 rounds before storage.
- Strict password policy enforced client-side AND server-side (uppercase, lowercase, number, special character, minimum 8 chars).

### Brute Force Protection
- After **5 failed login attempts**, the account is locked for **15 minutes**.
- The IP address is additionally rate-limited to 15 authentication requests per 15-minute window.

### Session Security
- JWT tokens are stored in **HttpOnly, Signed, SameSite=Strict** cookies — inaccessible to JavaScript (prevents XSS token theft).
- Each session is tracked in the database; sessions can be individually revoked from any device.

### 2FA / MFA (TOTP)
- Follows **RFC 6238 TOTP** standard, compatible with Google Authenticator, Authy, and Microsoft Authenticator.
- Includes **5 one-time-use backup recovery codes** generated during setup.

### Security Audit Trail
- Every significant event is stored: signups, logins (success & failure), lockouts, password resets, 2FA changes, session revocations.
- All audit entries include timestamp, IP address, and user agent.

---

## 📸 UI Highlights

- **Galactic Cyber-Glass** dark theme with animated gradient background blobs
- Real-time password strength meter with requirement checklist
- Toast notifications for all operations
- Responsive dashboard with session cards and scrollable audit log table

---

## 🧪 Testing

A development-only TOTP endpoint is available to programmatically generate codes for testing:

```
GET /api/test/totp?secret=<base32_secret>
```

> This endpoint is **disabled in production** (`NODE_ENV=production`).

---

## 📝 License

MIT License © 2026
