require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const path = require('path');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const nodemailer = require('nodemailer');
const QRCode = require('qrcode');
const crypto = require('crypto');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;
app.set('trust proxy', process.env.TRUST_PROXY || 'loopback');
app.disable('x-powered-by');

let lockdownEnabled = false;
db.get(`SELECT value FROM settings WHERE key = 'lockdown_mode'`, (err, row) => {
  if (!err && row && typeof row.value === 'string') {
    lockdownEnabled = row.value === 'true';
  }
});

const setLockdown = (enabled) => {
  lockdownEnabled = !!enabled;
  db.run(
    `INSERT INTO settings (key, value) VALUES ('lockdown_mode', ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP`,
    [lockdownEnabled ? 'true' : 'false']
  );
};

let firewallEnabled = false;
db.get(`SELECT value FROM settings WHERE key = 'firewall_mode'`, (err, row) => {
  if (!err && row && typeof row.value === 'string') {
    firewallEnabled = row.value === 'true';
  }
});

const setFirewall = (enabled) => {
  firewallEnabled = !!enabled;
  db.run(
    `INSERT INTO settings (key, value) VALUES ('firewall_mode', ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP`,
    [firewallEnabled ? 'true' : 'false']
  );
};

// ============ LOGGING ============
const logEvent = (level, message, meta = {}) => {
  const entry = {
    ts: new Date().toISOString(),
    level,
    message,
    ...meta
  };
  const payload = JSON.stringify(entry);
  if (level === 'error') {
    console.error(payload);
  } else {
    console.log(payload);
  }

  try {
    db.run(
      'INSERT INTO security_logs (ts, level, message, meta_json) VALUES (?, ?, ?, ?)',
      [entry.ts, level, message, JSON.stringify(meta || {})]
    );
  } catch (e) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', message: 'security_logs.insert_failed', error: e.message }));
  }
};

// ============ HILFSFUNKTIONEN ============

// Funktion zum Generieren des 8-stelligen Codes
function generateBookingCode(length = 8) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Ohne I, 1, 0, O zur besseren Lesbarkeit
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// Base32 -> Buffer (für TOTP)
function base32ToBuffer(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = (input || '').toString().toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (const ch of clean) {
    const val = alphabet.indexOf(ch);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

function generateTotp(secret, timestamp = Date.now(), step = 30, digits = 6) {
  const key = base32ToBuffer(secret);
  const counter = Math.floor(timestamp / 1000 / step);
  const msg = Buffer.alloc(8);
  msg.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  msg.writeUInt32BE(counter & 0xffffffff, 4);
  const hmac = crypto.createHmac('sha1', key).update(msg).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = (hmac.readUInt32BE(offset) & 0x7fffffff) % (10 ** digits);
  return code.toString().padStart(digits, '0');
}

function verifyTotp(token, secret) {
  const value = (token || '').toString().replace(/\s+/g, '');
  if (!value || !secret) return false;
  const now = Date.now();
  for (let w = -1; w <= 1; w++) {
    const expected = generateTotp(secret, now + w * 30000);
    if (crypto.timingSafeEqual(Buffer.from(value), Buffer.from(expected))) {
      return true;
    }
  }
  return false;
}

function safeEqual(a, b) {
  if (!a || !b) return false;
  const aBuf = Buffer.from(a);
  const bBuf = Buffer.from(b);
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

// ============ KONFIGURATION ============

// Email Transporter konfigurieren
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: process.env.SMTP_PORT || 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// Test Email-Verbindung
if (process.env.SMTP_USER && process.env.SMTP_PASS) {
  transporter.verify((error, success) => {
    if (error) {
      console.log('⚠️  Email-Konfiguration Fehler:', error.message);
    } else {
      console.log('✓ Email-Server bereit');
    }
  });
}

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10
});

const otpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 5
});

// Middleware
const FORCE_HTTPS = process.env.FORCE_HTTPS === 'true';
if (process.env.NODE_ENV === 'production' && FORCE_HTTPS) {
  app.use((req, res, next) => {
    if (!req.secure) {
      return res.redirect(301, `https://${req.headers.host}${req.originalUrl}`);
    }
    next();
  });
}

app.use((req, res, next) => {
  req.requestId = crypto.randomUUID();
  const start = Date.now();
  res.on('finish', () => {
    logEvent('info', 'request.completed', {
      requestId: req.requestId,
      method: req.method,
      path: req.originalUrl,
      status: res.statusCode,
      durationMs: Date.now() - start,
      ip: req.ip
    });
  });
  next();
});

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      baseUri: ["'self'"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      styleSrc: ["'self'", "https://fonts.googleapis.com", "'unsafe-inline'"],
      scriptSrc: ["'self'", "https://challenges.cloudflare.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://challenges.cloudflare.com"],
      frameSrc: ["https://challenges.cloudflare.com"],
      frameAncestors: ["'none'"]
    }
  },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  crossOriginEmbedderPolicy: false,
  ...(process.env.NODE_ENV === 'production'
    ? { hsts: { maxAge: 15552000, includeSubDomains: true, preload: true } }
    : { hsts: false })
}));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

app.use(limiter);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    maxAge: 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
  }
}));
app.use(passport.initialize());
app.use(passport.session());


// ============ PASSPORT CONFIGURATION ============

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  db.get('SELECT * FROM users WHERE id = ?', [id], (err, user) => {
    done(err, user);
  });
});

// Local Strategy
passport.use(new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password'
}, (email, password, done) => {
  db.get('SELECT * FROM users WHERE email = ? AND provider = ?', [email, 'local'], (err, user) => {
    if (err) return done(err);
    if (!user) return done(null, false, { message: 'Ungültige E-Mail oder Passwort' });
    
    bcrypt.compare(password, user.password_hash, (err, result) => {
      if (err) return done(err);
      if (!result) return done(null, false, { message: 'Ungültige E-Mail oder Passwort' });
      
      db.run('UPDATE users SET letzter_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);
      return done(null, user);
    });
  });
}));

// Google Strategy
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL
  }, (accessToken, refreshToken, profile, done) => {
    db.get('SELECT * FROM users WHERE provider_id = ? AND provider = ?', 
      [profile.id, 'google'], (err, user) => {
        if (err) return done(err);
        
        if (user) {
          db.run('UPDATE users SET letzter_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);
          return done(null, user);
        }
        
        const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;
        const name = profile.displayName;
        const avatar = profile.photos && profile.photos[0] ? profile.photos[0].value : null;
        
        db.run(`INSERT INTO users (email, name, provider, provider_id, avatar_url, letzter_login) 
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
          [email, name, 'google', profile.id, avatar], function(err) {
            if (err) return done(err);
            
            db.get('SELECT * FROM users WHERE id = ?', [this.lastID], (err, newUser) => {
              return done(err, newUser);
            });
          });
      });
  }));
}

// GitHub Strategy
if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: process.env.GITHUB_CALLBACK_URL
  }, (accessToken, refreshToken, profile, done) => {
    db.get('SELECT * FROM users WHERE provider_id = ? AND provider = ?', 
      [profile.id, 'github'], (err, user) => {
        if (err) return done(err);
        
        if (user) {
          db.run('UPDATE users SET letzter_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);
          return done(null, user);
        }
        
        const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;
        const name = profile.displayName || profile.username;
        const avatar = profile.photos && profile.photos[0] ? profile.photos[0].value : null;
        
        db.run(`INSERT INTO users (email, name, provider, provider_id, avatar_url, letzter_login) 
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
          [email, name, 'github', profile.id, avatar], function(err) {
            if (err) return done(err);
            
            db.get('SELECT * FROM users WHERE id = ?', [this.lastID], (err, newUser) => {
              return done(err, newUser);
            });
          });
      });
  }));
}

// ============ CLOUDFLARE TURNSTILE VALIDATION ============
const verifyTurnstile = async (token, ip) => {
    const secretKey = process.env.CF_TURNSTILE_SECRET_KEY;
    
    // Wenn kein Secret Key gesetzt ist, Skip (für Entwicklung)
    if (!secretKey) {
        console.log('⚠️ Turnstile Secret Key nicht gesetzt - Skip Validierung');
        return { success: true };
    }
    
    try {
        const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                secret: secretKey,
                response: token,
                remoteip: ip
            })
        });
        
        const result = await response.json();
        return result;
        
    } catch (error) {
        console.error('Turnstile verification error:', error);
        return { success: false, error: 'Verifikation fehlgeschlagen' };
    }
};

// Route zum Überprüfen des Passworts (mit Turnstile)
app.post('/api/app-password', async (req, res) => {
    const { password, cf_turnstile_response } = req.body;
    const correctPassword = process.env.APP_PASSWORD;
    
    // Turnstile Validierung
    if (cf_turnstile_response) {
        const turnstileResult = await verifyTurnstile(cf_turnstile_response, req.ip);
        
        if (!turnstileResult.success) {
            return res.status(400).json({ 
                success: false, 
                error: 'Bot-Verifikation fehlgeschlagen. Bitte erneut versuchen.' 
            });
        }
    } else {
        // Nur in Entwicklung ohne Turnstile erlauben
        if (process.env.NODE_ENV !== 'production') {
            console.log('⚠️ Entwicklungsumgebung: Turnstile übersprungen');
        } else {
            return res.status(400).json({ 
                success: false, 
                error: 'Bot-Verifikation erforderlich' 
            });
        }
    }
    
    // Passwort-Überprüfung
    if (!correctPassword) {
        return res.json({ success: true }); // Kein Passwort gesetzt
    }
    
    if (password === correctPassword) {
        req.session.appPasswordVerified = true;
        logEvent('info', 'appPassword.verified', { requestId: req.requestId, ip: req.ip });
        res.json({ success: true, message: 'Passwort korrekt' });
    } else {
        logEvent('warn', 'appPassword.invalid', { requestId: req.requestId, ip: req.ip });
        res.status(401).json({ success: false, error: 'Falscher Zugangscode' });
    }
});

// ============ APP PASSWORD PROTECTION ============
const GOOGLE_VERIFICATION_FILE = '/googlee5c0a0d064e3bb72.html';
const LANDING_PAGE_PATH = '/cj';
const LANDING_PAGE_FILE = '/cj.html';
const isVerificationFile = (path) => path === GOOGLE_VERIFICATION_FILE;
const PUBLIC_PAGES = ['/impressum', '/datenschutz', '/cookies', '/agb', '/impressum.html', '/datenschutz.html', '/cookies.html', '/agb.html'];
const requireAppPassword = (req, res, next) => {
  const appPassword = process.env.APP_PASSWORD;
  
  // Wenn kein Passwort in .env gesetzt ist, Skip
  if (!appPassword) {
    return next();
  }
  
  // Erlaube Zugriff auf Passwort-Route, Security Center und statische Dateien
  if (
    req.path === '/api/app-password' ||
    req.path === '/password.html' ||
    req.path === '/password.js' ||
    req.path.startsWith('/security-center') ||
    req.path.startsWith('/api/developer') ||
    req.path.startsWith('/api/security') ||
    req.path.startsWith('/lockdown') ||
    isVerificationFile(req.path) ||
    req.path === LANDING_PAGE_PATH ||
    req.path === LANDING_PAGE_FILE ||
    PUBLIC_PAGES.includes(req.path) ||
    req.path.endsWith('.css') ||
    req.path.endsWith('.js') ||
    req.path.endsWith('.png') ||
    req.path.endsWith('.svg') ||
    req.path.endsWith('.ico')
  ) {
    return next();
  }
  
  // Überprüfe ob Passwort in Session gespeichert ist
  if (req.session.appPasswordVerified) {
    return next();
  }
  
  // Blockiere Zugriff
  if (req.path.startsWith('/api')) {
    return res.status(403).json({ error: 'Passwort erforderlich', requirePassword: true });
  }
  return res.redirect(302, '/password.html');
};

const lockdownGate = (req, res, next) => {
  if (!lockdownEnabled) return next();

  const devOk = req.session && req.session.developer && req.session.developer.mfaVerified;
  const allowPaths = [
    '/lockdown',
    '/security-center',
    '/api/developer',
    '/api/security',
    '/security-center.css',
    '/security-center.js'
  ];
  if (devOk) return next();
  if (allowPaths.some(p => req.path.startsWith(p))) return next();
  if (isVerificationFile(req.path)) return next();
  if (req.path === LANDING_PAGE_PATH || req.path === LANDING_PAGE_FILE) return next();
  if (PUBLIC_PAGES.includes(req.path)) return next();
  return res.redirect(302, '/lockdown');
};

let ipRulesCache = { ts: 0, allow: [], deny: [] };
const loadIpRules = (cb) => {
  const now = Date.now();
  if (now - ipRulesCache.ts < 10000) return cb(null, ipRulesCache);
  db.all(`SELECT ip, rule_type FROM security_ip_rules`, (err, rows) => {
    if (err) return cb(err);
    const allow = [];
    const deny = [];
    (rows || []).forEach(r => {
      if (r.rule_type === 'allow') allow.push(r.ip);
      if (r.rule_type === 'deny') deny.push(r.ip);
    });
    ipRulesCache = { ts: now, allow, deny };
    cb(null, ipRulesCache);
  });
};

const firewallGate = (req, res, next) => {
  if (!firewallEnabled) return next();

  const devOk = req.session && req.session.developer && req.session.developer.mfaVerified;
  if (devOk) return next();

  loadIpRules((err, rules) => {
    if (err) return res.status(500).send('Firewall Fehler');
    const ip = req.ip;
    if (rules.deny.includes(ip)) {
      return res.status(403).send('Zugriff verweigert');
    }
    if (rules.allow.length > 0 && !rules.allow.includes(ip)) {
      return res.status(403).send('Zugriff verweigert');
    }
    next();
  });
};

// Middleware anwenden (vor allen anderen Routen)
app.use(lockdownGate);
app.use(firewallGate);
app.use(requireAppPassword);
app.use(express.static('public'));

// Route zum Ausloggen (Passwort zurücksetzen)
app.post('/api/app-password/logout', (req, res) => {
  req.session.appPasswordVerified = false;
  res.json({ success: true, message: 'Passwort zurückgesetzt' });
});

// Kontaktformular (öffentlich)
app.post('/api/contact', (req, res) => {
  const { name, email, message, turnstileToken } = req.body || {};
  if (!name || !email || !message) {
    return res.status(400).json({ error: 'Name, Email und Nachricht sind erforderlich' });
  }
  if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
    return res.status(500).json({ error: 'SMTP ist nicht konfiguriert' });
  }
  if (!process.env.CF_TURNSTILE_SECRET_KEY_CJ) {
    return res.status(500).json({ error: 'Turnstile ist nicht konfiguriert' });
  }
  if (!turnstileToken) {
    return res.status(400).json({ error: 'Turnstile Token fehlt' });
  }

  const https = require('https');
  const postData = new URLSearchParams({
    secret: process.env.CF_TURNSTILE_SECRET_KEY_CJ,
    response: turnstileToken,
    remoteip: req.ip
  }).toString();

  const verifyOptions = {
    hostname: 'challenges.cloudflare.com',
    port: 443,
    path: '/turnstile/v0/siteverify',
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': Buffer.byteLength(postData)
    }
  };

  const verifyReq = https.request(verifyOptions, (verifyRes) => {
    let data = '';
    verifyRes.on('data', (chunk) => { data += chunk; });
    verifyRes.on('end', () => {
      let payload = null;
      try { payload = JSON.parse(data); } catch (_) {}
      if (!payload || payload.success !== true) {
        return res.status(400).json({ error: 'Turnstile Verifikation fehlgeschlagen' });
      }

      const adminEmail = process.env.SMTP_USER;
      const mailOptions = {
        from: process.env.SMTP_USER,
        to: adminEmail,
        replyTo: email,
        subject: 'Website Admin Kontakt aufnehmen',
        html: `
          <div style="font-family: sans-serif; padding: 16px;">
            <h2>Neue Nachricht ueber die Website</h2>
            <p><strong>Name:</strong> ${String(name)}</p>
            <p><strong>Email:</strong> ${String(email)}</p>
            <p><strong>Nachricht:</strong></p>
            <p>${String(message).replace(/\\n/g, '<br>')}</p>
          </div>
        `
      };

      transporter.sendMail(mailOptions, (err) => {
        if (err) {
          console.error('Kontakt Email Fehler:', err);
          return res.status(500).json({ error: 'Email konnte nicht gesendet werden' });
        }
        return res.json({ success: true });
      });
    });
  });

  verifyReq.on('error', (err) => {
    console.error('Turnstile Verify Fehler:', err);
    return res.status(500).json({ error: 'Turnstile Verifikation fehlgeschlagen' });
  });

  verifyReq.write(postData);
  verifyReq.end();
});

const requireAuth = (req, res, next) => {
  if (req.isAuthenticated()) {
    next();
  } else {
    res.status(401).json({ error: 'Nicht angemeldet' });
  }
};

const requireAdmin = (req, res, next) => {
  if (req.session && req.session.admin) {
    next();
  } else {
    res.status(401).json({ error: 'Nicht autorisiert' });
  }
};

const requireDeveloper2FA = (req, res, next) => {
  if (req.session && req.session.developer && req.session.developer.mfaVerified) {
    return next();
  }
  res.status(401).json({ error: 'Developer Zugriff erforderlich' });
};


const blockMobileAndBots = (req, res, next) => {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  const isBot = /bot|crawl|spider|scanner|wget|curl|python-requests/.test(ua);
  const isMobile = /mobi|android|iphone|ipad|ipod|tablet/.test(ua);
  if (isBot) {
    return res.status(403).send('Zugriff verweigert');
  }
  if (isMobile) {
    return res.status(403).send('Diese Seite ist nur fuer Laptop/Desktop erlaubt');
  }
  next();
};

// ============ AUTH ROUTES ============

app.post('/auth/register', async (req, res) => {
  const { email, password, name } = req.body;
  
  // Validierung
  if (!email || !password || !name) {
    return res.status(400).json({ error: 'Alle Felder sind erforderlich' });
  }
  
  try {
    db.get('SELECT id FROM users WHERE email = ?', [email], async (err, existing) => {
      if (err) return res.status(500).json({ error: err.message });
      if (existing) return res.status(400).json({ error: 'E-Mail bereits registriert' });
      
      const hash = await bcrypt.hash(password, 10);
      
      db.run(`INSERT INTO users (email, name, provider, password_hash) VALUES (?, ?, ?, ?)`,
        [email, name, 'local', hash], function(err) {
          if (err) return res.status(500).json({ error: err.message });
          
          db.get('SELECT * FROM users WHERE id = ?', [this.lastID], (err, user) => {
            if (err) return res.status(500).json({ error: err.message });
            
            req.login(user, (err) => {
              if (err) return res.status(500).json({ error: err.message });
              logEvent('info', 'auth.register', { requestId: req.requestId, userId: user.id, email: user.email });
              res.json({ message: 'Erfolgreich registriert', user: { id: user.id, email: user.email, name: user.name } });
            });
          });
        });
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/auth/login', passport.authenticate('local'), (req, res) => {
  logEvent('info', 'auth.login', { requestId: req.requestId, userId: req.user.id, email: req.user.email });
  res.json({ 
    message: 'Erfolgreich angemeldet', 
    user: { 
      id: req.user.id, 
      email: req.user.email, 
      name: req.user.name,
      avatar_url: req.user.avatar_url
    } 
  });
});

// ============ DEVELOPER SECURITY CENTER ============
app.get('/security-center', blockMobileAndBots, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'security-center.html'));
});

app.get('/lockdown', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'lockdown.html'));
});

app.get('/api/developer/status', blockMobileAndBots, (req, res) => {
  const dev = req.session && req.session.developer ? req.session.developer : null;
  res.json({
    loggedIn: !!dev,
    mfaVerified: !!(dev && dev.mfaVerified),
    username: dev ? dev.username : null
  });
});

app.post('/api/developer/login', blockMobileAndBots, authLimiter, (req, res) => {
  const { username, password } = req.body;
  const expectedUser = process.env.DEV_USERNAME;
  const expectedPass = process.env.DEV_PASSWORD;

  if (!expectedUser || !expectedPass) {
    return res.status(500).json({ error: 'Developer Zugang ist nicht konfiguriert' });
  }

  if (!username || !password) {
    return res.status(400).json({ error: 'Benutzername und Passwort erforderlich' });
  }

  const userOk = safeEqual(username, expectedUser);
  const passOk = safeEqual(password, expectedPass);

  if (!userOk || !passOk) {
    logEvent('warn', 'developer.login.failed', { requestId: req.requestId, ip: req.ip });
    return res.status(401).json({ error: 'Ungültige Anmeldedaten' });
  }

  req.session.developer = { username: expectedUser, mfaVerified: false };
  logEvent('info', 'developer.login.success', { requestId: req.requestId, ip: req.ip, username: expectedUser });
  res.json({ message: 'Login ok, 2FA erforderlich', mfaRequired: true });
});

app.post('/api/developer/request-otp', blockMobileAndBots, otpLimiter, (req, res) => {
  const targetEmail = process.env.DEV_2FA_EMAIL;

  if (!req.session || !req.session.developer) {
    return res.status(401).json({ error: 'Bitte zuerst einloggen' });
  }
  if (!targetEmail) {
    return res.status(500).json({ error: '2FA Email ist nicht konfiguriert' });
  }
  if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
    return res.status(500).json({ error: 'SMTP ist nicht konfiguriert' });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const otpHash = crypto.createHash('sha256').update(otp).digest('hex');
  const expiresAt = Date.now() + 5 * 60 * 1000;

  req.session.developer.otpHash = otpHash;
  req.session.developer.otpExpiresAt = expiresAt;

  const mailOptions = {
    from: process.env.SMTP_USER,
    to: targetEmail,
    subject: 'Security Center 2FA Code',
    html: `<p>Dein 2FA Code lautet: <strong>${otp}</strong></p><p>Gueltig fuer 5 Minuten.</p>`
  };

  transporter.sendMail(mailOptions, (err) => {
    if (err) {
      logEvent('error', 'developer.otp.send_failed', { requestId: req.requestId, ip: req.ip, error: err.message });
      return res.status(500).json({ error: '2FA Email konnte nicht gesendet werden' });
    }
    logEvent('info', 'developer.otp.sent', { requestId: req.requestId, ip: req.ip, targetEmail });
    res.json({ message: '2FA Code gesendet' });
  });
});

app.post('/api/developer/verify-2fa', blockMobileAndBots, authLimiter, (req, res) => {
  const { token } = req.body;

  if (!req.session || !req.session.developer) {
    return res.status(401).json({ error: 'Bitte zuerst einloggen' });
  }
  if (!token) {
    return res.status(400).json({ error: '2FA Code erforderlich' });
  }
  const dev = req.session.developer;
  if (!dev.otpHash || !dev.otpExpiresAt) {
    return res.status(400).json({ error: 'Bitte zuerst einen 2FA Code anfordern' });
  }
  if (Date.now() > dev.otpExpiresAt) {
    return res.status(401).json({ error: '2FA Code abgelaufen' });
  }
  const tokenHash = crypto.createHash('sha256').update(token.toString().trim()).digest('hex');
  const ok = safeEqual(tokenHash, dev.otpHash);
  if (!ok) {
    logEvent('warn', 'developer.2fa.failed', { requestId: req.requestId, ip: req.ip, username: req.session.developer.username });
    return res.status(401).json({ error: '2FA Code ungültig' });
  }

  req.session.developer.mfaVerified = true;
  req.session.developer.otpHash = null;
  req.session.developer.otpExpiresAt = null;
  logEvent('info', 'developer.2fa.verified', { requestId: req.requestId, ip: req.ip, username: req.session.developer.username });
  res.json({ message: '2FA bestätigt' });
});

app.post('/api/developer/logout', blockMobileAndBots, (req, res) => {
  if (req.session) {
    req.session.developer = null;
  }
  res.json({ message: 'Abgemeldet' });
});

// ============ SECURITY DASHBOARD API ============
const parseDays = (value, fallback = 7) => {
  const n = parseInt(value, 10);
  if (Number.isNaN(n) || n <= 0) return fallback;
  return Math.min(n, 90);
};

const clamp = (n, min, max) => Math.min(Math.max(n, min), max);

const demoStats = (rangeDays = 7) => {
  const template = [
    { errors: 0, warnings: 1, infos: 20 },
    { errors: 0, warnings: 1, infos: 22 },
    { errors: 0, warnings: 1, infos: 19 },
    { errors: 0, warnings: 1, infos: 21 },
    { errors: 0, warnings: 0, infos: 25 },
    { errors: 0, warnings: 1, infos: 22 },
    { errors: 0, warnings: 0, infos: 19 }
  ];
  const now = new Date();
  return template
    .slice(-rangeDays)
    .map((row, idx, arr) => {
      const d = new Date(now);
      d.setHours(0, 0, 0, 0);
      d.setDate(d.getDate() - (arr.length - 1 - idx));
      return { day: d.toISOString().slice(0, 10), ...row };
    });
};

const demoHighlights = () => {
  const ts = new Date().toISOString();
  return [
    { ts, message: 'auth.login.failed', level: 'warn', count: 2 },
    { ts, message: 'developer.login.failed', level: 'warn', count: 1 },
    { ts, message: 'firewall.probe', level: 'warn', count: 1 }
  ];
};

const randomIp = () => {
  const ranges = [
    [203, 0, 113],
    [198, 51, 100],
    [192, 0, 2],
    [10, 10, 10]
  ];
  const base = ranges[Math.floor(Math.random() * ranges.length)];
  return `${base[0]}.${base[1]}.${base[2]}.${Math.floor(Math.random() * 200) + 1}`;
};

const seedSecurityLogs = (days = 7, countPerDay = 40, cb) => {
  const now = new Date();
  const messages = [
    { level: 'info', msg: 'page.view' },
    { level: 'info', msg: 'api.request' },
    { level: 'warn', msg: 'auth.login.failed' },
    { level: 'warn', msg: 'developer.login.failed' },
    { level: 'warn', msg: 'firewall.probe' },
    { level: 'error', msg: 'payment.gateway.timeout' }
  ];

  const stmt = db.prepare('INSERT INTO security_logs (ts, level, message, meta_json) VALUES (?, ?, ?, ?)');
  for (let d = 0; d < days; d++) {
    const day = new Date(now);
    day.setHours(12, 0, 0, 0);
    day.setDate(now.getDate() - d);
    for (let i = 0; i < countPerDay; i++) {
      const entry = messages[Math.floor(Math.random() * messages.length)];
      const ts = new Date(day.getTime() - Math.floor(Math.random() * 12 * 60 * 60 * 1000));
      const meta = { ip: randomIp(), path: '/api', method: 'GET' };
      stmt.run(ts.toISOString(), entry.level, entry.msg, JSON.stringify(meta));
    }
  }
  stmt.finalize(cb);
};

app.get('/api/security/summary', blockMobileAndBots, requireDeveloper2FA, (req, res) => {
  const days = parseDays(req.query.days, 7);
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

  db.get(
    `SELECT COUNT(*) as total,
            SUM(CASE WHEN level = 'error' THEN 1 ELSE 0 END) as errors,
            SUM(CASE WHEN level = 'warn' THEN 1 ELSE 0 END) as warnings,
            SUM(CASE WHEN level = 'info' THEN 1 ELSE 0 END) as infos
     FROM security_logs
     WHERE ts >= ?`,
    [since],
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      db.get(
        `SELECT ts as lastErrorAt
         FROM security_logs
         WHERE level = 'error'
         ORDER BY ts DESC
         LIMIT 1`,
        [],
        (err2, lastErrorRow) => {
          if (err2) return res.status(500).json({ error: err2.message });
  db.all(
    `SELECT message, level, MAX(ts) as ts, COUNT(*) as count
     FROM security_logs
     WHERE level IN ('warn','error') AND ts >= ?
     GROUP BY message, level
     ORDER BY count DESC
     LIMIT 5`,
    [since],
    (err3, warnings) => {
      if (err3) return res.status(500).json({ error: err3.message });
      let totals = {
        total: row ? row.total || 0 : 0,
        errors: row ? row.errors || 0 : 0,
        warnings: row ? row.warnings || 0 : 0,
        infos: row ? row.infos || 0 : 0
      };
      let highlights = (warnings || []).map(w => ({
        ts: w.ts,
        message: w.message,
        count: w.count || 1
      }));

      if (totals.total === 0) {
        const demo = demoStats(days);
        totals = demo.reduce((acc, r) => ({
          total: acc.total + r.errors + r.warnings + r.infos,
          errors: acc.errors + r.errors,
          warnings: acc.warnings + r.warnings,
          infos: acc.infos + r.infos
        }), { total: 0, errors: 0, warnings: 0, infos: 0 });
        highlights = demoHighlights();
      }

      res.json({
        rangeDays: days,
        totals,
        lastErrorAt: totals.errors > 0 ? (lastErrorRow ? lastErrorRow.lastErrorAt : new Date().toISOString()) : null,
        highlights
      });
    }
  );
        }
      );
    }
  );
});

app.get('/api/security/stats', blockMobileAndBots, requireDeveloper2FA, (req, res) => {
  const days = parseDays(req.query.days, 7);
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

  db.all(
    `SELECT date(ts) as day,
            SUM(CASE WHEN level = 'error' THEN 1 ELSE 0 END) as errors,
            SUM(CASE WHEN level = 'warn' THEN 1 ELSE 0 END) as warnings,
            SUM(CASE WHEN level = 'info' THEN 1 ELSE 0 END) as infos
     FROM security_logs
     WHERE ts >= ?
     GROUP BY date(ts)
     ORDER BY day ASC`,
    [since],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      const payload = rows && rows.length ? rows : demoStats(days);
      res.json({ rangeDays: days, rows: payload });
    }
  );
});

app.get('/api/security/logs', blockMobileAndBots, requireDeveloper2FA, (req, res) => {
  const days = parseDays(req.query.days, 7);
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  const level = (req.query.level || 'all').toLowerCase();
  const limit = clamp(parseInt(req.query.limit, 10) || 50, 1, 200);
  const offset = clamp(parseInt(req.query.offset, 10) || 0, 0, 10000);

  if (!['all', 'info', 'warn', 'error'].includes(level)) {
    return res.status(400).json({ error: 'Ungültiger level' });
  }

  const baseSql = `SELECT id, ts, level, message, meta_json
                   FROM security_logs
                   WHERE ts >= ?`;
  const levelSql = level === 'all' ? '' : ' AND level = ?';
  const sql = `${baseSql}${levelSql} ORDER BY ts DESC LIMIT ? OFFSET ?`;
  const params = level === 'all'
    ? [since, limit, offset]
    : [since, level, limit, offset];

  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    let data = rows || [];
    if (data.length === 0) {
      const demo = demoStats(days);
      data = demo.map((r, idx) => ({
        id: idx + 1,
        ts: new Date().toISOString(),
        level: r.warnings > 0 ? 'warn' : 'info',
        message: r.warnings > 0 ? 'auth.login.failed' : 'page.view',
        meta: { ip: idx % 2 === 0 ? '203.0.113.10' : '198.51.100.8' }
      }));
    } else {
      data = data.map(r => ({
        id: r.id,
        ts: r.ts,
        level: r.level,
        message: r.message,
        meta: r.meta_json ? JSON.parse(r.meta_json) : {}
      }));
    }
    res.json({ rangeDays: days, level, limit, offset, logs: data });
  });
});

app.get('/api/security/warnings', blockMobileAndBots, requireDeveloper2FA, (req, res) => {
  const days = parseDays(req.query.days, 7);
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  const limit = clamp(parseInt(req.query.limit, 10) || 20, 1, 200);

  db.all(
    `SELECT id, ts, level, message, meta_json
     FROM security_logs
     WHERE ts >= ? AND level IN ('warn','error')
     ORDER BY ts DESC
     LIMIT ?`,
    [since, limit],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      const data = rows && rows.length ? rows : demoHighlights();
      const logs = (data || []).map(r => ({
        id: r.id,
        ts: r.ts,
        level: r.level,
        message: r.message,
        meta: r.meta_json ? JSON.parse(r.meta_json) : {}
      }));
      res.json({ rangeDays: days, logs });
    }
  );
});

app.get('/api/security/insights', blockMobileAndBots, requireDeveloper2FA, (req, res) => {
  const days = parseDays(req.query.days, 7);
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  const limit = clamp(parseInt(req.query.limit, 10) || 500, 50, 2000);

  db.all(
    `SELECT ts, level, message, meta_json
     FROM security_logs
     WHERE ts >= ?
     ORDER BY ts DESC
     LIMIT ?`,
    [since, limit],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });

      const rowsSafe = rows || [];
      const useDemo = rowsSafe.length === 0;

      const messageCounts = {};
      const ipCounts = {};
      let failedLogins = 0;
      let otpFailures = 0;
      let adminActions = 0;

      const sourceRows = useDemo
        ? demoStats(days).map(r => ({
            ts: new Date().toISOString(),
            level: r.warnings > 0 ? 'warn' : 'info',
            message: r.warnings > 0 ? 'auth.login.failed' : 'page.view',
            meta_json: JSON.stringify({ ip: '203.0.113.10' })
          }))
        : rowsSafe;

      sourceRows.forEach(r => {
        const msg = r.message || 'unknown';
        messageCounts[msg] = (messageCounts[msg] || 0) + 1;

        let meta = {};
        try {
          meta = r.meta_json ? JSON.parse(r.meta_json) : {};
        } catch (_) {}
        if (meta.ip) {
          ipCounts[meta.ip] = (ipCounts[meta.ip] || 0) + 1;
        }
        if (msg.includes('auth.login') || msg.includes('admin.login') || msg.includes('developer.login')) {
          if (r.level === 'warn' || r.level === 'error') failedLogins += 1;
        }
        if (msg.includes('developer.2fa.failed')) {
          otpFailures += 1;
        }
        if (msg.startsWith('admin.')) {
          adminActions += 1;
        }
      });

      const topMessages = Object.entries(messageCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 6)
        .map(([message, count]) => ({ message, count }));

      const topIps = Object.entries(ipCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 6)
        .map(([ip, count]) => ({ ip, count }));

      if (useDemo) {
        failedLogins = 4;
        otpFailures = 2;
        adminActions = 3;
      }

      res.json({
        rangeDays: days,
        limit,
        topMessages,
        topIps,
        failedLogins,
        otpFailures,
        adminActions
      });
    }
  );
});

const getSettingsMap = (keys, cb) => {
  const placeholders = keys.map(() => '?').join(',');
  db.all(`SELECT key, value FROM settings WHERE key IN (${placeholders})`, keys, (err, rows) => {
    if (err) return cb(err);
    const map = {};
    (rows || []).forEach(r => { map[r.key] = r.value; });
    cb(null, map);
  });
};

const upsertSetting = (key, value) => {
  db.run(
    `INSERT INTO settings (key, value) VALUES (?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP`,
    [key, value]
  );
};

app.get('/api/security/metrics', blockMobileAndBots, requireDeveloper2FA, (req, res) => {
  const days = parseDays(req.query.days, 7);
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  const since30 = new Date(Date.now() - 30 * 60 * 1000).toISOString();
  const settingKeys = [
    'dlp_rules', 'key_rotation_days', 'vault_health',
    'last_backup_at', 'last_restore_test_at', 'db_integrity',
    'service_payment_status', 'service_payment_latency',
    'service_email_status', 'service_email_queue',
    'service_fraud_status', 'service_fraud_code'
  ];

  getSettingsMap(settingKeys, (err, settings) => {
    if (err) return res.status(500).json({ error: err.message });

    db.all(
      `SELECT date(ts) as day,
              SUM(CASE WHEN level = 'error' THEN 1 ELSE 0 END) as errors,
              SUM(CASE WHEN level = 'warn' THEN 1 ELSE 0 END) as warnings,
              SUM(CASE WHEN level = 'info' THEN 1 ELSE 0 END) as infos
       FROM security_logs
       WHERE ts >= ?
       GROUP BY date(ts)`,
      [since],
      (errStats, rows) => {
        if (errStats) return res.status(500).json({ error: errStats.message });
        const rowsSafe = rows && rows.length ? rows : demoStats(days);

        db.all(
          `SELECT meta_json FROM security_logs WHERE ts >= ?`,
          [since30],
          (errReq, recentRows) => {
            if (errReq) return res.status(500).json({ error: errReq.message });

            const perDayTotals = rowsSafe.map(r => (r.errors || 0) + (r.warnings || 0) + (r.infos || 0));
            const peak = perDayTotals.length ? Math.max(...perDayTotals) : 0;
            const avg = perDayTotals.length ? Math.round(perDayTotals.reduce((a, b) => a + b, 0) / perDayTotals.length) : 0;

            const ips = new Set();
            const metaSource = recentRows && recentRows.length ? recentRows : [{ meta_json: JSON.stringify({ ip: '203.0.113.10' }) }, { meta_json: JSON.stringify({ ip: '198.51.100.8' }) }];
            metaSource.forEach(r => {
              try {
                const meta = r.meta_json ? JSON.parse(r.meta_json) : {};
                if (meta.ip) ips.add(meta.ip);
              } catch (e) {}
            });

            const errorsTotal = rowsSafe.reduce((acc, r) => acc + (r.errors || 0), 0);
            const warningsTotal = rowsSafe.reduce((acc, r) => acc + (r.warnings || 0), 0);
            const threatLevel = errorsTotal > 5 ? 'Hoch' : warningsTotal > 10 ? 'Mittel' : 'Niedrig';

            const scorePenalty = (errorsTotal * 2) + (warningsTotal * 0.5) + Math.min(10, Math.floor((peak || 0) / 50));
            const postureScore = Math.max(40, Math.min(99, Math.round(100 - scorePenalty)));

            const policyCoverage = Math.max(70, Math.min(99, 95 - warningsTotal));
            const misconfigAlerts = Math.min(12, Math.round(warningsTotal / 2));
            const endpointDrift = Math.min(9, Math.round(errorsTotal / 2));

            const uptime = Math.max(95.0, Math.min(99.99, 99.99 - errorsTotal * 0.02)).toFixed(2);

            const defaultBackup = new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString();
            const defaultRestore = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();

            const dlpRules = parseInt(settings.dlp_rules || '18', 10);
            const keyRotation = settings.key_rotation_days || '14d';
            const vaultHealth = settings.vault_health || 'OK';
            const lastBackup = settings.last_backup_at || defaultBackup;
            const lastRestoreTest = settings.last_restore_test_at || defaultRestore;
            const dbIntegrity = settings.db_integrity || 'OK';

            // Persist defaults so future reads have values
            if (!settings.dlp_rules) upsertSetting('dlp_rules', dlpRules.toString());
            if (!settings.key_rotation_days) upsertSetting('key_rotation_days', keyRotation);
            if (!settings.vault_health) upsertSetting('vault_health', vaultHealth);
            if (!settings.last_backup_at) upsertSetting('last_backup_at', lastBackup);
            if (!settings.last_restore_test_at) upsertSetting('last_restore_test_at', lastRestoreTest);
            if (!settings.db_integrity) upsertSetting('db_integrity', dbIntegrity);

            const services = {
              payment: {
                latency: parseInt(settings.service_payment_latency || '120', 10),
                status: { label: settings.service_payment_status || 'Operational', tone: 'ok' }
              },
              email: {
                queue: parseInt(settings.service_email_queue || '0', 10),
                status: { label: settings.service_email_status || 'Operational', tone: 'ok' }
              },
              fraud: {
                code: settings.service_fraud_code || '200',
                status: { label: settings.service_fraud_status || 'Degraded', tone: 'warn' }
              }
            };

            const geo = { DE: 62, AT: 18, CH: 9, NL: 6, US: 5 };
            const devices = { desktop: 68, mobile: 29, tablet: 3 };

            res.json({
              threat: { level: threatLevel, hint: `${errorsTotal} Errors, ${warningsTotal} Warnungen` },
              posture: {
                score: postureScore,
                policyCoverage,
                misconfigAlerts,
                endpointDrift,
                label: postureScore > 85 ? 'Stabil' : postureScore > 70 ? 'Beobachten' : 'Kritisch',
                tone: postureScore > 85 ? 'ok' : 'warn'
              },
              sessions: { active: ips.size, uptime },
              chart: { peak, avg },
              signals: {
                login: { label: warningsTotal + errorsTotal > 0 ? 'erkannt' : 'keine Aktivität', tone: warningsTotal + errorsTotal > 0 ? 'ok' : 'warn' },
                page: { label: peak > 0 ? 'aktiv' : 'keine Aktivität', tone: peak > 0 ? 'ok' : 'warn' },
                checkout: { label: warningsTotal > 0 ? 'prüfen' : 'keine Aktivität', tone: warningsTotal > 0 ? 'warn' : 'ok' },
                admin: { label: errorsTotal > 0 ? 'erkannt' : 'keine Aktivität', tone: errorsTotal > 0 ? 'ok' : 'warn' },
                pdf: { label: peak > 0 ? 'bereit' : 'keine Aktivität', tone: peak > 0 ? 'ok' : 'warn' },
                api: { label: peak > 0 ? 'aktiv' : 'keine Aktivität', tone: peak > 0 ? 'ok' : 'warn' }
              },
              behavior: {
                sessionDrift: Math.min(9, warningsTotal),
                geoShift: Math.min(7, Math.round(warningsTotal / 2)),
                deviceShift: Math.min(5, Math.round(errorsTotal / 2))
              },
              dataProtection: {
                dlpRules,
                keyRotation,
                vaultHealth,
                lastBackup,
                restoreTest: lastRestoreTest,
                dbIntegrity
              },
              services,
              geo,
              devices
            });
          }
        );
      }
    );
  });
});

app.post('/api/security/seed-demo', blockMobileAndBots, requireDeveloper2FA, (req, res) => {
  const reset = req.body && req.body.reset;
  const days = clamp(parseInt(req.body?.days, 10) || 7, 1, 30);
  const count = clamp(parseInt(req.body?.count, 10) || 40, 5, 200);

  const afterSeed = (err) => {
    if (err) return res.status(500).json({ error: err.message });
    logEvent('info', 'security.seed.created', { requestId: req.requestId, days, count });
    res.json({ message: 'Demo-Logs erstellt', days, count });
  };

  if (reset) {
    db.run('DELETE FROM security_logs', [], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      seedSecurityLogs(days, count, afterSeed);
    });
  } else {
    seedSecurityLogs(days, count, afterSeed);
  }
});

app.get('/api/security/lockdown', blockMobileAndBots, requireDeveloper2FA, (req, res) => {
  res.json({ enabled: lockdownEnabled });
});

app.post('/api/security/lockdown', blockMobileAndBots, requireDeveloper2FA, (req, res) => {
  const enabled = !!req.body.enabled;
  setLockdown(enabled);
  logEvent('info', 'security.lockdown.set', { requestId: req.requestId, enabled, ip: req.ip });
  res.json({ enabled });
});

app.get('/api/security/firewall', blockMobileAndBots, requireDeveloper2FA, (req, res) => {
  res.json({ enabled: firewallEnabled });
});

app.post('/api/security/firewall', blockMobileAndBots, requireDeveloper2FA, (req, res) => {
  const enabled = !!req.body.enabled;
  setFirewall(enabled);
  logEvent('info', 'security.firewall.set', { requestId: req.requestId, enabled, ip: req.ip });
  res.json({ enabled });
});

app.get('/api/security/ip-rules', blockMobileAndBots, requireDeveloper2FA, (req, res) => {
  db.all(`SELECT id, ip, rule_type, created_at FROM security_ip_rules ORDER BY created_at DESC`, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows || []);
  });
});

app.post('/api/security/ip-rules', blockMobileAndBots, requireDeveloper2FA, (req, res) => {
  const { ip, rule_type } = req.body;
  if (!ip || !rule_type || !['allow', 'deny'].includes(rule_type)) {
    return res.status(400).json({ error: 'IP und rule_type erforderlich' });
  }
  db.run(`INSERT INTO security_ip_rules (ip, rule_type) VALUES (?, ?)`, [ip, rule_type], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    ipRulesCache.ts = 0;
    logEvent('info', 'security.iprule.add', { requestId: req.requestId, ip, rule_type });
    res.json({ id: this.lastID, ip, rule_type });
  });
});

app.delete('/api/security/ip-rules/:id', blockMobileAndBots, requireDeveloper2FA, (req, res) => {
  const id = req.params.id;
  db.run(`DELETE FROM security_ip_rules WHERE id = ?`, [id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: 'Regel nicht gefunden' });
    ipRulesCache.ts = 0;
    logEvent('info', 'security.iprule.delete', { requestId: req.requestId, id });
    res.json({ message: 'Regel geloescht' });
  });
});

app.get('/api/security/logs/search', blockMobileAndBots, requireDeveloper2FA, (req, res) => {
  const days = parseDays(req.query.days, 7);
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  const q = (req.query.q || '').trim();
  const level = (req.query.level || 'all').toLowerCase();
  const limit = clamp(parseInt(req.query.limit, 10) || 50, 1, 200);
  const offset = clamp(parseInt(req.query.offset, 10) || 0, 0, 10000);

  if (!q) return res.json({ logs: [], rangeDays: days, level, limit, offset });
  if (!['all', 'info', 'warn', 'error'].includes(level)) {
    return res.status(400).json({ error: 'Ungültiger level' });
  }

  const baseSql = `SELECT id, ts, level, message, meta_json
                   FROM security_logs
                   WHERE ts >= ? AND (message LIKE ? OR meta_json LIKE ?)`;
  const levelSql = level === 'all' ? '' : ' AND level = ?';
  const sql = `${baseSql}${levelSql} ORDER BY ts DESC LIMIT ? OFFSET ?`;
  const like = `%${q}%`;
  const params = level === 'all'
    ? [since, like, like, limit, offset]
    : [since, like, like, level, limit, offset];

  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const logs = (rows || []).map(r => ({
      id: r.id,
      ts: r.ts,
      level: r.level,
      message: r.message,
      meta: r.meta_json ? JSON.parse(r.meta_json) : {}
    }));
    res.json({ rangeDays: days, level, limit, offset, logs });
  });
});

app.get('/api/security/logs/export', blockMobileAndBots, requireDeveloper2FA, (req, res) => {
  const days = parseDays(req.query.days, 7);
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  const level = (req.query.level || 'all').toLowerCase();
  if (!['all', 'info', 'warn', 'error'].includes(level)) {
    return res.status(400).json({ error: 'Ungültiger level' });
  }

  const baseSql = `SELECT ts, level, message, meta_json
                   FROM security_logs
                   WHERE ts >= ?`;
  const levelSql = level === 'all' ? '' : ' AND level = ?';
  const sql = `${baseSql}${levelSql} ORDER BY ts DESC LIMIT 1000`;
  const params = level === 'all' ? [since] : [since, level];

  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const header = 'ts,level,message,meta';
    const source = rows && rows.length ? rows : demoStats(days).map(r => ({
      ts: new Date().toISOString(),
      level: r.warnings > 0 ? 'warn' : 'info',
      message: r.warnings > 0 ? 'auth.login.failed' : 'page.view',
      meta_json: JSON.stringify({ ip: '203.0.113.10' })
    }));
    const lines = (source || []).map(r => {
      const meta = (r.meta_json || '').replace(/\"/g, '\"\"');
      const msg = (r.message || '').replace(/\"/g, '\"\"');
      return `\"${r.ts}\",\"${r.level}\",\"${msg}\",\"${meta}\"`;
    });
    const csv = [header, ...lines].join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=\"security-logs.csv\"');
    res.send(csv);
  });
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/?login=failed' }),
  (req, res) => {
    res.redirect('/?login=success');
  }
);

app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));

app.get('/auth/github/callback',
  passport.authenticate('github', { failureRedirect: '/?login=failed' }),
  (req, res) => {
    res.redirect('/?login=success');
  }
);

app.post('/auth/logout', (req, res) => {
  req.logout((err) => {
    if (err) return res.status(500).json({ error: err.message });
    if (req.user) {
      logEvent('info', 'auth.logout', { requestId: req.requestId, userId: req.user.id });
    }
    res.json({ message: 'Erfolgreich abgemeldet' });
  });
});

app.get('/auth/status', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ 
      loggedIn: true, 
      user: {
        id: req.user.id,
        email: req.user.email,
        name: req.user.name,
        avatar_url: req.user.avatar_url,
        provider: req.user.provider
      }
    });
  } else {
    res.json({ loggedIn: false });
  }
});

app.post('/api/cookies-consent', requireAuth, (req, res) => {
  const { accepted } = req.body;
  
  db.run('UPDATE users SET cookies_accepted = ? WHERE id = ?', 
    [accepted ? 1 : 0, req.user.id], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: 'Cookie-Einstellungen gespeichert' });
    });
});

// ============ PUBLIC ROUTES ============

app.get('/api/filme', (req, res) => {
  // Wir holen alle aktiven Filme, die mindestens eine Vorstellung ab heute haben
  const sql = `
    SELECT * FROM filme 
    WHERE aktiv = 1 
    AND id IN (SELECT DISTINCT film_id FROM vorstellungen WHERE datum >= date('now'))
    ORDER BY woche ASC, titel ASC
  `;

  db.all(sql, [], (err, rows) => {
    if (err) {
      // Das wird in deinem Terminal (VS Code / CMD) angezeigt
      console.error('❌ Datenbankfehler bei /api/filme:', err.message);
      return res.status(500).json({ error: 'Interner Serverfehler' });
    }
    
    console.log(`🎬 API liefert ${rows.length} Filme aus.`);
    res.json(rows || []);
  });
});

app.get('/api/filme/:id', (req, res) => {
  db.get(`SELECT * FROM filme WHERE id = ?`, [req.params.id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: 'Film nicht gefunden' });
    res.json(row);
  });
});

app.get('/api/vorstellungen/film/:filmId', (req, res) => {
  const query = `
    SELECT v.*, f.titel, f.cover_url, f.genre, f.dauer,
           (SELECT COUNT(DISTINCT id) FROM buchungen WHERE vorstellung_id = v.id) as buchungen_count,
           (SELECT SUM(anzahl_sitze) FROM buchungen WHERE vorstellung_id = v.id) as gebucht
    FROM vorstellungen v
    JOIN filme f ON v.film_id = f.id
    WHERE v.film_id = ? AND v.datum >= date('now')
    ORDER BY v.datum, v.zeit
  `;
  
  db.all(query, [req.params.filmId], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    rows = (rows || []).map(r => ({ ...r, gebucht: r.gebucht || 0 }));
    res.json(rows);
  });
});

app.get('/api/vorstellungen', (req, res) => {
  const query = `
    SELECT v.*, f.titel, f.cover_url, f.genre, f.dauer,
           (SELECT COUNT(DISTINCT id) FROM buchungen WHERE vorstellung_id = v.id) as buchungen_count,
           (SELECT SUM(anzahl_sitze) FROM buchungen WHERE vorstellung_id = v.id) as gebucht
    FROM vorstellungen v
    JOIN filme f ON v.film_id = f.id
    WHERE v.datum >= date('now')
    ORDER BY v.datum, v.zeit
  `;
  
  db.all(query, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    rows = (rows || []).map(r => ({ ...r, gebucht: r.gebucht || 0 }));
    res.json(rows);
  });
});

app.get('/api/buchungen/vorstellung/:id', (req, res) => {
  db.all(`SELECT sitze FROM buchungen WHERE vorstellung_id = ?`, 
    [req.params.id], (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      
      const alleSitze = [];
      (rows || []).forEach(row => {
        try {
          const sitze = JSON.parse(row.sitze);
          alleSitze.push(...sitze);
        } catch (e) {
          // Falls es ein einfacher String "1,2" ist
          const sitze = row.sitze.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
          alleSitze.push(...sitze);
        }
      });
      
      res.json(alleSitze);
    });
});

// ============ BUCHUNGS ROUTE (KORRIGIERT) ============

app.post('/api/buchungen', requireAuth, (req, res) => {
  const { vorstellung_id, sitze } = req.body;
  
  // 1. Validierung
  if (!vorstellung_id) {
    return res.status(400).json({ error: 'Vorstellung ID fehlt' });
  }
  
  if (!sitze || (Array.isArray(sitze) && sitze.length === 0)) {
    return res.status(400).json({ error: 'Mindestens ein Sitz muss ausgewählt werden' });
  }

  // Sicherstellen, dass sitze ein Array ist
  let sitzArray;
  try {
    sitzArray = Array.isArray(sitze) ? sitze : JSON.parse(sitze);
  } catch (e) {
    // Falls es ein String wie "1,2,3" ist
    sitzArray = sitze.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
  }
  
  if (sitzArray.length === 0) {
    return res.status(400).json({ error: 'Ungültige Sitzauswahl' });
  }
  
  // 2. Konfliktprüfung
  db.all(`SELECT sitze FROM buchungen WHERE vorstellung_id = ?`, [vorstellung_id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    
    const belegteSitze = [];
    (rows || []).forEach(row => {
      try {
        belegteSitze.push(...JSON.parse(row.sitze));
      } catch (e) {
        const sitze = row.sitze.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
        belegteSitze.push(...sitze);
      }
    });
    
    const konflikt = sitzArray.some(sitz => belegteSitze.includes(sitz));
    if (konflikt) {
      return res.status(400).json({ error: 'Einer oder mehrere Sitze sind bereits gebucht' });
    }
    
    // 3. Vorstellungsdaten holen für Preis
    db.get(`
        SELECT v.*, f.titel 
        FROM vorstellungen v 
        JOIN filme f ON v.film_id = f.id 
        WHERE v.id = ?`, 
        [vorstellung_id], 
        (err, vorstellung) => {
      
      if (err) return res.status(500).json({ error: err.message });
      if (!vorstellung) return res.status(404).json({ error: 'Vorstellung nicht gefunden' });
      
      const gesamtPreis = vorstellung.preis * sitzArray.length;
      
      // 4. Code generieren
      const buchungscode = generateBookingCode();
      
      // 5. Buchung in DB speichern (Sitze als JSON String)
      const sitzeJson = JSON.stringify(sitzArray);

      db.run(`INSERT INTO buchungen (vorstellung_id, user_id, sitze, anzahl_sitze, gesamt_preis, bezahlt, buchungscode) 
              VALUES (?, ?, ?, ?, ?, 1, ?)`,
        [vorstellung_id, req.user.id, sitzeJson, sitzArray.length, gesamtPreis, buchungscode], 
        function(err) {
          if (err) return res.status(500).json({ error: err.message });
          
          const buchungsId = this.lastID;
          const buchungsnummer = `KIN-${String(buchungsId).padStart(6, '0')}`;
          
          // QR-Code generieren
          const qrData = JSON.stringify({
            buchungsId: buchungsId,
            buchungscode: buchungscode,
            buchungsnummer: buchungsnummer,
            userId: req.user.id
          });
          
          QRCode.toDataURL(qrData, { width: 400, margin: 2 }, (err, qrCodeUrl) => {
            if (err) {
              console.error('QR-Code Fehler:', err);
              qrCodeUrl = null; // Bei Fehler null setzen
            }
            
            // 6. Emails senden
            if (process.env.SMTP_USER && req.user.email) {
               // Admin Mail
               if (process.env.NOTIFICATION_EMAIL) {
                 const mailOptions = {
                   from: process.env.SMTP_USER,
                   to: process.env.NOTIFICATION_EMAIL,
                   subject: `Neue Buchung: ${buchungscode}`,
                   html: `<p>Neue Buchung ${buchungsnummer} (Code: <strong>${buchungscode}</strong>) für ${vorstellung.titel}.</p>`
                 };
                 transporter.sendMail(mailOptions, (err) => { 
                   if(err) console.error('Admin Email Fehler:', err); 
                 });
               }

               // Kunden Mail
               const kundenMailOptions = {
                 from: process.env.SMTP_USER,
                 to: req.user.email,
                 subject: `Ihre Buchung ${buchungscode} - CineVerse`,
                 html: `
                   <div style="font-family: sans-serif; padding: 20px;">
                     <h2 style="color: #d4af37;">Buchung Bestätigt!</h2>
                     <p>Ihr Einlass-Code lautet:</p>
                     <div style="background: #eee; padding: 15px; font-size: 24px; letter-spacing: 5px; font-family: monospace; text-align: center; border-radius: 8px;">
                        <strong>${buchungscode}</strong>
                     </div>
                     <p>Film: ${vorstellung.titel}</p>
                     <p>Datum: ${new Date(vorstellung.datum).toLocaleDateString('de-DE')}</p>
                     <p>Zeit: ${vorstellung.zeit}</p>
                     <p>Sitze: ${sitzArray.join(', ')}</p>
                     <p>Gesamtpreis: ${gesamtPreis.toFixed(2)} €</p>
                     <br>
                     <p>Bitte zeigen Sie den Code am Einlass vor.</p>
                     ${qrCodeUrl ? `<img src="${qrCodeUrl}" alt="QR Code" style="max-width: 200px; margin-top: 20px;" />` : ''}
                   </div>
                 `
               };
               transporter.sendMail(kundenMailOptions, (err) => { 
                 if(err) console.error('Kunden Email Fehler:', err); 
               });
            }
            
            logEvent('info', 'booking.created', { requestId: req.requestId, userId: req.user.id, buchungId: buchungsId, vorstellungId: vorstellung_id });
            // 7. Antwort ans Frontend
            res.json({ 
              id: buchungsId,
              message: 'Buchung erfolgreich!',
              buchungscode: buchungscode,
              buchungsnummer: buchungsnummer,
              titel: vorstellung.titel,
              datum: vorstellung.datum,
              zeit: vorstellung.zeit,
              sitze: sitzArray,
              anzahl_sitze: sitzArray.length,
              gesamt_preis: gesamtPreis
            });
            
          });
        });
    });
  });
});

// ============ USER BUCHUNGEN ============

app.get('/api/meine-buchungen', requireAuth, (req, res) => {
  const query = `
    SELECT b.*, v.datum, v.zeit, v.saal_typ, f.titel, f.cover_url, f.genre
    FROM buchungen b
    JOIN vorstellungen v ON b.vorstellung_id = v.id
    JOIN filme f ON v.film_id = f.id
    WHERE b.user_id = ?
    ORDER BY v.datum DESC, v.zeit DESC
  `;
  
  db.all(query, [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    
    // Sitze parsen
    const buchungen = (rows || []).map(row => {
      let sitze;
      try {
        sitze = JSON.parse(row.sitze);
      } catch (e) {
        sitze = row.sitze.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
      }
      return { ...row, sitze };
    });
    
    res.json(buchungen);
  });
});

app.get('/api/paypal-donation-link', (req, res) => {
  res.json({ link: process.env.PAYPAL_DONATION_LINK || '' });
});

// QR-Code Verifikation (Admin)
app.post('/api/admin/verify-qr', requireAdmin, (req, res) => {
  const { qrData } = req.body;
  
  if (!qrData) {
    return res.status(400).json({ error: 'QR-Daten fehlen' });
  }
  
  try {
    let buchungsId = null;
    let buchungscode = null;
    
    // Versuch 1: JSON parsen
    try {
      const data = JSON.parse(qrData);
      buchungsId = data.buchungsId;
      buchungscode = data.buchungscode;
    } catch(e) {
      // Versuch 2: Als reiner Code-String
      buchungscode = qrData.trim();
    }

    // SQL Query bauen
    let sql = `
      SELECT b.*, v.datum, v.zeit, f.titel, u.name, u.email
      FROM buchungen b
      JOIN vorstellungen v ON b.vorstellung_id = v.id
      JOIN filme f ON v.film_id = f.id
      JOIN users u ON b.user_id = u.id
      WHERE b.buchungscode = ?
    `;
    
    const params = [buchungscode];
    
    // Falls wir eine ID haben, auch danach suchen
    if (buchungsId) {
      sql += ` OR b.id = ?`;
      params.push(buchungsId);
    }

    db.get(sql, params, (err, buchung) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!buchung) return res.status(404).json({ error: 'Buchung nicht gefunden' });
      
      // Sitze parsen
      let sitze;
      try {
        sitze = JSON.parse(buchung.sitze);
      } catch (e) {
        sitze = buchung.sitze.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
      }
      
      if (buchung.verified === 1) {
        logEvent('info', 'admin.verifyQr.alreadyVerified', { requestId: req.requestId, admin: req.session.admin.username, buchungId: buchung.id });
        return res.json({
          valid: true,
          alreadyVerified: true,
          message: 'Bereits eingelassen!',
          buchung: {
            code: buchung.buchungscode,
            film: buchung.titel,
            datum: buchung.datum,
            zeit: buchung.zeit,
            sitze: sitze,
            kunde: buchung.name
          }
        });
      }
      
      // Verifizieren
      db.run('UPDATE buchungen SET verified = 1 WHERE id = ?', [buchung.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        
        logEvent('info', 'admin.verifyQr.verified', { requestId: req.requestId, admin: req.session.admin.username, buchungId: buchung.id });
        res.json({
          valid: true,
          alreadyVerified: false,
          message: 'Zutritt gewährt',
          buchung: {
            code: buchung.buchungscode,
            film: buchung.titel,
            datum: buchung.datum,
            zeit: buchung.zeit,
            sitze: sitze,
            kunde: buchung.name,
            email: buchung.email
          }
        });
      });
    });
  } catch (error) {
    res.status(400).json({ error: 'Ungültiger Code: ' + error.message });
  }
});

// ============ ADMIN ROUTES ============

app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Benutzername und Passwort erforderlich' });
  }
  
  db.get(`SELECT * FROM admins WHERE username = ?`, [username], (err, admin) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!admin) return res.status(401).json({ error: 'Ungültige Anmeldedaten' });
    
    bcrypt.compare(password, admin.password_hash, (err, result) => {
      if (err || !result) {
        return res.status(401).json({ error: 'Ungültige Anmeldedaten' });
      }
      
      req.session.admin = { id: admin.id, username: admin.username };
      logEvent('info', 'admin.login', { requestId: req.requestId, adminId: admin.id, username: admin.username });
      res.json({ message: 'Erfolgreich angemeldet', username: admin.username });
    });
  });
});

app.post('/api/admin/logout', (req, res) => {
  const admin = req.session && req.session.admin ? req.session.admin.username : null;
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ error: err.message });
    if (admin) {
      logEvent('info', 'admin.logout', { requestId: req.requestId, username: admin });
    }
    res.json({ message: 'Erfolgreich abgemeldet' });
  });
});

app.get('/api/admin/status', (req, res) => {
  if (req.session && req.session.admin) {
    res.json({ loggedIn: true, username: req.session.admin.username });
  } else {
    res.json({ loggedIn: false });
  }
});

app.get('/api/admin/filme', requireAdmin, (req, res) => {
  db.all(`SELECT * FROM filme ORDER BY woche ASC, titel ASC`, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows || []);
  });
});

app.post('/api/admin/filme', requireAdmin, (req, res) => {
  const { titel, beschreibung, genre, dauer, cover_url, preis, woche } = req.body;
  
  if (!titel || !genre || !dauer) {
    return res.status(400).json({ error: 'Titel, Genre und Dauer sind erforderlich' });
  }
  
  db.run(`INSERT INTO filme (titel, beschreibung, genre, dauer, cover_url, preis, woche) 
          VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [titel, beschreibung || '', genre, dauer, cover_url || '', preis || 10, woche || 1], 
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      logEvent('info', 'admin.film.create', { requestId: req.requestId, admin: req.session.admin.username, filmId: this.lastID });
      res.json({ id: this.lastID, message: 'Film hinzugefügt' });
    });
});

app.put('/api/admin/filme/:id', requireAdmin, (req, res) => {
  const { titel, beschreibung, genre, dauer, cover_url, preis, woche, aktiv } = req.body;
  
  db.run(`UPDATE filme SET titel = ?, beschreibung = ?, genre = ?, dauer = ?, 
          cover_url = ?, preis = ?, woche = ?, aktiv = ? WHERE id = ?`,
    [titel, beschreibung, genre, dauer, cover_url, preis, woche, aktiv !== undefined ? aktiv : 1, req.params.id], 
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      if (this.changes === 0) return res.status(404).json({ error: 'Film nicht gefunden' });
      logEvent('info', 'admin.film.update', { requestId: req.requestId, admin: req.session.admin.username, filmId: req.params.id });
      res.json({ message: 'Film aktualisiert' });
    });
});

app.delete('/api/admin/filme/:id', requireAdmin, (req, res) => {
  const filmId = req.params.id;
  db.serialize(() => {
    db.run('BEGIN TRANSACTION');
    db.all('SELECT id FROM vorstellungen WHERE film_id = ?', [filmId], (err, rows) => {
      if (err) {
        db.run('ROLLBACK');
        return res.status(500).json({ error: err.message });
      }
      const vorstellungIds = (rows || []).map(r => r.id);
      const deleteBookings = (cb) => {
        if (vorstellungIds.length === 0) return cb();
        const placeholders = vorstellungIds.map(() => '?').join(', ');
        db.run(`DELETE FROM buchungen WHERE vorstellung_id IN (${placeholders})`, vorstellungIds, cb);
      };

      deleteBookings((err) => {
        if (err) {
          db.run('ROLLBACK');
          return res.status(500).json({ error: err.message });
        }
        db.run('DELETE FROM vorstellungen WHERE film_id = ?', [filmId], (err) => {
          if (err) {
            db.run('ROLLBACK');
            return res.status(500).json({ error: err.message });
          }
          db.run('DELETE FROM filme WHERE id = ?', [filmId], function(err) {
            if (err) {
              db.run('ROLLBACK');
              return res.status(500).json({ error: err.message });
            }
            if (this.changes === 0) {
              db.run('ROLLBACK');
              return res.status(404).json({ error: 'Film nicht gefunden' });
            }
            db.run('COMMIT', (commitErr) => {
              if (commitErr) return res.status(500).json({ error: commitErr.message });
              logEvent('info', 'admin.film.delete', { requestId: req.requestId, admin: req.session.admin.username, filmId, deletedVorstellungen: vorstellungIds.length });
              res.json({ message: 'Film gelöscht', deletedVorstellungen: vorstellungIds.length });
            });
          });
        });
      });
    });
  });
});

app.get('/api/admin/vorstellungen', requireAdmin, (req, res) => {
  const query = `
    SELECT v.*, f.titel,
           (SELECT SUM(anzahl_sitze) FROM buchungen WHERE vorstellung_id = v.id) as gebucht
    FROM vorstellungen v
    JOIN filme f ON v.film_id = f.id
    ORDER BY v.datum DESC, v.zeit DESC
  `;
  
  db.all(query, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    rows = (rows || []).map(r => ({ ...r, gebucht: r.gebucht || 0 }));
    res.json(rows);
  });
});

app.post('/api/admin/vorstellungen', requireAdmin, (req, res) => {
  const { film_id, datum, zeit, preis } = req.body;
  
  if (!film_id || !datum || !zeit) {
    return res.status(400).json({ error: 'Film, Datum und Zeit sind erforderlich' });
  }
  
  db.run(`INSERT INTO vorstellungen (film_id, datum, zeit, saal_typ, sitzplaetze_gesamt, preis) 
          VALUES (?, ?, ?, 'standard', 8, ?)`,
    [film_id, datum, zeit, preis || 0], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      logEvent('info', 'admin.vorstellung.create', { requestId: req.requestId, admin: req.session.admin.username, vorstellungId: this.lastID, filmId: film_id });
      res.json({ id: this.lastID, message: 'Vorstellung hinzugefügt (8 Sitzplätze)' });
    });
});

app.delete('/api/admin/vorstellungen/:id', requireAdmin, (req, res) => {
  const vorstellungId = req.params.id;
  db.serialize(() => {
    db.run('BEGIN TRANSACTION');
    db.run('DELETE FROM buchungen WHERE vorstellung_id = ?', [vorstellungId], (err) => {
      if (err) {
        db.run('ROLLBACK');
        return res.status(500).json({ error: err.message });
      }
      db.run('DELETE FROM vorstellungen WHERE id = ?', [vorstellungId], function(err) {
        if (err) {
          db.run('ROLLBACK');
          return res.status(500).json({ error: err.message });
        }
        if (this.changes === 0) {
          db.run('ROLLBACK');
          return res.status(404).json({ error: 'Vorstellung nicht gefunden' });
        }
        db.run('COMMIT', (commitErr) => {
          if (commitErr) return res.status(500).json({ error: commitErr.message });
          logEvent('info', 'admin.vorstellung.delete', { requestId: req.requestId, admin: req.session.admin.username, vorstellungId });
          res.json({ message: 'Vorstellung gelöscht' });
        });
      });
    });
  });
});

app.get('/api/admin/buchungen', requireAdmin, (req, res) => {
  const query = `
    SELECT b.*, v.datum, v.zeit, f.titel, u.name, u.email
    FROM buchungen b
    JOIN vorstellungen v ON b.vorstellung_id = v.id
    JOIN filme f ON v.film_id = f.id
    JOIN users u ON b.user_id = u.id
    ORDER BY b.erstellt_am DESC
  `;
  
  db.all(query, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    
    // Sitze parsen
    const buchungen = (rows || []).map(row => {
      let sitze;
      try {
        sitze = JSON.parse(row.sitze);
      } catch (e) {
        sitze = row.sitze.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
      }
      return { ...row, sitze };
    });
    
    res.json(buchungen);
  });
});

// Admin: Users verwalten
app.get('/api/admin/users', requireAdmin, (req, res) => {
  db.all(`SELECT id, email, name, provider, erstellt_am, letzter_login FROM users ORDER BY erstellt_am DESC`, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows || []);
  });
});

app.post('/api/admin/users', requireAdmin, async (req, res) => {
  const { email, name, password } = req.body;
  if (!email || !name || !password) {
    return res.status(400).json({ error: 'Email, Name und Passwort erforderlich' });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    db.run(`INSERT INTO users (email, name, provider, password_hash) VALUES (?, ?, ?, ?)`,
      [email, name, 'local', hash], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        logEvent('info', 'admin.user.create', { requestId: req.requestId, admin: req.session.admin.username, userId: this.lastID, email });
        res.json({ id: this.lastID, message: 'User erstellt' });
      });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  const userId = req.params.id;
  db.serialize(() => {
    db.run('BEGIN TRANSACTION');
    db.run('DELETE FROM buchungen WHERE user_id = ?', [userId], (err) => {
      if (err) {
        db.run('ROLLBACK');
        return res.status(500).json({ error: err.message });
      }
      db.run('DELETE FROM spenden WHERE user_id = ?', [userId], (err2) => {
        if (err2) {
          db.run('ROLLBACK');
          return res.status(500).json({ error: err2.message });
        }
        db.run('DELETE FROM users WHERE id = ?', [userId], function(err3) {
          if (err3) {
            db.run('ROLLBACK');
            return res.status(500).json({ error: err3.message });
          }
          if (this.changes === 0) {
            db.run('ROLLBACK');
            return res.status(404).json({ error: 'User nicht gefunden' });
          }
          db.run('COMMIT', (commitErr) => {
            if (commitErr) return res.status(500).json({ error: commitErr.message });
            logEvent('info', 'admin.user.delete', { requestId: req.requestId, admin: req.session.admin.username, userId });
            res.json({ message: 'User geloescht' });
          });
        });
      });
    });
  });
});

// Admin: Buchung loeschen
app.delete('/api/admin/buchungen/:id', requireAdmin, (req, res) => {
  const id = req.params.id;
  db.run('DELETE FROM buchungen WHERE id = ?', [id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: 'Buchung nicht gefunden' });
    logEvent('info', 'admin.booking.delete', { requestId: req.requestId, admin: req.session.admin.username, buchungId: id });
    res.json({ message: 'Buchung geloescht' });
  });
});

app.get('/api/admin/spenden', requireAdmin, (req, res) => {
  const query = `
    SELECT s.*, u.name, u.email
    FROM spenden s
    LEFT JOIN users u ON s.user_id = u.id
    ORDER BY s.datum DESC
  `;
  
  db.all(query, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows || []);
  });
});

app.get('/api/admin/statistiken', requireAdmin, (req, res) => {
  const stats = {};
  
  db.get(`SELECT COUNT(*) as total FROM buchungen`, (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    stats.totalBuchungen = row ? row.total : 0;
    
    db.get(`SELECT SUM(gesamt_preis) as total FROM buchungen WHERE bezahlt = 1`, (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      stats.totalUmsatz = row ? (row.total || 0) : 0;
      
      db.get(`SELECT SUM(betrag) as total FROM spenden`, (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        stats.totalSpenden = row ? (row.total || 0) : 0;
        
        db.get(`SELECT COUNT(*) as total FROM filme WHERE aktiv = 1`, (err, row) => {
          if (err) return res.status(500).json({ error: err.message });
          stats.aktiveFilme = row ? row.total : 0;
          
          db.get(`SELECT COUNT(*) as total FROM users`, (err, row) => {
            if (err) return res.status(500).json({ error: err.message });
            stats.totalUsers = row ? row.total : 0;
            
            db.get(`SELECT COUNT(*) as total FROM vorstellungen WHERE datum >= date('now')`, (err, row) => {
              if (err) return res.status(500).json({ error: err.message });
              stats.zukuenftigeVorstellungen = row ? row.total : 0;
              
              res.json(stats);
            });
          });
        });
      });
    });
  });
});

// ============ STATIC PAGES ROUTES ============
// Routen für HTML-Seiten ohne .html-Endung
const staticPages = ['impressum', 'datenschutz', 'cookies', 'agb'];

staticPages.forEach(page => {
  app.get(`/${page}`, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', `${page}.html`));
  });
});

app.get('/cj', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'cj.html'));
});

// 404 Handler
app.use((req, res) => {
  if (req.accepts('html')) {
    return res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
  }
  if (req.accepts('json')) {
    return res.status(404).json({ error: 'Nicht gefunden' });
  }
  res.status(404).type('text').send('Nicht gefunden');
});

// Error Handler
app.use((err, req, res, next) => {
  logEvent('error', 'server.error', {
    requestId: req.requestId,
    path: req.originalUrl,
    method: req.method,
    error: err.message
  });
  res.status(500).json({ error: 'Interner Server Fehler' });
});

app.listen(PORT, () => {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`   CineVerse Kino-Buchungssystem v2.0`);
  console.log(`${'='.repeat(60)}\n`);
  console.log(`   Server: http://localhost:${PORT}`);
  console.log(`   Admin: username=admin, password=admin123`);
  console.log(`   Kinosaal: 8 Sitzplätze (fix)`);
  console.log(`\n${'='.repeat(60)}\n`);
});
