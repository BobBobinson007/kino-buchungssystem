const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const db = new sqlite3.Database('./kino.db');

db.serialize(() => {
    // Users Tabelle mit Email-Verifikation
    db.run(`CREATE TABLE IF NOT EXISTS users ( 
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        email TEXT UNIQUE, 
        name TEXT, 
        provider TEXT, 
        provider_id TEXT, 
        password_hash TEXT, 
        avatar_url TEXT, 
        email_verified INTEGER DEFAULT 0,
        email_verification_token TEXT,
        cookies_accepted INTEGER DEFAULT 0, 
        newsletter INTEGER DEFAULT 0, 
        erstellt_am DATETIME DEFAULT CURRENT_TIMESTAMP, 
        letzter_login DATETIME 
    )`);

    // Filme Tabelle
    db.run(`CREATE TABLE IF NOT EXISTS filme ( 
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        titel TEXT NOT NULL, 
        beschreibung TEXT, 
        genre TEXT, 
        dauer INTEGER, 
        cover_url TEXT, 
        preis REAL DEFAULT 12.50, 
        woche INTEGER DEFAULT 1, 
        aktiv INTEGER DEFAULT 1, 
        erstellt_am DATETIME DEFAULT CURRENT_TIMESTAMP 
    )`);

    // Vorstellungen Tabelle
    db.run(`CREATE TABLE IF NOT EXISTS vorstellungen ( 
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        film_id INTEGER, 
        datum DATE, 
        zeit TIME, 
        saal_typ TEXT DEFAULT 'standard', 
        sitzplaetze_gesamt INTEGER DEFAULT 8, 
        preis REAL, 
        FOREIGN KEY (film_id) REFERENCES filme(id) 
    )`);

    // Buchungen Tabelle
    db.run(`CREATE TABLE IF NOT EXISTS buchungen ( 
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        vorstellung_id INTEGER, 
        user_id INTEGER, 
        sitze TEXT, 
        anzahl_sitze INTEGER, 
        gesamt_preis REAL, 
        bezahlt INTEGER DEFAULT 1, 
        buchungscode TEXT UNIQUE, 
        verified INTEGER DEFAULT 0, 
        gebucht_am DATETIME DEFAULT CURRENT_TIMESTAMP, 
        FOREIGN KEY (vorstellung_id) REFERENCES vorstellungen(id), 
        FOREIGN KEY (user_id) REFERENCES users(id) 
    )`);

    // Spenden Tabelle
    db.run(`CREATE TABLE IF NOT EXISTS spenden ( 
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        user_id INTEGER, 
        betrag REAL, 
        nachricht TEXT, 
        datum DATETIME DEFAULT CURRENT_TIMESTAMP, 
        FOREIGN KEY (user_id) REFERENCES users(id) 
    )`);

    // Admin Tabelle
    db.run(`CREATE TABLE IF NOT EXISTS admins ( 
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        username TEXT UNIQUE, 
        password_hash TEXT, 
        erstellt_am DATETIME DEFAULT CURRENT_TIMESTAMP 
    )`, () => {
        const adminPassword = 'Nestle67';
        bcrypt.hash(adminPassword, 10, (err, hash) => {
            if (!err) {
                db.run(`INSERT OR IGNORE INTO admins (username, password_hash) VALUES (?, ?)`, ['admin', hash]);
            }
        });
    });

    // Security Logs Tabelle
    db.run(`CREATE TABLE IF NOT EXISTS security_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts DATETIME DEFAULT CURRENT_TIMESTAMP,
        level TEXT NOT NULL,
        message TEXT NOT NULL,
        meta_json TEXT
    )`);

    db.run(`CREATE INDEX IF NOT EXISTS idx_security_logs_ts ON security_logs(ts)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_security_logs_level ON security_logs(level)`);

    // Settings Tabelle
    db.run(`CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('lockdown_mode', 'false')`);
    db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('firewall_mode', 'false')`);

    // IP Regeln (Firewall)
    db.run(`CREATE TABLE IF NOT EXISTS security_ip_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        rule_type TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_security_ip_rules_type ON security_ip_rules(rule_type)`);

    console.log('✓ Datenbank initialisiert (ohne Beispielinhalte, nur Admin)');
});

module.exports = db;
