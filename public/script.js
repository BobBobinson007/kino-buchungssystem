// Globale Variablen
let alleFilme = [];
let aktuelleVorstellung = null;
let ausgewaehlteSitze = [];
let currentUser = null;

// Seite laden
document.addEventListener('DOMContentLoaded', () => {
    initEventListeners();
    checkAuth();
    ladeFilme();
    checkCookieConsent();
    checkLoginStatus();
    
    // Filter Tabs
    document.querySelectorAll('.filter-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.filter-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            const woche = tab.dataset.woche;
            filtereFilme(woche);
        });
    });
});

fetch('/api/filme')
  .then(response => {
    if (response.status === 403) {
      window.location.href = '/password.html';
    }
  })
  .catch(error => console.error('Error:', error));

// Öffnet Admin-Modal über Footer-Link
document.querySelectorAll('.open-admin-modal').forEach(button => {
    button.addEventListener('click', function(e) {
        e.preventDefault();
        document.getElementById('adminLoginModal').style.display = 'block';
    });
});
// Event Listeners initialisieren
function initEventListeners() {
    // Cookie Banner
    const acceptCookiesBtn = document.getElementById('acceptCookiesBtn');
    const declineCookiesBtn = document.getElementById('declineCookiesBtn');
    if (acceptCookiesBtn) acceptCookiesBtn.addEventListener('click', acceptCookies);
    if (declineCookiesBtn) declineCookiesBtn.addEventListener('click', declineCookies);
    
    // Navigation
    const loginNavBtn = document.getElementById('loginNavBtn');
    if (loginNavBtn) loginNavBtn.addEventListener('click', showLoginModal);
    
    const adminNavLink = document.getElementById('adminNavLink');
    if (adminNavLink) {
        adminNavLink.addEventListener('click', (e) => {
            e.preventDefault();
            showAdminLoginModal();
        });
    }
    
    // Hero CTA
    const heroCtaBtn = document.getElementById('heroCtaBtn');
    if (heroCtaBtn) {
        heroCtaBtn.addEventListener('click', () => {
            document.getElementById('filme').scrollIntoView({behavior: 'smooth'});
        });
    }
    
    // PayPal Donation
    const paypalBtn = document.getElementById('paypalDonationBtn');
    if (paypalBtn) paypalBtn.addEventListener('click', openPayPalDonation);
    
    // Modal Close Buttons
    document.querySelectorAll('[data-close-modal]').forEach(btn => {
        btn.addEventListener('click', closeModal);
    });
    
    document.querySelectorAll('[data-close-login-modal]').forEach(btn => {
        btn.addEventListener('click', closeLoginModal);
    });
    
    document.querySelectorAll('[data-close-admin-modal]').forEach(btn => {
        btn.addEventListener('click', closeAdminLoginModal);
    });
    
    // Auth Tabs
    document.querySelectorAll('[data-auth-tab]').forEach(tab => {
        tab.addEventListener('click', (e) => {
            const tabName = e.target.dataset.authTab;
            showAuthTab(tabName, e.target);
        });
    });
    
    // Forms
    const loginForm = document.getElementById('loginFormElement');
    if (loginForm) loginForm.addEventListener('submit', handleLogin);
    
    const registerForm = document.getElementById('registerFormElement');
    if (registerForm) registerForm.addEventListener('submit', handleRegister);
    
    const adminLoginForm = document.getElementById('adminLoginFormElement');
    if (adminLoginForm) adminLoginForm.addEventListener('submit', handleAdminLogin);
}

// Auth Status prüfen
async function checkAuth() {
    try {
        const response = await fetch('/auth/status');
        const status = await response.json();
        if (status.loggedIn) {
            currentUser = status.user;
            updateUserMenu(status.user);
        }
    } catch (error) {
        console.error('Auth-Check Fehler:', error);
    }
}

function updateUserMenu(user) {
    const userMenu = document.getElementById('userMenu');
    userMenu.innerHTML = `
        <div class="user-profile" id="userProfileBtn">
            ${user.avatar_url ? `<img src="${user.avatar_url}" alt="${user.name}">` : `<span class="initial">${user.name.charAt(0)}</span>`}
            <span>${user.name}</span>
        </div>
        <div class="user-dropdown" id="userDropdown">
            <a href="#meine-buchungen" id="myBookingsLink">Meine Buchungen</a>
            <button id="logoutBtn">Abmelden</button>
        </div>
    `;
    
    // Event Listeners für User Menu
    const profileBtn = document.getElementById('userProfileBtn');
    if (profileBtn) profileBtn.addEventListener('click', toggleUserDropdown);
    
    const myBookingsLink = document.getElementById('myBookingsLink');
    if (myBookingsLink) myBookingsLink.addEventListener('click', (e) => {
        e.preventDefault();
        showMyBookings();
    });
    
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) logoutBtn.addEventListener('click', logout);
}

function toggleUserDropdown() {
    const dropdown = document.getElementById('userDropdown');
    dropdown.classList.toggle('show');
}

// Click außerhalb schließt Dropdown
document.addEventListener('click', (e) => {
    const dropdown = document.getElementById('userDropdown');
    const profile = document.getElementById('userProfileBtn');
    if (dropdown && profile && !profile.contains(e.target) && !dropdown.contains(e.target)) {
        dropdown.classList.remove('show');
    }
});

// Login Status Check (URL Parameter)
function checkLoginStatus() {
    const urlParams = new URLSearchParams(window.location.search);
    const loginStatus = urlParams.get('login');
    if (loginStatus === 'success') {
        setTimeout(() => {
            checkAuth();
            window.history.replaceState({}, document.title, window.location.pathname);
        }, 500);
    } else if (loginStatus === 'failed') {
        alert('Anmeldung fehlgeschlagen. Bitte versuchen Sie es erneut.');
        window.history.replaceState({}, document.title, window.location.pathname);
    }
}

// Cookie Consent
function checkCookieConsent() {
    const consent = localStorage.getItem('cookieConsent');
    if (!consent) {
        document.getElementById('cookieBanner').classList.add('show');
        return;
    }
}

function acceptCookies() {
    localStorage.setItem('cookieConsent', 'accepted');
    document.getElementById('cookieBanner').classList.remove('show');
    if (currentUser) {
        fetch('/api/cookies-consent', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ accepted: true })
        });
    }
}

function declineCookies() {
    localStorage.setItem('cookieConsent', 'declined');
    document.getElementById('cookieBanner').classList.remove('show');
    if (currentUser) {
        fetch('/api/cookies-consent', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ accepted: false })
        });
    }
}

// Login Modal
function showLoginModal() {
    document.getElementById('loginModal').classList.add('active');
    document.body.style.overflow = 'hidden';
}

function closeLoginModal() {
    document.getElementById('loginModal').classList.remove('active');
    document.body.style.overflow = '';
}

// Admin Login Modal
function showAdminLoginModal() {
    document.getElementById('adminLoginModal').classList.add('active');
    document.body.style.overflow = 'hidden';
}

function closeAdminLoginModal() {
    document.getElementById('adminLoginModal').classList.remove('active');
    document.body.style.overflow = '';
}

// Admin Login Handler
async function handleAdminLogin(event) {
    event.preventDefault();
    const username = document.getElementById('adminLoginUsername').value;
    const password = document.getElementById('adminLoginPassword').value;

    try {
        const response = await fetch('/api/admin/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        const result = await response.json();
        
        if (response.ok) {
            closeAdminLoginModal();
            window.location.href = '/admin.html';
        } else {
            alert(result.error || 'Admin-Anmeldung fehlgeschlagen');
        }
    } catch (error) {
        console.error('Admin Login Fehler:', error);
        alert('Admin-Anmeldung fehlgeschlagen. Bitte versuchen Sie es erneut.');
    }
}

function showAuthTab(tab, targetElement) {
    document.querySelectorAll('.auth-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.auth-form').forEach(f => f.classList.remove('active'));
    targetElement.classList.add('active');
    document.getElementById(tab + 'Form').classList.add('active');
}

// Login Handler
async function handleLogin(event) {
    event.preventDefault();
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;

    try {
        const response = await fetch('/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        
        const result = await response.json();
        
        if (response.ok) {
            currentUser = result.user;
            updateUserMenu(result.user);
            closeLoginModal();
            alert('Erfolgreich angemeldet!');
        } else {
            alert(result.error || 'Anmeldung fehlgeschlagen');
        }
    } catch (error) {
        console.error('Login Fehler:', error);
        alert('Anmeldung fehlgeschlagen. Bitte versuchen Sie es erneut.');
    }
}

// Register Handler
async function handleRegister(event) {
    event.preventDefault();
    const name = document.getElementById('registerName').value;
    const email = document.getElementById('registerEmail').value;
    const password = document.getElementById('registerPassword').value;

    if (password.length < 6) {
        alert('Passwort muss mindestens 6 Zeichen lang sein');
        return;
    }

    try {
        const response = await fetch('/auth/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, email, password })
        });
        
        const result = await response.json();
        
        if (response.ok) {
            currentUser = result.user;
            updateUserMenu(result.user);
            closeLoginModal();
            alert('Erfolgreich registriert!');
        } else {
            alert(result.error || 'Registrierung fehlgeschlagen');
        }
    } catch (error) {
        console.error('Register Fehler:', error);
        alert('Registrierung fehlgeschlagen. Bitte versuchen Sie es erneut.');
    }
}

// Logout
async function logout() {
    try {
        await fetch('/auth/logout', { method: 'POST' });
        currentUser = null;
        const userMenu = document.getElementById('userMenu');
        userMenu.innerHTML = '<button class="login-btn" id="loginNavBtn">Anmelden</button>';
        
        // Event Listener erneut hinzufügen
        const loginNavBtn = document.getElementById('loginNavBtn');
        if (loginNavBtn) loginNavBtn.addEventListener('click', showLoginModal);
        
        alert('Erfolgreich abgemeldet');
    } catch (error) {
        console.error('Logout Fehler:', error);
    }
}

// Filme laden
async function ladeFilme() {
    try {
        const response = await fetch('/api/filme');
        alleFilme = await response.json();
        
        // Für jeden Film den günstigsten Preis aus den Vorstellungen holen
        for (let film of alleFilme) {
            try {
                const vorstellungenResponse = await fetch(`/api/vorstellungen/film/${film.id}`);
                const vorstellungen = await vorstellungenResponse.json();
                
                if (vorstellungen && vorstellungen.length > 0) {
                    // Finde den günstigsten Preis
                    const guenstigsterPreis = Math.min(...vorstellungen.map(v => v.preis));
                    film.preis = guenstigsterPreis;
                }
            } catch (error) {
                console.error(`Fehler beim Laden der Vorstellungen für Film ${film.id}:`, error);
                // Behalte den Standard-Preis aus der filme Tabelle bei Fehler
            }
        }
        
        zeigeFilme(alleFilme);
    } catch (error) {
        console.error('Fehler beim Laden der Filme:', error);
    }
}

// Filme anzeigen
function zeigeFilme(filme) {
    const grid = document.getElementById('filmeGrid');
    if (filme.length === 0) {
        grid.innerHTML = '<p style="text-align: center; grid-column: 1/-1; padding: 3rem; color: rgba(245, 241, 232, 0.6);">Keine Filme gefunden</p>';
        return;
    }

    grid.innerHTML = filme.map((film, index) => `
        <div class="film-card" data-film-id="${film.id}" style="animation: fadeInUp 0.6s ease-out forwards; animation-delay: ${index * 0.1}s;">
            <img src="${film.cover_url}" alt="${film.titel}" class="film-cover">
            <div class="film-info">
                <span class="film-woche">WOCHE ${film.woche}</span>
                <h3 class="film-titel">${film.titel}</h3>
                <div class="film-meta">
                    <span class="film-genre">${film.genre}</span>
                    <span class="film-dauer">${film.dauer} Min.</span>
                </div>
                <p class="film-beschreibung">${film.beschreibung}</p>
                <div class="film-preis">Ab ${film.preis.toFixed(2)}€</div>
            </div>
        </div>
    `).join('');
    
    // Event Listeners für Film Cards
    document.querySelectorAll('.film-card').forEach(card => {
        card.addEventListener('click', () => {
            const filmId = parseInt(card.dataset.filmId);
            zeigeFilmDetails(filmId);
        });
    });
}

// Globale Liste deiner Filme (muss existieren)
// Beispiel: const alleFilme = [{ titel: "...", woche: "woche1" }, ...];

function getCurrentWeekIdentifier() {
    // ⚠️ ANPASSEN AN DEIN SYSTEM!
    // Wenn du weißt, dass "diese Woche" = "woche1" und "nächste Woche" = "woche2":
    return "woche1"; // ← Dieser Wert muss dynamisch sein oder aus Backend kommen!
}

function getNextWeekIdentifier() {
    return "woche2"; // ← Oder berechnet: z. B. aus aktueller Woche +1
}

function normalizeWeekValue(value) {
    if (value == null) return '';
    return String(value).toLowerCase().replace(/[^a-z0-9]/g, '');
}

function filtereFilme(woche) {
    if (woche === 'alle') {
        zeigeFilme(alleFilme);
        return;
    }

    // Mappe relative Bezeichner auf echte Wochen-IDs
    let targetWeek;
    if (woche === 'aktuelle_woche') {
        targetWeek = getCurrentWeekIdentifier();
    } else if (woche === 'naechste_woche') {
        targetWeek = getNextWeekIdentifier();
    } else {
        targetWeek = woche; // fallback für explizite IDs wie "woche3"
    }

    const gefiltert = alleFilme.filter(film => 
        normalizeWeekValue(film.woche) === normalizeWeekValue(targetWeek)
    );
    zeigeFilme(gefiltert);
}

// Film Details anzeigen
function zeigeFilmDetails(filmId) {
    const film = alleFilme.find(f => f.id === filmId);
    if (!film) return;

    // Vorstellungen für diesen Film finden
    fetch(`/api/vorstellungen/film/${filmId}`)
        .then(response => response.json())
        .then(vorstellungen => {
            const modalContent = `
                <h2 style="font-family: 'Playfair Display', serif; font-size: 2.5rem; margin-bottom: 1rem;">${film.titel}</h2>
                <div style="display: grid; grid-template-columns: 1fr 2fr; gap: 2rem; margin-bottom: 2rem;">
                    <img src="${film.cover_url}" alt="${film.titel}" style="width: 100%; border: 2px solid var(--secondary);">
                    <div>
                        <div style="margin-bottom: 1rem;">
                            <span style="background: var(--secondary); color: var(--dark); padding: 0.3rem 0.8rem; font-size: 0.8rem; font-weight: 600;">WOCHE ${film.woche}</span>
                        </div>
                        <p style="margin-bottom: 1rem; line-height: 1.8;">${film.beschreibung}</p>
                        <div style="display: flex; gap: 2rem; margin-bottom: 1rem; color: rgba(245, 241, 232, 0.8);">
                            <span>${film.genre}</span>
                            <span>${film.dauer} Minuten</span>
                        </div>
                        <div style="font-size: 1.5rem; color: var(--secondary); font-weight: 600;">
                            Ab ${film.preis.toFixed(2)}€ pro Sitz
                        </div>
                    </div>
                </div>
                
                <h3 style="font-size: 1.8rem; margin-bottom: 1.5rem; color: var(--secondary);">Verfügbare Vorstellungen</h3>
                <div style="display: grid; gap: 1rem;" id="vorstellungenContainer">
                    ${vorstellungen.length > 0 ? vorstellungen.map(v => {
                        const verfuegbar = 8 - v.gebucht;
                        let status = 'verfuegbar';
                        let statusText = `${verfuegbar} von 8 Plätzen frei`;
                        
                        if (verfuegbar === 0) {
                            status = 'ausverkauft';
                            statusText = 'Ausverkauft';
                        } else if (verfuegbar <= 2) {
                            status = 'wenig';
                            statusText = `Nur noch ${verfuegbar} Plätze`;
                        }
                        
                        return `
                            <div class="vorstellung-item" data-vorstellung='${JSON.stringify(v)}' data-verfuegbar="${verfuegbar}" 
                                 style="background: rgba(26, 10, 15, 0.5); border: 1px solid rgba(212, 175, 55, 0.2); padding: 1.5rem; cursor: ${verfuegbar > 0 ? 'pointer' : 'not-allowed'}; transition: all 0.3s ease;">
                                <div style="display: flex; justify-content: space-between; align-items: center;">
                                    <div>
                                        <h4 style="font-size: 1.2rem; margin-bottom: 0.5rem; color: var(--secondary);">
                                            ${new Date(v.datum).toLocaleDateString('de-DE', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}
                                        </h4>
                                        <div style="display: flex; gap: 1.5rem; color: rgba(245, 241, 232, 0.8);">
                                            <span>${v.zeit} Uhr</span>
                                            <span>8 Sitzplätze</span>
                                            <span style="color: ${status === 'ausverkauft' ? '#ff6b6b' : status === 'wenig' ? '#fbbf24' : '#4ade80'}; font-weight: 600;">${statusText}</span>
                                        </div>
                                    </div>
                                    <div style="text-align: right;">
                                        <div style="font-size: 1.3rem; color: var(--secondary); font-weight: 600;">${v.preis.toFixed(2)}€</div>
                                        ${verfuegbar > 0 ? 
                                            `<button class="cta-button vorstellung-buchen-btn" style="padding: 0.8rem 1.5rem; margin-top: 0.5rem;">Buchen</button>` : 
                                            '<span style="color: var(--accent);">Ausverkauft</span>'
                                        }
                                    </div>
                                </div>
                            </div>
                        `;
                    }).join('') : '<p style="text-align: center; padding: 2rem; color: rgba(245, 241, 232, 0.6);">Keine Vorstellungen verfügbar</p>'}
                </div>
            `;
            
            document.getElementById('modalContent').innerHTML = modalContent;
            openModal();
            
            // Event Listeners für Vorstellungen
            document.querySelectorAll('.vorstellung-item').forEach(item => {
                const verfuegbar = parseInt(item.dataset.verfuegbar);
                
                if (verfuegbar > 0) {
                    // Hover-Effekt
                    item.addEventListener('mouseenter', () => {
                        item.style.borderColor = 'var(--secondary)';
                    });
                    item.addEventListener('mouseleave', () => {
                        item.style.borderColor = 'rgba(212, 175, 55, 0.2)';
                    });
                    
                    // Click-Handler
                    const buchBtn = item.querySelector('.vorstellung-buchen-btn');
                    if (buchBtn) {
                        buchBtn.addEventListener('click', (e) => {
                            e.stopPropagation();
                            const vorstellung = JSON.parse(item.dataset.vorstellung);
                            zeigeSitzplan(vorstellung);
                        });
                    }
                    
                    item.addEventListener('click', () => {
                        const vorstellung = JSON.parse(item.dataset.vorstellung);
                        zeigeSitzplan(vorstellung);
                    });
                }
            });
        })
        .catch(error => {
            console.error('Fehler beim Laden der Vorstellungen:', error);
        });
}

// Sitzplan anzeigen (8 Sitze)
async function zeigeSitzplan(vorstellung) {
    if (!currentUser) {
        alert('Bitte melden Sie sich an, um Tickets zu buchen.');
        closeModal();
        showLoginModal();
        return;
    }
    
    aktuelleVorstellung = vorstellung;
    ausgewaehlteSitze = [];

    try {
        const response = await fetch(`/api/buchungen/vorstellung/${vorstellung.id}`);
        const belegteSitze = await response.json();
        
        const modalContent = `
            <h2 style="font-family: 'Playfair Display', serif; font-size: 2rem; margin-bottom: 1rem;">Sitzplätze wählen</h2>
            <div style="margin-bottom: 2rem; padding: 1rem; background: rgba(26, 10, 15, 0.5); border: 1px solid rgba(212, 175, 55, 0.2);">
                <h3 style="color: var(--secondary); margin-bottom: 0.5rem;">${vorstellung.titel}</h3>
                <p>${new Date(vorstellung.datum).toLocaleDateString('de-DE', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })} - ${vorstellung.zeit} Uhr</p>
                <p>8 Sitzplätze - ${vorstellung.preis.toFixed(2)}€ pro Sitz</p>
            </div>
            
            <div class="sitzplan-container">
                <div class="leinwand">LEINWAND</div>
                <div class="sitzplan-grid">
                    <!-- Reihe 1 -->
                    <div class="sitzplan-reihe">
                        ${[1, 2, 3, 4].map(sitzNr => `
                            <button class="sitz ${belegteSitze.includes(sitzNr) ? 'belegt' : ''}" 
                                   data-sitz="${sitzNr}"
                                   data-belegt="${belegteSitze.includes(sitzNr)}"
                                   ${belegteSitze.includes(sitzNr) ? 'disabled' : ''}>
                                ${sitzNr}
                            </button>
                        `).join('')}
                    </div>
                    <!-- Reihe 2 -->
                    <div class="sitzplan-reihe">
                        ${[5, 6, 7, 8].map(sitzNr => `
                            <button class="sitz ${belegteSitze.includes(sitzNr) ? 'belegt' : ''}" 
                                   data-sitz="${sitzNr}"
                                   data-belegt="${belegteSitze.includes(sitzNr)}"
                                   ${belegteSitze.includes(sitzNr) ? 'disabled' : ''}>
                                ${sitzNr}
                            </button>
                        `).join('')}
                    </div>
                </div>
                
                <div class="sitz-legende">
                    <div class="legende-item">
                        <div class="legende-box"></div>
                        <span>Verfügbar</span>
                    </div>
                    <div class="legende-item">
                        <div class="legende-box ausgewaehlt"></div>
                        <span>Ausgewählt</span>
                    </div>
                    <div class="legende-item">
                        <div class="legende-box belegt"></div>
                        <span>Belegt</span>
                    </div>
                </div>
            </div>
            
            <div id="buchungsSummary" style="margin-top: 2rem; padding: 1.5rem; background: rgba(212, 175, 55, 0.1); border: 1px solid rgba(212, 175, 55, 0.3); display: none;">
                <h3 style="margin-bottom: 1rem; color: var(--secondary);">Ihre Auswahl</h3>
                <p>Ausgewählte Sitze: <span id="selectedSeatsText" style="font-weight: 600;"></span></p>
                <p>Anzahl: <span id="seatCount" style="font-weight: 600;">0</span></p>
                <p style="font-size: 1.3rem; color: var(--secondary); font-weight: 700; margin-top: 0.5rem;">
                    Gesamt: <span id="totalPrice">0.00</span>€
                </p>
                <button id="buchungAbschliessenBtn" class="submit-button" style="margin-top: 1rem;">
                    Jetzt buchen
                </button>
            </div>
        `;
        
        document.getElementById('modalContent').innerHTML = modalContent;
        openModal();
        
        // Event Listeners für Sitze
        document.querySelectorAll('.sitz').forEach(sitzBtn => {
            sitzBtn.addEventListener('click', () => {
                const sitzNr = parseInt(sitzBtn.dataset.sitz);
                const belegt = sitzBtn.dataset.belegt === 'true';
                toggleSitz(sitzNr, belegt, sitzBtn);
            });
        });
        
        // Event Listener für Buchung abschließen
        const buchungBtn = document.getElementById('buchungAbschliessenBtn');
        if (buchungBtn) {
            buchungBtn.addEventListener('click', buchungAbschliessen);
        }
        
    } catch (error) {
        console.error('Fehler beim Laden des Sitzplans:', error);
    }
}

// Multi-Sitz Auswahl
function toggleSitz(sitzNr, belegt, sitzElement) {
    if (belegt) return;

    if (ausgewaehlteSitze.includes(sitzNr)) {
        // Sitz abwählen
        ausgewaehlteSitze = ausgewaehlteSitze.filter(s => s !== sitzNr);
        sitzElement.classList.remove('ausgewaehlt');
    } else {
        // Sitz auswählen
        ausgewaehlteSitze.push(sitzNr);
        sitzElement.classList.add('ausgewaehlt');
    }

    updateBuchungsSummary();
}

function updateBuchungsSummary() {
    const summary = document.getElementById('buchungsSummary');
    if (ausgewaehlteSitze.length === 0) {
        summary.style.display = 'none';
        return;
    }

    summary.style.display = 'block';

    const sortedSeats = [...ausgewaehlteSitze].sort((a, b) => a - b);
    document.getElementById('selectedSeatsText').textContent = sortedSeats.join(', ');
    document.getElementById('seatCount').textContent = ausgewaehlteSitze.length;

    const totalPrice = (aktuelleVorstellung.preis * ausgewaehlteSitze.length).toFixed(2);
    document.getElementById('totalPrice').textContent = totalPrice;
}

// Buchung abschließen
async function buchungAbschliessen() {
    if (ausgewaehlteSitze.length === 0) {
        alert('Bitte wählen Sie mindestens einen Sitz aus');
        return;
    }
    if (!currentUser) {
        alert('Bitte melden Sie sich an');
        closeModal();
        showLoginModal();
        return;
    }

    const buchungsDaten = {
        vorstellung_id: aktuelleVorstellung.id,
        sitze: ausgewaehlteSitze
    };

    try {
        const response = await fetch('/api/buchungen', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(buchungsDaten)
        });
        
        const result = await response.json();
        
        if (response.ok) {
            zeigeBuchungsBestaetigung(result);
        } else {
            alert(result.error || 'Fehler bei der Buchung');
        }
    } catch (error) {
        console.error('Fehler bei der Buchung:', error);
        alert('Fehler bei der Buchung. Bitte versuchen Sie es erneut.');
    }
}

// Buchungsbestätigung mit 8-stelligem Code
function zeigeBuchungsBestaetigung(buchung) {
    // Sitze formatieren
    let sitzeText;
    if (Array.isArray(buchung.sitze)) {
        sitzeText = buchung.sitze.join(', ');
    } else {
        try {
            const sitzeArray = JSON.parse(buchung.sitze);
            sitzeText = sitzeArray.join(', ');
        } catch (e) {
            sitzeText = buchung.sitze;
        }
    }
    
    const modalContent = `
        <div style="text-align: center;">
            <h2 style="font-family: 'Playfair Display', serif; font-size: 2.5rem; margin-bottom: 1rem; color: var(--secondary);">
                Buchung erfolgreich!
            </h2>
            <p style="margin-bottom: 2rem; color: rgba(245, 241, 232, 0.8);">
                Ihre Buchung wurde erfolgreich abgeschlossen.
            </p>
            
            <div style="background: rgba(26, 10, 15, 0.8); border: 2px solid var(--secondary); border-radius: 10px; padding: 2rem; margin: 2rem 0;">
                <h3 style="color: var(--secondary); margin-bottom: 1rem;">Ihr Buchungscode</h3>
                <div style="font-family: 'Courier New', monospace; font-size: 2.5rem; letter-spacing: 0.5rem; 
                           background: var(--dark); padding: 1.5rem; border-radius: 8px; 
                           color: var(--secondary); font-weight: bold; margin: 1rem 0;">
                    ${buchung.buchungscode}
                </div>
                <p style="color: rgba(245, 241, 232, 0.8); margin-top: 1rem;">
                    Notieren Sie sich diesen Code! Sie benötigen ihn für den Einlass.
                </p>
            </div>
            
            <div style="background: rgba(26, 10, 15, 0.5); padding: 1.5rem; border-radius: 8px; margin: 2rem 0; text-align: left;">
                <p><strong>Buchungsnummer:</strong> ${buchung.buchungsnummer || buchung.id}</p>
                <p><strong>Anzahl Sitze:</strong> ${buchung.anzahl_sitze}</p>
                <p><strong>Gesamtpreis:</strong> ${buchung.gesamt_preis.toFixed(2)}€</p>
                <p><strong>Vorstellung:</strong> ${buchung.titel} am ${new Date(buchung.datum).toLocaleDateString('de-DE')} um ${buchung.zeit} Uhr</p>
                <p><strong>Sitze:</strong> ${sitzeText}</p>
            </div>
            
            <div style="display: flex; gap: 1rem; margin-top: 2rem; flex-wrap: wrap; justify-content: center;">
                <button id="copyCodeBtn" data-code="${buchung.buchungscode}" class="cta-button">
                    Code kopieren
                </button>
                <button id="closeSuccessBtn" class="cta-button" style="background: var(--mid);">
                    Weitere Filme ansehen
                </button>
            </div>
            
            <p style="margin-top: 2rem; color: rgba(245, 241, 232, 0.8); font-size: 0.9rem;">
                Sie haben eine Bestätigungs-E-Mail mit diesem Code erhalten.<br>
                Bitte kommen Sie 15 Minuten vor Vorstellungsbeginn und zeigen Sie den Code vor.
            </p>
        </div>
    `;

    document.getElementById('modalContent').innerHTML = modalContent;
    
    // Event Listeners
    const copyBtn = document.getElementById('copyCodeBtn');
    if (copyBtn) {
        copyBtn.addEventListener('click', () => {
            const code = copyBtn.dataset.code;
            copyBookingCode(code);
        });
    }
    
    const closeBtn = document.getElementById('closeSuccessBtn');
    if (closeBtn) {
        closeBtn.addEventListener('click', () => {
            closeModal();
            ladeFilme();
        });
    }
}

// Code kopieren
function copyBookingCode(code) {
    navigator.clipboard.writeText(code).then(() => {
        alert('Buchungscode erfolgreich kopiert!');
    }).catch(err => {
        console.error('Fehler beim Kopieren:', err);
        alert('Fehler beim Kopieren des Codes');
    });
}

// PayPal Spenden
async function openPayPalDonation() {
    try {
        const response = await fetch('/api/paypal-donation-link');
        const data = await response.json();
        if (data.link && data.link !== 'https://www.paypal.com/donate/?hosted_button_id=DEINE_BUTTON_ID') {
            window.open(data.link, '_blank');
        } else {
            alert('PayPal-Spendenlink noch nicht konfiguriert. Bitte fügen Sie Ihre PayPal-Button-ID in der .env Datei hinzu.');
        }
    } catch (error) {
        console.error('Fehler beim Laden des PayPal-Links:', error);
        alert('Spendenfunktion vorübergehend nicht verfügbar.');
    }
}

// Modal Funktionen
function openModal() {
    document.getElementById('buchungsModal').classList.add('active');
    document.body.style.overflow = 'hidden';
}

function closeModal() {
    document.getElementById('buchungsModal').classList.remove('active');
    document.body.style.overflow = '';
}

// Meine Buchungen
async function showMyBookings() {
    alert('Diese Funktion wird bald verfügbar sein!');
    const dropdown = document.getElementById('userDropdown');
    if (dropdown) dropdown.classList.remove('show');
}
