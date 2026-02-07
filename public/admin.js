// ============ GLOBALE VARIABLEN ============
let alleFilme = [];
let alleVorstellungen = [];

// ============ INITIALISIERUNG ============
document.addEventListener('DOMContentLoaded', async () => {
    try {
        const response = await fetch('/api/admin/status');
        const status = await response.json();
        
        if (!status.loggedIn) {
            window.location.href = '/';
            return;
        }
        
        const userDisplay = document.getElementById('adminUsername');
        if (userDisplay) userDisplay.textContent = `Angemeldet als: ${status.username}`;
        
        // Event Listeners initialisieren
        initEventListeners();
        
        // Daten laden
        ladeStatistiken();
        ladeAlleFilme();
        ladeAlleVorstellungen();
        ladeAlleBuchungen();
        ladeAlleSpenden();
    } catch (error) {
        console.error('Fehler beim Auth-Check:', error);
        window.location.href = '/';
    }
});

// ============ EVENT LISTENERS ============
function initEventListeners() {
    // Logout Button
    const logoutBtn = document.getElementById('adminLogoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', (e) => {
            e.preventDefault();
            adminLogout();
        });
    }
    
    // Sidebar Navigation
    document.querySelectorAll('.menu-item').forEach(item => {
        item.addEventListener('click', (e) => {
            const section = e.currentTarget.dataset.section;
            showSection(e, section);
        });
    });
    
    // Code Verifikation Form
    const codeForm = document.getElementById('codeVerifikationForm');
    if (codeForm) {
        codeForm.addEventListener('submit', (e) => {
            e.preventDefault();
            verifyBookingCode();
        });
    }

    
    
    // Film Form Buttons
    const showFilmBtn = document.getElementById('showFilmFormBtn');
    if (showFilmBtn) showFilmBtn.addEventListener('click', showFilmForm);
    
    const hideFilmBtn = document.getElementById('hideFilmFormBtn');
    if (hideFilmBtn) hideFilmBtn.addEventListener('click', hideFilmForm);
    
    const filmForm = document.getElementById('filmFormElement');
    if (filmForm) filmForm.addEventListener('submit', speichereFilm);
    
    // Vorstellung Form Buttons
    const showVorstellungBtn = document.getElementById('showVorstellungFormBtn');
    if (showVorstellungBtn) showVorstellungBtn.addEventListener('click', showVorstellungForm);
    
    const hideVorstellungBtn = document.getElementById('hideVorstellungFormBtn');
    if (hideVorstellungBtn) hideVorstellungBtn.addEventListener('click', hideVorstellungForm);
    
    const vorstellungForm = document.getElementById('vorstellungFormElement');
    if (vorstellungForm) vorstellungForm.addEventListener('submit', speichereVorstellung);
}

// ============ NAVIGATION ============
function showSection(event, sectionId) {
    // 1. Alle Sektionen verstecken
    document.querySelectorAll('.admin-section').forEach(s => s.classList.remove('active'));
    // 2. Alle Menü-Buttons deaktivieren
    document.querySelectorAll('.menu-item').forEach(m => m.classList.remove('active'));
    // 3. Ziel-Sektion anzeigen
    const target = document.getElementById(sectionId);
    if (target) target.classList.add('active');

    // 4. Aktiven Button markieren
    if (event && event.currentTarget) {
        event.currentTarget.classList.add('active');
    }
}

async function adminLogout() {
    try {
        await fetch('/api/admin/logout', { method: 'POST' });
        window.location.href = '/';
    } catch (error) {
        console.error('Logout Fehler:', error);
        window.location.href = '/';
    }
}

// ============ STATISTIKEN ============
async function ladeStatistiken() {
    try {
        const response = await fetch('/api/admin/statistiken');
        const stats = await response.json();
        
        document.getElementById('statFilme').textContent = stats.aktiveFilme || 0;
        document.getElementById('statBuchungen').textContent = stats.totalBuchungen || 0;
        document.getElementById('statUsers').textContent = stats.totalUsers || 0;
        document.getElementById('statSpenden').textContent = (stats.totalSpenden || 0).toFixed(2) + '€';
    } catch (error) {
        console.error('Fehler beim Laden der Statistiken:', error);
    }
}

// ============ CODE VERIFIKATION ============
async function verifyBookingCode() {
    const codeInput = document.getElementById('bookingCodeInput');
    const code = codeInput.value.trim().toUpperCase();
    
    if (!code || code.length !== 8) {
        alert('Bitte geben Sie einen gültigen 8-stelligen Buchungscode ein');
        return;
    }
    
    const resultDiv = document.getElementById('verificationResult');
    resultDiv.innerHTML = '<p style="text-align: center; color: var(--secondary);">Verifiziere Code...</p>';
    
    try {
        const response = await fetch('/api/admin/verify-qr', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ qrData: code })
        });
        
        const result = await response.json();
        
        if (response.ok && result.valid) {
            // Sitze formatieren
            let sitzeText = '';
            if (result.buchung && result.buchung.sitze) {
                if (Array.isArray(result.buchung.sitze)) {
                    sitzeText = result.buchung.sitze.join(', ');
                } else {
                    sitzeText = result.buchung.sitze;
                }
            }
            
            if (result.alreadyVerified) {
                resultDiv.innerHTML = `
                    <div style="background: rgba(255, 193, 7, 0.2); border: 2px solid #ffc107; padding: 1.5rem; border-radius: 8px;">
                        <h3 style="color: #ffc107; margin-bottom: 1rem;">⚠️ Bereits eingelassen!</h3>
                        <p><strong>Film:</strong> ${result.buchung.film}</p>
                        <p><strong>Kunde:</strong> ${result.buchung.kunde}</p>
                        <p><strong>Code:</strong> ${result.buchung.code}</p>
                        <p style="margin-top: 1rem; color: rgba(245, 241, 232, 0.8);">
                            Diese Buchung wurde bereits verifiziert.
                        </p>
                    </div>
                `;
            } else {
                resultDiv.innerHTML = `
                    <div style="background: rgba(40, 167, 69, 0.2); border: 2px solid #28a745; padding: 1.5rem; border-radius: 8px;">
                        <h3 style="color: #28a745; margin-bottom: 1rem;">✓ Buchung verifiziert!</h3>
                        <p><strong>Film:</strong> ${result.buchung.film}</p>
                        <p><strong>Kunde:</strong> ${result.buchung.kunde}</p>
                        ${sitzeText ? `<p><strong>Sitze:</strong> ${sitzeText}</p>` : ''}
                        <p style="margin-top: 1rem; font-weight: bold; color: #28a745; font-size: 1.2rem;">
                            ✅ Einlass gewähren
                        </p>
                    </div>
                `;
                
                // Buchungen neu laden
                setTimeout(() => {
                    ladeAlleBuchungen();
                }, 1000);
            }
            
            // Code-Feld leeren für nächste Verifikation
            codeInput.value = '';
            codeInput.focus();
            
        } else {
            resultDiv.innerHTML = `
                <div style="background: rgba(220, 53, 69, 0.2); border: 2px solid #dc3545; padding: 1.5rem; border-radius: 8px;">
                    <h3 style="color: #dc3545; margin-bottom: 1rem;">✗ Code ungültig!</h3>
                    <p>${result.error || 'Der eingegebene Code ist ungültig oder existiert nicht.'}</p>
                </div>
            `;
            
            codeInput.focus();
        }
    } catch (error) {
        console.error('Fehler bei der Code-Verifikation:', error);
        resultDiv.innerHTML = `
            <div style="background: rgba(220, 53, 69, 0.2); border: 2px solid #dc3545; padding: 1.5rem; border-radius: 8px;">
                <h3 style="color: #dc3545; margin-bottom: 1rem;">✗ Fehler!</h3>
                <p>Fehler bei der Verifikation. Bitte versuchen Sie es erneut.</p>
            </div>
        `;
    }
}

// ============ FILME ============
async function ladeAlleFilme() {
    try {
        const response = await fetch('/api/admin/filme');
        alleFilme = await response.json();
        zeigeFilmeListe();
        aktualisiereFilmDropdown();
    } catch (error) {
        console.error('Fehler beim Laden der Filme:', error);
    }
}

function zeigeFilmeListe() {
    const tbody = document.getElementById('filmeTable');
    if (!tbody) return;
    
    if (alleFilme.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="empty-state">Keine Filme vorhanden</td></tr>';
        return;
    }

    tbody.innerHTML = alleFilme.map(film => `
        <tr>
            <td><img src="${film.cover_url}" alt="${film.titel}" class="film-cover-thumb" style="width:50px; height:75px; object-fit:cover; border-radius:4px;"></td>
            <td><strong>${film.titel}</strong></td>
            <td>${film.genre}</td>
            <td>${film.dauer} Min.</td>
            <td>${film.preis.toFixed(2)}€</td>
            <td>Woche ${film.woche}</td>
            <td><span class="status-badge ${film.aktiv ? 'status-aktiv' : 'status-inaktiv'}">${film.aktiv ? 'Aktiv' : 'Inaktiv'}</span></td>
            <td>
                <div class="action-buttons">
                    <button class="action-btn bearbeiten-film-btn" data-film-id="${film.id}">Bearbeiten</button>
                    <button class="action-btn delete loeschen-film-btn" data-film-id="${film.id}">Löschen</button>
                </div>
            </td>
        </tr>
    `).join('');
    
    // Event Listeners für Buttons
    document.querySelectorAll('.bearbeiten-film-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const filmId = parseInt(btn.dataset.filmId);
            bearbeiteFilm(filmId);
        });
    });
    
    document.querySelectorAll('.loeschen-film-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const filmId = parseInt(btn.dataset.filmId);
            loescheFilm(filmId);
        });
    });
}

function showFilmForm() {
    document.getElementById('filmForm').style.display = 'block';
    document.getElementById('filmId').value = '';
    
    // Formular leeren
    document.getElementById('filmTitel').value = '';
    document.getElementById('filmGenre').value = '';
    document.getElementById('filmBeschreibung').value = '';
    document.getElementById('filmDauer').value = '';
    document.getElementById('filmPreis').value = '';
    document.getElementById('filmWoche').value = '1';
    document.getElementById('filmCover').value = '';
}

function hideFilmForm() {
    document.getElementById('filmForm').style.display = 'none';
    document.getElementById('filmId').value = '';
}

function bearbeiteFilm(filmId) {
    const film = alleFilme.find(f => f.id === filmId);
    if (!film) return;
    
    document.getElementById('filmId').value = film.id;
    document.getElementById('filmTitel').value = film.titel;
    document.getElementById('filmGenre').value = film.genre;
    document.getElementById('filmBeschreibung').value = film.beschreibung || '';
    document.getElementById('filmDauer').value = film.dauer;
    document.getElementById('filmPreis').value = film.preis;
    document.getElementById('filmWoche').value = film.woche;
    document.getElementById('filmCover').value = film.cover_url;
    
    document.getElementById('filmForm').style.display = 'block';
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

async function loescheFilm(filmId) {
    if (!confirm('Film wirklich dauerhaft löschen? (inkl. Vorstellungen/Buchungen)')) return;
    
    try {
        const response = await fetch(`/api/admin/filme/${filmId}`, {
            method: 'DELETE'
        });
        
        if (response.ok) {
            alert('Film wurde gelöscht');
            ladeAlleFilme();
            ladeAlleVorstellungen();
            ladeStatistiken();
        } else {
            const error = await response.json();
            alert(error.error || 'Fehler beim Löschen');
        }
    } catch (error) {
        console.error('Fehler:', error);
        alert('Fehler beim Löschen des Films');
    }
}

async function speichereFilm(event) {
    event.preventDefault();
    const filmId = document.getElementById('filmId').value;
    const filmData = {
        titel: document.getElementById('filmTitel').value,
        genre: document.getElementById('filmGenre').value,
        beschreibung: document.getElementById('filmBeschreibung').value,
        dauer: parseInt(document.getElementById('filmDauer').value),
        preis: parseFloat(document.getElementById('filmPreis').value),
        woche: parseInt(document.getElementById('filmWoche').value),
        cover_url: document.getElementById('filmCover').value || 'https://images.unsplash.com/photo-1478720568477-152d9b164e26',
        aktiv: 1
    };
    
    try {
        const url = filmId ? `/api/admin/filme/${filmId}` : '/api/admin/filme';
        const method = filmId ? 'PUT' : 'POST';

        const response = await fetch(url, {
            method: method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(filmData)
        });

        if (response.ok) {
            alert('Film erfolgreich gespeichert');
            hideFilmForm();
            ladeAlleFilme();
            ladeStatistiken();
        } else {
            const error = await response.json();
            alert(error.error || 'Fehler beim Speichern');
        }
    } catch (error) {
        console.error('Fehler:', error);
        alert('Fehler beim Speichern des Films');
    }
}

// ============ VORSTELLUNGEN ============
async function ladeAlleVorstellungen() {
    try {
        const response = await fetch('/api/admin/vorstellungen');
        alleVorstellungen = await response.json();
        zeigeVorstellungenListe();
    } catch (error) {
        console.error('Fehler:', error);
    }
}

function zeigeVorstellungenListe() {
    const tbody = document.getElementById('vorstellungenTable');
    if (!tbody) return;
    
    if (alleVorstellungen.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-state">Keine Vorstellungen vorhanden</td></tr>';
        return;
    }
    
    tbody.innerHTML = alleVorstellungen.map(v => `
        <tr>
            <td><strong>${v.titel}</strong></td>
            <td>${new Date(v.datum).toLocaleDateString('de-DE')}</td>
            <td>${v.zeit} Uhr</td>
            <td>${v.gebucht || 0} / 8</td>
            <td>${v.preis.toFixed(2)}€</td>
            <td>
                <div class="action-buttons">
                    <button class="action-btn delete loeschen-vorstellung-btn" data-vorstellung-id="${v.id}">Löschen</button>
                </div>
            </td>
        </tr>
    `).join('');

    document.querySelectorAll('.loeschen-vorstellung-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const vorstellungId = parseInt(btn.dataset.vorstellungId);
            loescheVorstellung(vorstellungId);
        });
    });
}

function aktualisiereFilmDropdown() {
    const select = document.getElementById('vorstellungFilm');
    if (!select) return;
    
    select.innerHTML = '<option value="">Bitte wählen</option>' +
        alleFilme.filter(f => f.aktiv).map(f => `<option value="${f.id}">${f.titel}</option>`).join('');
}

function showVorstellungForm() {
    document.getElementById('vorstellungForm').style.display = 'block';
    
    // Formular leeren
    document.getElementById('vorstellungFilm').value = '';
    document.getElementById('vorstellungDatum').value = '';
    document.getElementById('vorstellungZeit').value = '';
    document.getElementById('vorstellungPreis').value = '';
}

function hideVorstellungForm() {
    document.getElementById('vorstellungForm').style.display = 'none';
}

async function speichereVorstellung(event) {
    event.preventDefault();
    
    const vorstellungData = {
        film_id: parseInt(document.getElementById('vorstellungFilm').value),
        datum: document.getElementById('vorstellungDatum').value,
        zeit: document.getElementById('vorstellungZeit').value,
        preis: parseFloat(document.getElementById('vorstellungPreis').value)
    };
    
    try {
        const response = await fetch('/api/admin/vorstellungen', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(vorstellungData)
        });

        if (response.ok) {
            alert('Vorstellung erfolgreich erstellt (8 Sitzplätze)');
            hideVorstellungForm();
            ladeAlleVorstellungen();
        } else {
            const error = await response.json();
            alert(error.error || 'Fehler beim Speichern');
        }
    } catch (error) {
        console.error('Fehler:', error);
        alert('Fehler beim Erstellen der Vorstellung');
    }
}

async function loescheVorstellung(vorstellungId) {
    if (!confirm('Vorstellung wirklich dauerhaft löschen? (inkl. Buchungen)')) return;

    try {
        const response = await fetch(`/api/admin/vorstellungen/${vorstellungId}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            alert('Vorstellung wurde gelöscht');
            ladeAlleVorstellungen();
            ladeStatistiken();
        } else {
            const error = await response.json();
            alert(error.error || 'Fehler beim Löschen');
        }
    } catch (error) {
        console.error('Fehler:', error);
        alert('Fehler beim Löschen der Vorstellung');
    }
}

// ============ BUCHUNGEN ============
async function ladeAlleBuchungen() {
    try {
        const response = await fetch('/api/admin/buchungen');
        const buchungen = await response.json();
        
        const tbody = document.getElementById('buchungenTable');
        if (!tbody) return;
        
        if (buchungen.length === 0) {
            tbody.innerHTML = '<tr><td colspan="9" class="empty-state">Keine Buchungen vorhanden</td></tr>';
            return;
        }
        
        tbody.innerHTML = buchungen.map(b => {
            // Sitze formatieren
            let sitzeText = '';
            try {
                const sitzeArray = JSON.parse(b.sitze);
                sitzeText = sitzeArray.join(', ');
            } catch (e) {
                sitzeText = b.sitze;
            }
            
            return `
                <tr>
                    <td><strong>#${b.id}</strong></td>
                    <td style="font-family: 'Courier New', monospace; font-weight: 600;">${b.buchungscode || '-'}</td>
                    <td>${b.titel}</td>
                    <td>${new Date(b.datum).toLocaleDateString('de-DE')} / ${b.zeit}</td>
                    <td>${sitzeText}</td>
                    <td>${b.gesamt_preis ? b.gesamt_preis.toFixed(2) + '€' : '-'}</td>
                    <td>${b.name}</td>
                    <td>
                        <span class="status-badge ${b.verified ? 'status-aktiv' : 'status-inaktiv'}">
                            ${b.verified ? '✓ Eingelassen' : 'Offen'}
                        </span>
                    </td>
                    <td>${new Date(b.gebucht_am || b.erstellt_am).toLocaleDateString('de-DE')}</td>
                </tr>
            `;
        }).join('');
    } catch (error) {
        console.error('Fehler beim Laden der Buchungen:', error);
    }
}

// ============ SPENDEN ============
async function ladeAlleSpenden() {
    try {
        const response = await fetch('/api/admin/spenden');
        const spenden = await response.json();
        
        const tbody = document.getElementById('spendenTable');
        if (!tbody) return;
        
        if (spenden.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="empty-state">Keine Spenden vorhanden</td></tr>';
            return;
        }
        
        tbody.innerHTML = spenden.map(s => `
            <tr>
                <td>${new Date(s.datum).toLocaleDateString('de-DE')}</td>
                <td>${s.name || 'Anonym'}</td>
                <td><strong>${s.betrag ? s.betrag.toFixed(2) : '0.00'}€</strong></td>
                <td>${s.nachricht || '-'}</td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Fehler beim Laden der Spenden:', error);
    }
}
