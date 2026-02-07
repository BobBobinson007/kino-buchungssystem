let turnstileToken = null;

const passwordInput = document.getElementById('password');
const errorDiv = document.getElementById('error');
const turnstileLoader = document.getElementById('turnstileLoader');
const turnstileWidget = document.querySelector('.cf-turnstile');

function showError(message) {
    errorDiv.textContent = message;
    setTimeout(() => {
        errorDiv.textContent = '';
    }, 4000);
}

function showStatus(message, color = '#d4af37') {
    turnstileLoader.style.display = 'block';
    turnstileLoader.style.height = 'auto';
    turnstileLoader.innerHTML = `<div style="color:${color}; font-size:0.9rem">${message}</div>`;
}

function submitPassword() {
    const password = passwordInput.value.trim();

    if (!turnstileToken) {
        showError('Bitte bestätigen Sie zuerst den Bot-Schutz');
        return;
    }

    if (password.length !== 4) {
        showError('Bitte geben Sie genau 4 Zeichen ein');
        return;
    }

    fetch('/api/app-password', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            password,
            cf_turnstile_response: turnstileToken
        })
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                window.location.href = '/';
            } else {
                showError(data.error || 'Falscher Zugangscode oder Verifikation fehlgeschlagen');
                passwordInput.value = '';
                passwordInput.focus();

                if (window.turnstile && typeof window.turnstile.reset === 'function') {
                    window.turnstile.reset();
                }
                turnstileToken = null;
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showError('Verbindungsfehler. Bitte später erneut versuchen.');
        });
}

window.turnstileCallback = function turnstileCallback(token) {
    turnstileToken = token;
    turnstileLoader.style.display = 'none';
    turnstileWidget.classList.add('loaded');
};

window.turnstileErrorCallback = function turnstileErrorCallback() {
    showStatus('Turnstile konnte nicht geladen werden. Prüfe Adblocker/VPN oder Domain-Zulassung.', '#ef4444');
};

window.turnstileExpiredCallback = function turnstileExpiredCallback() {
    turnstileToken = null;
    showStatus('Verifizierung abgelaufen. Bitte erneut bestätigen.');
};

window.turnstileTimeoutCallback = function turnstileTimeoutCallback() {
    showStatus('Verifizierung hat zu lange gedauert. Bitte erneut versuchen.', '#ef4444');
};

function markLoaded() {
    turnstileLoader.style.display = 'none';
    turnstileWidget.classList.add('loaded');
}

const widgetObserver = new MutationObserver(() => {
    if (turnstileWidget.querySelector('iframe')) {
        markLoaded();
        widgetObserver.disconnect();
    }
});

widgetObserver.observe(turnstileWidget, { childList: true, subtree: true });

const turnstileScript = document.querySelector('script[src*="challenges.cloudflare.com/turnstile"]');
if (turnstileScript) {
    turnstileScript.addEventListener('error', () => {
        showStatus('Turnstile-Skript blockiert oder nicht erreichbar.', '#ef4444');
    });
}

passwordInput.addEventListener('input', function onInput() {
    let value = this.value.toUpperCase();
    value = value.replace(/[^A-Z0-9]/g, '');
    this.value = value;

    if (value.length === 4 && turnstileToken) {
        submitPassword();
    }
});

passwordInput.addEventListener('keypress', function onKeypress(e) {
    if (e.key === 'Enter' && this.value.length === 4 && turnstileToken) {
        submitPassword();
    }
});

passwordInput.addEventListener('input', function onClear() {
    if (this.value.length === 0 && turnstileToken) {
        if (window.turnstile && typeof window.turnstile.reset === 'function') {
            window.turnstile.reset();
        }
        turnstileToken = null;
    }
});

setTimeout(() => {
    if (!turnstileToken && turnstileLoader.style.display !== 'none') {
        showStatus('Verifizierung wird geladen...');

        setTimeout(() => {
            if (!turnstileToken && !turnstileWidget.querySelector('iframe')) {
                showStatus('Verifizierung fehlgeschlagen?<br>Bitte Seite neu laden oder VPN deaktivieren', '#ef4444');
            }
        }, 5000);
    }
}, 8000);
