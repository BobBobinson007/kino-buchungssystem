(function () {
    const consentKey = 'cookieConsent';
    const banner = document.getElementById('cookieBanner');
    const acceptBtn = document.getElementById('acceptCookiesBtn');
    const declineBtn = document.getElementById('declineCookiesBtn');

    function checkConsent() {
        const consent = localStorage.getItem(consentKey);
        if (!consent) {
            banner && banner.classList.add('show');
            return;
        }
    }

    if (acceptBtn) {
        acceptBtn.addEventListener('click', () => {
            localStorage.setItem(consentKey, 'accepted');
            banner && banner.classList.remove('show');
        });
    }

    if (declineBtn) {
        declineBtn.addEventListener('click', () => {
            localStorage.setItem(consentKey, 'declined');
            banner && banner.classList.remove('show');
        });
    }

    checkConsent();

    const pendingPayloads = {};
    const turnstileWidgetIds = {};

    function renderTurnstile(formId, containerId) {
        if (!window.turnstile || turnstileWidgetIds[formId]) return;
        turnstileWidgetIds[formId] = window.turnstile.render(`#${containerId}`, {
            sitekey: '0x4AAAAAACZzI2XDWas_NJDV',
            size: 'invisible',
            callback: (token) => {
                submitContact(formId, token);
            }
        });
    }

    async function submitContact(formId, token) {
        const payloadBase = pendingPayloads[formId];
        if (!payloadBase) return;
        const status = document.getElementById(payloadBase.statusId);
        const payload = { ...payloadBase.payload, turnstileToken: token };
        try {
            const res = await fetch('/api/contact', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            if (!res.ok) throw new Error('Senden fehlgeschlagen');
            if (status) status.textContent = 'Danke! Wir melden uns.';
            const formEl = document.getElementById(formId);
            if (formEl) formEl.reset();
        } catch (err) {
            if (status) status.textContent = 'Konnte nicht senden. Bitte spaeter erneut versuchen.';
        } finally {
            pendingPayloads[formId] = null;
            if (window.turnstile && turnstileWidgetIds[formId]) {
                window.turnstile.reset(turnstileWidgetIds[formId]);
            }
        }
    }

    function setupForm(config) {
        const form = document.getElementById(config.formId);
        if (!form) return;
        form.addEventListener('submit', (e) => {
            e.preventDefault();
            const status = document.getElementById(config.statusId);
            const name = document.getElementById(config.nameId).value.trim();
            const email = document.getElementById(config.emailId).value.trim();
            const message = document.getElementById(config.messageId).value.trim();
            const consent = document.getElementById(config.consentId).checked;
            const subject = config.subjectId ? document.getElementById(config.subjectId).value.trim() : '';

            if (!consent) {
                if (status) status.textContent = 'Bitte Zustimmung zur Verarbeitung geben.';
                return;
            }

            const composedMessage = subject
                ? `Betreff: ${subject}\n\n${message}`
                : message;

            pendingPayloads[config.formId] = {
                statusId: config.statusId,
                payload: { name, email, message: composedMessage }
            };
            if (status) status.textContent = 'Pruefe...';

            renderTurnstile(config.formId, config.turnstileId);
            if (window.turnstile && turnstileWidgetIds[config.formId]) {
                window.turnstile.execute(turnstileWidgetIds[config.formId]);
            } else {
                if (status) status.textContent = 'Turnstile konnte nicht geladen werden.';
                pendingPayloads[config.formId] = null;
            }
        });
    }

    setupForm({
        formId: 'contactForm',
        nameId: 'contactName',
        emailId: 'contactEmail',
        messageId: 'contactMessage',
        consentId: 'contactConsent',
        statusId: 'contactStatus',
        turnstileId: 'turnstile'
    });

    setupForm({
        formId: 'adminContactForm',
        nameId: 'adminName',
        emailId: 'adminEmail',
        messageId: 'adminMessage',
        consentId: 'adminConsent',
        statusId: 'adminStatus',
        turnstileId: 'adminTurnstile',
        subjectId: 'adminSubject'
    });
})();
