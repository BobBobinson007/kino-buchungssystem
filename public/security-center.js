const statusEl = document.getElementById('status');
const messageEl = document.getElementById('message');
const mfaStateEl = document.getElementById('mfaState');
const sessionStateEl = document.getElementById('sessionState');

const usernameEl = document.getElementById('username');
const passwordEl = document.getElementById('password');
const tokenEl = document.getElementById('token');

const loginBtn = document.getElementById('loginBtn');
const logoutBtn = document.getElementById('logoutBtn');
const printBtn = document.getElementById('printBtn');
const exportBtn = document.getElementById('exportBtn');

const rangeSelect = document.getElementById('rangeSelect');
const levelSelect = document.getElementById('levelSelect');
const viewSelect = document.getElementById('viewSelect');

const totalCountEl = document.getElementById('totalCount');
const warnCountEl = document.getElementById('warnCount');
const errorCountEl = document.getElementById('errorCount');
const lastErrorEl = document.getElementById('lastError');
const failedLoginsEl = document.getElementById('failedLogins');
const otpFailuresEl = document.getElementById('otpFailures');
const adminActionsEl = document.getElementById('adminActions');
const refreshStateEl = document.getElementById('refreshState');
const lastUpdateEl = document.getElementById('lastUpdate');
const threatLevelEl = document.getElementById('threatLevel');
const threatHintEl = document.getElementById('threatHint');
const postureScoreEl = document.getElementById('postureScore');
const postureBarEl = document.getElementById('postureBar');
const postureLabelEl = document.getElementById('postureLabel');
const policyCoverageEl = document.getElementById('policyCoverage');
const misconfigCountEl = document.getElementById('misconfigCount');
const endpointDriftEl = document.getElementById('endpointDrift');
const credHygieneEl = document.getElementById('credHygiene');
const geoPolicyEl = document.getElementById('geoPolicy');
const botShieldEl = document.getElementById('botShield');
const activeSessionsEl = document.getElementById('activeSessions');
const chartPeakEl = document.getElementById('chartPeak');
const chartAvgEl = document.getElementById('chartAvg');
const uptimeSlaEl = document.getElementById('uptimeSla');
const dlpRulesEl = document.getElementById('dlpRules');
const keyRotationEl = document.getElementById('keyRotation');
const vaultHealthEl = document.getElementById('vaultHealth');
const lastBackupEl = document.getElementById('lastBackup');
const restoreTestEl = document.getElementById('restoreTest');
const dbIntegrityEl = document.getElementById('dbIntegrity');
const signalLoginEl = document.getElementById('signalLogin');
const signalPageEl = document.getElementById('signalPage');
const signalCheckoutEl = document.getElementById('signalCheckout');
const signalAdminEl = document.getElementById('signalAdmin');
const signalPdfEl = document.getElementById('signalPdf');
const signalApiEl = document.getElementById('signalApi');
const sessionDriftEl = document.getElementById('sessionDrift');
const geoShiftEl = document.getElementById('geoShift');
const deviceShiftEl = document.getElementById('deviceShift');
const servicePaymentStatusEl = document.getElementById('servicePaymentStatus');
const servicePaymentLatencyEl = document.getElementById('servicePaymentLatency');
const serviceEmailStatusEl = document.getElementById('serviceEmailStatus');
const serviceEmailQueueEl = document.getElementById('serviceEmailQueue');
const serviceFraudStatusEl = document.getElementById('serviceFraudStatus');
const serviceFraudLatencyEl = document.getElementById('serviceFraudLatency');
const geoDEEl = document.getElementById('geoDE');
const geoATEl = document.getElementById('geoAT');
const geoCHEl = document.getElementById('geoCH');
const geoNLEl = document.getElementById('geoNL');
const geoUSEl = document.getElementById('geoUS');
const deviceDesktopEl = document.getElementById('deviceDesktop');
const deviceMobileEl = document.getElementById('deviceMobile');
const deviceTabletEl = document.getElementById('deviceTablet');

const warningsEl = document.getElementById('warnings');
const chartEl = document.getElementById('chart');
const chartEmptyEl = document.getElementById('chartEmpty');
const logsEl = document.getElementById('logs');
const logsEmptyEl = document.getElementById('logsEmpty');
const topMessagesEl = document.getElementById('topMessages');
const topIpsEl = document.getElementById('topIps');
const prevBtn = document.getElementById('prevBtn');
const nextBtn = document.getElementById('nextBtn');

const lockdownToggle = document.getElementById('lockdownToggle');
const lockdownState = document.getElementById('lockdownState');
const firewallToggle = document.getElementById('firewallToggle');
const firewallState = document.getElementById('firewallState');

const ipInput = document.getElementById('ipInput');
const ruleType = document.getElementById('ruleType');
const addRuleBtn = document.getElementById('addRuleBtn');
const rulesEl = document.getElementById('rules');

const searchInput = document.getElementById('searchInput');
const searchBtn = document.getElementById('searchBtn');
const clearSearchBtn = document.getElementById('clearSearchBtn');

let offset = 0;
let lastRange = 7;
let refreshTimer = null;
let searchMode = false;

function setText(el, value) {
  if (!el) return;
  el.textContent = value;
}

function setSignal(el, state, tone) {
  if (!el) return;
  el.textContent = state;
  el.classList.remove('ok', 'warn', 'danger');
  if (tone) el.classList.add(tone);
}

function setPill(el, state) {
  if (!el) return;
  el.textContent = state.label;
  el.classList.remove('ok', 'warn', 'neutral');
  el.classList.add(state.tone || 'neutral');
}

async function fetchStatus() {
  const res = await fetch('/api/developer/status', { credentials: 'include' });
  const data = await res.json();
  const logged = data.loggedIn && data.mfaVerified;

  statusEl.textContent = logged ? 'Status: Zugriff gewaehrt' : 'Status: Gesperrt';
  mfaStateEl.textContent = data.mfaVerified ? 'aktiv' : 'inaktiv';
  sessionStateEl.textContent = data.loggedIn ? `angemeldet (${data.username || '-'})` : 'abgemeldet';

  document.getElementById('center').style.display = logged ? 'block' : 'none';
  document.getElementById('login').style.display = logged ? 'none' : 'grid';
  return logged;
}

async function login() {
  messageEl.textContent = '';
  const res = await fetch('/api/developer/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({
      username: usernameEl.value.trim(),
      password: passwordEl.value
    })
  });
  const data = await res.json();
  messageEl.textContent = data.message || data.error || 'Unbekannte Antwort';

  if (data.mfaRequired) {
    await fetch('/api/developer/request-otp', { method: 'POST', credentials: 'include' });
  }
}

async function verify2fa(token) {
  const res = await fetch('/api/developer/verify-2fa', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ token })
  });
  const data = await res.json();
  messageEl.textContent = data.message || data.error || 'Unbekannte Antwort';
  await refreshAll();
}

async function logout() {
  messageEl.textContent = '';
  await fetch('/api/developer/logout', { method: 'POST', credentials: 'include' });
  messageEl.textContent = 'Abgemeldet.';
  await refreshAll();
}

function formatTs(ts) {
  if (!ts) return '-';
  const d = new Date(ts);
  return d.toLocaleString('de-DE');
}

function renderWarnings(list) {
  warningsEl.innerHTML = '';
  if (!list.length) {
    warningsEl.innerHTML = '<li>Keine Warnungen in diesem Zeitraum.</li>';
    return;
  }
  list.forEach(w => {
    const count = w.count && w.count > 1 ? ` <span class="count">x${w.count}</span>` : '';
    const li = document.createElement('li');
    li.innerHTML = `<strong>${w.level.toUpperCase()}</strong> ${w.message}${count} <span class="muted">(${formatTs(w.ts)})</span>`;
    warningsEl.appendChild(li);
  });
}

function renderLogs(logs) {
  const view = viewSelect.value;
  logsEl.innerHTML = '';
  if (!logs.length) {
    logsEmptyEl.style.display = 'block';
    return;
  }
  logsEmptyEl.style.display = 'none';
  const lines = logs.map(l => {
    const meta = l.meta && Object.keys(l.meta).length ? JSON.stringify(l.meta) : '';
    const metaBlock = view === 'raw' && meta ? ` | ${meta}` : '';
    return `<div class="log-line"><span class="tag ${l.level}">${l.level}</span>${formatTs(l.ts)} ${l.message}${metaBlock}</div>`;
  }).join('');
  logsEl.innerHTML = lines;
}

function renderChart(rows, rangeDays) {
  chartEl.innerHTML = '';
  if (!rows.length) {
    chartEmptyEl.style.display = 'block';
    setText(chartPeakEl, '0');
    setText(chartAvgEl, '0');
    return;
  }
  chartEmptyEl.style.display = 'none';

  const map = new Map();
  rows.forEach(r => map.set(r.day, r));

  const points = [];
  for (let i = rangeDays - 1; i >= 0; i--) {
    const d = new Date();
    d.setHours(0, 0, 0, 0);
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    const row = map.get(key) || { errors: 0, warnings: 0, infos: 0 };
    points.push({
      day: key,
      errors: row.errors || 0,
      warnings: row.warnings || 0,
      infos: row.infos || 0
    });
  }

  const totals = points.map(p => p.errors + p.warnings + p.infos);
  const peak = Math.max(...totals);
  const avg = Math.round(totals.reduce((a, b) => a + b, 0) / points.length);
  setText(chartPeakEl, peak);
  setText(chartAvgEl, avg);

  const max = Math.max(1, ...points.map(p => p.errors + p.warnings + p.infos));
  const w = 720;
  const h = 220;
  const barW = Math.max(10, Math.floor(w / points.length) - 6);

  const bars = points.map((p, idx) => {
    const x = idx * (barW + 6) + 16;
    const warnH = Math.round((p.warnings / max) * (h - 30));
    const errH = Math.round((p.errors / max) * (h - 30));
    const infoH = Math.round((p.infos / max) * (h - 30));
    const yBase = h - 12;

    return `
      <g>
        <rect x="${x}" y="${yBase - infoH}" width="${barW}" height="${infoH}" fill="#0f62fe" opacity="0.35" />
        <rect x="${x}" y="${yBase - infoH - warnH}" width="${barW}" height="${warnH}" fill="#f59e0b" />
        <rect x="${x}" y="${yBase - infoH - warnH - errH}" width="${barW}" height="${errH}" fill="#dc2626" />
      </g>`;
  }).join('');

  chartEl.innerHTML = `
    <svg viewBox="0 0 ${w} ${h}" width="100%" height="${h}">
      <rect x="0" y="0" width="${w}" height="${h}" fill="#ffffff" />
      ${bars}
    </svg>`;
}

function renderList(target, items, emptyText, mapper) {
  target.innerHTML = '';
  if (!items.length) {
    target.innerHTML = `<li>${emptyText}</li>`;
    return;
  }
  items.forEach(i => {
    const li = document.createElement('li');
    li.innerHTML = mapper(i);
    target.appendChild(li);
  });
}

async function refreshSummary(days) {
  const res = await fetch(`/api/security/summary?days=${days}`, { credentials: 'include' });
  const data = await res.json();
  const total = data.totals.total || 0;
  const warnings = data.totals.warnings || 0;
  const errors = data.totals.errors || 0;
  totalCountEl.textContent = total;
  warnCountEl.textContent = warnings;
  errorCountEl.textContent = errors;
  lastErrorEl.textContent = data.lastErrorAt ? formatTs(data.lastErrorAt) : 'Keine';
  renderWarnings(data.highlights || []);

  const penalty = (errors * 2) + (warnings * 0.5) + Math.min(10, Math.floor(total / 200));
  const score = Math.max(35, Math.min(99, Math.round(100 - penalty)));
  setText(postureScoreEl, score);
  if (postureBarEl) postureBarEl.style.width = `${score}%`;
  setText(policyCoverageEl, `${Math.max(70, Math.min(99, 92 - warnings))}%`);
  setText(misconfigCountEl, Math.min(12, Math.round(warnings / 2)));
  setText(endpointDriftEl, Math.min(9, Math.round(errors / 2)));

  const threat = errors > 3 ? 'Hoch' : warnings > 6 ? 'Mittel' : 'Niedrig';
  setText(threatLevelEl, threat);
  setText(threatHintEl, `${errors} Errors, ${warnings} Warnungen`);

  if (postureLabelEl) {
    postureLabelEl.textContent = score > 85 ? 'Stabil' : score > 70 ? 'Beobachten' : 'Kritisch';
    postureLabelEl.classList.remove('ok', 'warn');
    postureLabelEl.classList.add(score > 85 ? 'ok' : 'warn');
  }

  const sessions = total > 0 ? Math.max(1, Math.min(48, Math.round(total / 15))) : 0;
  setText(activeSessionsEl, sessions);
}

async function refreshStats(days) {
  const res = await fetch(`/api/security/stats?days=${days}`, { credentials: 'include' });
  const data = await res.json();
  renderChart(data.rows || [], days);
}

async function refreshLogs(days, level, offsetVal) {
  const url = searchMode
    ? `/api/security/logs/search?days=${days}&level=${level}&q=${encodeURIComponent(searchInput.value)}&limit=50&offset=${offsetVal}`
    : `/api/security/logs?days=${days}&level=${level}&limit=50&offset=${offsetVal}`;
  const res = await fetch(url, { credentials: 'include' });
  const data = await res.json();
  renderLogs(data.logs || []);
}

async function refreshInsights(days) {
  const res = await fetch(`/api/security/insights?days=${days}`, { credentials: 'include' });
  const data = await res.json();

  renderList(
    topMessagesEl,
    data.topMessages || [],
    'Keine Events in diesem Zeitraum.',
    (i) => `<strong>${i.message}</strong> <span class="muted">(${i.count})</span>`
  );

  renderList(
    topIpsEl,
    data.topIps || [],
    'Keine IPs erfasst.',
    (i) => `<strong>${i.ip}</strong> <span class="muted">(${i.count})</span>`
  );

  failedLoginsEl.textContent = data.failedLogins || 0;
  otpFailuresEl.textContent = data.otpFailures || 0;
  adminActionsEl.textContent = data.adminActions || 0;

  const failedLogins = data.failedLogins || 0;
  const otpFailures = data.otpFailures || 0;
  const adminActions = data.adminActions || 0;
  setText(sessionDriftEl, Math.min(9, Math.round((failedLogins + otpFailures) / 2)));
  setText(geoShiftEl, Math.min(7, Math.round(failedLogins / 3)));
  setText(deviceShiftEl, Math.min(5, Math.round(otpFailures / 2)));

  if (credHygieneEl) {
    credHygieneEl.textContent = failedLogins > 4 ? 'Review' : 'OK';
    credHygieneEl.classList.remove('ok', 'warn');
    credHygieneEl.classList.add(failedLogins > 4 ? 'warn' : 'ok');
  }

  if (geoPolicyEl) geoPolicyEl.textContent = 'Aktiv';
  if (botShieldEl) botShieldEl.textContent = 'Aktiv';

  const messageBlob = (data.topMessages || [])
    .map(m => (m.message || '').toLowerCase())
    .join(' ');

  const hasKeyword = (keywords) => keywords.some(k => messageBlob.includes(k));
  const loginDetected = failedLogins > 0 || adminActions > 0 || hasKeyword(['login', 'signin', 'anmeldung']);
  const pageDetected = hasKeyword(['page', 'seite', 'view', 'visit', 'aufgerufen']) || messageBlob.length > 0;
  const checkoutDetected = hasKeyword(['checkout', 'zahlung', 'payment', 'kasse']);
  const adminDetected = adminActions > 0 || hasKeyword(['admin', 'console', 'backend']);
  const pdfDetected = hasKeyword(['pdf', 'export', 'download']);
  const apiDetected = hasKeyword(['api', 'webhook', 'integration']);

  setSignal(signalLoginEl, loginDetected ? 'erkannt' : 'keine Daten', loginDetected ? 'ok' : 'warn');
  setSignal(signalPageEl, pageDetected ? 'erkannt' : 'keine Daten', pageDetected ? 'ok' : 'warn');
  setSignal(signalCheckoutEl, checkoutDetected ? 'erkannt' : 'keine Daten', checkoutDetected ? 'warn' : 'ok');
  setSignal(signalAdminEl, adminDetected ? 'erkannt' : 'keine Daten', adminDetected ? 'ok' : 'warn');
  setSignal(signalPdfEl, pdfDetected ? 'erkannt' : 'keine Daten', pdfDetected ? 'ok' : 'warn');
  setSignal(signalApiEl, apiDetected ? 'erkannt' : 'keine Daten', apiDetected ? 'ok' : 'warn');
}

async function refreshMetrics(days) {
  const res = await fetch(`/api/security/metrics?days=${days}`, { credentials: 'include' });
  const data = await res.json();
  if (data.threat) {
    setText(threatLevelEl, data.threat.level);
    setText(threatHintEl, data.threat.hint);
  }
  if (data.posture) {
    setText(postureScoreEl, data.posture.score);
    if (postureBarEl) postureBarEl.style.width = `${data.posture.score}%`;
    setText(policyCoverageEl, `${data.posture.policyCoverage}%`);
    setText(misconfigCountEl, data.posture.misconfigAlerts);
    setText(endpointDriftEl, data.posture.endpointDrift);
    if (postureLabelEl) {
      postureLabelEl.textContent = data.posture.label;
      postureLabelEl.classList.remove('ok', 'warn');
      postureLabelEl.classList.add(data.posture.tone);
    }
  }
  if (data.sessions) {
    setText(activeSessionsEl, data.sessions.active);
    setText(uptimeSlaEl, `${data.sessions.uptime}%`);
  }
  if (data.chart) {
    setText(chartPeakEl, data.chart.peak);
    setText(chartAvgEl, data.chart.avg);
  }
  if (data.signals) {
    setSignal(signalLoginEl, data.signals.login.label, data.signals.login.tone);
    setSignal(signalPageEl, data.signals.page.label, data.signals.page.tone);
    setSignal(signalCheckoutEl, data.signals.checkout.label, data.signals.checkout.tone);
    setSignal(signalAdminEl, data.signals.admin.label, data.signals.admin.tone);
    setSignal(signalPdfEl, data.signals.pdf.label, data.signals.pdf.tone);
    setSignal(signalApiEl, data.signals.api.label, data.signals.api.tone);
  }
  if (data.behavior) {
    setText(sessionDriftEl, data.behavior.sessionDrift);
    setText(geoShiftEl, data.behavior.geoShift);
    setText(deviceShiftEl, data.behavior.deviceShift);
  }
  if (data.dataProtection) {
    setText(dlpRulesEl, data.dataProtection.dlpRules);
    setText(keyRotationEl, data.dataProtection.keyRotation);
    setText(vaultHealthEl, data.dataProtection.vaultHealth);
    setText(lastBackupEl, formatTs(data.dataProtection.lastBackup));
    setText(restoreTestEl, formatTs(data.dataProtection.restoreTest));
    setText(dbIntegrityEl, data.dataProtection.dbIntegrity);
  }
  if (data.services) {
    setPill(servicePaymentStatusEl, data.services.payment.status);
    setText(servicePaymentLatencyEl, `Latency ${data.services.payment.latency}ms`);
    setPill(serviceEmailStatusEl, data.services.email.status);
    setText(serviceEmailQueueEl, `Queue ${data.services.email.queue}`);
    setPill(serviceFraudStatusEl, data.services.fraud.status);
    setText(serviceFraudLatencyEl, `Status ${data.services.fraud.code}`);
  }
  if (data.geo) {
    setText(geoDEEl, `DE ${data.geo.DE}%`);
    setText(geoATEl, `AT ${data.geo.AT}%`);
    setText(geoCHEl, `CH ${data.geo.CH}%`);
    setText(geoNLEl, `NL ${data.geo.NL}%`);
    setText(geoUSEl, `US ${data.geo.US}%`);
  }
  if (data.devices) {
    setText(deviceDesktopEl, `${data.devices.desktop}%`);
    setText(deviceMobileEl, `${data.devices.mobile}%`);
    setText(deviceTabletEl, `${data.devices.tablet}%`);
  }
}

async function refreshLockdown() {
  const res = await fetch('/api/security/lockdown', { credentials: 'include' });
  const data = await res.json();
  lockdownToggle.checked = !!data.enabled;
  lockdownState.textContent = `Status: ${data.enabled ? 'aktiv' : 'inaktiv'}`;
}

async function setLockdown(enabled) {
  const res = await fetch('/api/security/lockdown', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ enabled })
  });
  const data = await res.json();
  lockdownToggle.checked = !!data.enabled;
  lockdownState.textContent = `Status: ${data.enabled ? 'aktiv' : 'inaktiv'}`;
}

async function refreshFirewall() {
  const res = await fetch('/api/security/firewall', { credentials: 'include' });
  const data = await res.json();
  firewallToggle.checked = !!data.enabled;
  firewallState.textContent = `Status: ${data.enabled ? 'aktiv' : 'inaktiv'}`;
}

async function setFirewall(enabled) {
  const res = await fetch('/api/security/firewall', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ enabled })
  });
  const data = await res.json();
  firewallToggle.checked = !!data.enabled;
  firewallState.textContent = `Status: ${data.enabled ? 'aktiv' : 'inaktiv'}`;
}

async function refreshRules() {
  const res = await fetch('/api/security/ip-rules', { credentials: 'include' });
  const data = await res.json();
  rulesEl.innerHTML = '';
  if (!data.length) {
    rulesEl.innerHTML = '<div class="muted">Keine Regeln vorhanden.</div>';
    return;
  }
  data.forEach(r => {
    const row = document.createElement('div');
    row.className = 'rule';
    row.innerHTML = `<div>${r.ip} <span>(${r.rule_type})</span></div><button class="ghost" data-id="${r.id}">Loeschen</button>`;
    rulesEl.appendChild(row);
  });
}

async function addRule() {
  const ip = ipInput.value.trim();
  const type = ruleType.value;
  if (!ip) return;
  await fetch('/api/security/ip-rules', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ ip, rule_type: type })
  });
  ipInput.value = '';
  refreshRules();
}

async function deleteRule(id) {
  await fetch(`/api/security/ip-rules/${id}`, {
    method: 'DELETE',
    credentials: 'include'
  });
  refreshRules();
}

async function refreshAll() {
  const logged = await fetchStatus();
  if (!logged) return;

  const days = parseInt(rangeSelect.value, 10);
  lastRange = days;
  const level = levelSelect.value;
  await refreshSummary(days);
  await refreshStats(days);
  await refreshInsights(days);
  await refreshMetrics(days);
  await refreshLogs(days, level, offset);
  await refreshLockdown();
  await refreshFirewall();
  await refreshRules();

  lastUpdateEl.textContent = new Date().toLocaleTimeString('de-DE');
}

function startAutoRefresh() {
  if (refreshTimer) clearInterval(refreshTimer);
  refreshTimer = setInterval(() => {
    refreshAll();
  }, 30000);
  refreshStateEl.textContent = '30s';
}

loginBtn.addEventListener('click', login);
logoutBtn.addEventListener('click', logout);
printBtn.addEventListener('click', () => window.print());
exportBtn.addEventListener('click', () => {
  const days = rangeSelect.value;
  const level = levelSelect.value;
  window.location.href = `/api/security/logs/export?days=${days}&level=${level}`;
});

lockdownToggle.addEventListener('change', (e) => {
  setLockdown(e.target.checked);
});

firewallToggle.addEventListener('change', (e) => {
  setFirewall(e.target.checked);
});

addRuleBtn.addEventListener('click', addRule);
rulesEl.addEventListener('click', (e) => {
  if (e.target && e.target.dataset && e.target.dataset.id) {
    deleteRule(e.target.dataset.id);
  }
});

searchBtn.addEventListener('click', () => {
  searchMode = true;
  offset = 0;
  refreshLogs(lastRange, levelSelect.value, offset);
});

clearSearchBtn.addEventListener('click', () => {
  searchMode = false;
  searchInput.value = '';
  offset = 0;
  refreshLogs(lastRange, levelSelect.value, offset);
});

rangeSelect.addEventListener('change', () => {
  offset = 0;
  refreshAll();
});

levelSelect.addEventListener('change', () => {
  offset = 0;
  refreshAll();
});

viewSelect.addEventListener('change', () => {
  refreshLogs(lastRange, levelSelect.value, offset);
});

prevBtn.addEventListener('click', () => {
  offset = Math.max(0, offset - 50);
  refreshLogs(lastRange, levelSelect.value, offset);
});

nextBtn.addEventListener('click', () => {
  offset += 50;
  refreshLogs(lastRange, levelSelect.value, offset);
});

// Auto-verify when 6 digits entered
if (tokenEl) {
  tokenEl.addEventListener('input', () => {
    const v = tokenEl.value.trim();
    if (v.length === 6) verify2fa(v);
  });
}

refreshAll();
startAutoRefresh();
