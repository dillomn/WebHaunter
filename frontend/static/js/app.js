/* ── WebHaunter SPA ──────────────────────────────────────────────────────── */

const API = '';
let currentUser = null;
let currentScanId = null;
let sseSource = null;

// ── Auth helpers ──────────────────────────────────────────────────────────────

function getToken() { return localStorage.getItem('gh_token'); }
function setToken(t) { localStorage.setItem('gh_token', t); }
function clearToken() { localStorage.removeItem('gh_token'); localStorage.removeItem('gh_user'); }

function getUser() {
  try { return JSON.parse(localStorage.getItem('gh_user')); } catch { return null; }
}
function setUser(u) { localStorage.setItem('gh_user', JSON.stringify(u)); }

async function apiFetch(path, options = {}) {
  const token = getToken();
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(API + path, { ...options, headers });
  if (res.status === 401) { clearToken(); renderAuth(); return null; }
  return res;
}

// ── Router ────────────────────────────────────────────────────────────────────

function route() {
  const token = getToken();
  if (!token) { renderAuth(); return; }
  currentUser = getUser();
  const hash = location.hash;
  if (hash.startsWith('#/scan/')) {
    const id = parseInt(hash.replace('#/scan/', ''));
    renderScanDetail(id);
  } else {
    renderDashboard();
  }
}

window.addEventListener('hashchange', route);
window.addEventListener('load', route);

// ── Render helpers ────────────────────────────────────────────────────────────

function app() { return document.getElementById('app'); }

function renderTopbar() {
  const user = getUser();
  return `
  <div class="topbar">
    <div class="logo" onclick="renderDashboard()">
      <img class="logo-img" src="/static/img/haunter.png" alt="">
      WEB HAUNTER
    </div>
    <div class="topbar-right">
      ${user ? `<div class="user-badge"><strong>${esc(user.username)}</strong></div>` : ''}
      ${user ? `<button class="btn btn-secondary btn-sm" onclick="logout()">Sign Out</button>` : ''}
    </div>
  </div>`;
}

function esc(str) {
  if (!str) return '';
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function logout() {
  clearToken();
  if (sseSource) { sseSource.close(); sseSource = null; }
  renderAuth();
}

// ── Auth pages ────────────────────────────────────────────────────────────────

function renderAuth(mode = 'login') {
  app().innerHTML = `
  <div class="auth-page">
    <div class="auth-card">
      <div class="auth-logo">
        <img class="auth-logo-img" src="/static/img/haunter.png" alt="WebHaunter">
        <div class="auth-logo-text">WEB HAUNTER</div>
      </div>
      <div class="auth-tagline">Vulnerability Scanner</div>
      <div id="auth-alert"></div>
      ${mode === 'login' ? loginForm() : registerForm()}
    </div>
  </div>`;
}

function loginForm() {
  return `
  <form id="login-form">
    <div class="form-group">
      <label>Username</label>
      <input type="text" id="login-user" placeholder="Enter username" required autocomplete="username">
    </div>
    <div class="form-group">
      <label>Password</label>
      <input type="password" id="login-pass" placeholder="Enter password" required autocomplete="current-password">
    </div>
    <button type="submit" class="btn btn-primary btn-full">Sign In</button>
  </form>
  <div class="auth-link">No account? <a onclick="renderAuth('register')">Create one</a></div>`;
}

function registerForm() {
  return `
  <form id="register-form">
    <div class="form-group">
      <label>Username</label>
      <input type="text" id="reg-user" placeholder="Choose a username" required>
    </div>
    <div class="form-group">
      <label>Email</label>
      <input type="email" id="reg-email" placeholder="your@email.com" required>
    </div>
    <div class="form-group">
      <label>Password</label>
      <input type="password" id="reg-pass" placeholder="Choose a password" required>
    </div>
    <button type="submit" class="btn btn-primary btn-full">Create Account</button>
  </form>
  <div class="auth-link">Have an account? <a onclick="renderAuth('login')">Sign in</a></div>`;
}

document.addEventListener('submit', async (e) => {
  const alertEl = document.getElementById('auth-alert');

  if (e.target.id === 'login-form') {
    e.preventDefault();
    const body = new URLSearchParams({
      username: document.getElementById('login-user').value,
      password: document.getElementById('login-pass').value,
    });
    const res = await fetch(API + '/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    if (res.ok) {
      const data = await res.json();
      setToken(data.access_token);
      setUser({ username: data.username });
      currentUser = { username: data.username };
      location.hash = '#/';
      renderDashboard();
    } else {
      const err = await res.json();
      if (alertEl) alertEl.innerHTML = `<div class="alert alert-error">${esc(err.detail)}</div>`;
    }
  }

  if (e.target.id === 'register-form') {
    e.preventDefault();
    const res = await apiFetch('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        username: document.getElementById('reg-user').value,
        email: document.getElementById('reg-email').value,
        password: document.getElementById('reg-pass').value,
      }),
    });
    if (res && res.ok) {
      const data = await res.json();
      setToken(data.access_token);
      setUser({ username: data.username });
      currentUser = { username: data.username };
      location.hash = '#/';
      renderDashboard();
    } else if (res) {
      const err = await res.json();
      if (alertEl) alertEl.innerHTML = `<div class="alert alert-error">${esc(err.detail)}</div>`;
    }
  }
});

// ── Dashboard ─────────────────────────────────────────────────────────────────

let dashTab = 'scans';

async function renderDashboard(tab) {
  if (tab) dashTab = tab;
  app().innerHTML = renderTopbar() + `
  <div class="main">
    <div class="page-header">
      <h1>Dashboard</h1>
      <div class="subtitle">Vulnerability assessment platform</div>
    </div>
    <div class="dash-tabs">
      <div class="dash-tab ${dashTab === 'scans' ? 'active' : ''}" onclick="renderDashboard('scans')">Scan History</div>
      <div class="dash-tab ${dashTab === 'schedules' ? 'active' : ''}" onclick="renderDashboard('schedules')">Schedules</div>
    </div>
    <div id="dash-content"><div style="text-align:center;padding:40px;"><div class="spinner"></div></div></div>
  </div>`;

  if (dashTab === 'schedules') {
    await renderSchedulesTab();
  } else {
    await renderScansTab();
  }
}

async function renderScansTab() {
  const content = document.getElementById('dash-content');
  content.innerHTML = `
  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
    <div id="scan-count" style="color:var(--text-dim); font-size:13px;"></div>
    <button class="btn btn-primary" onclick="renderNewScan()">+ New Scan</button>
  </div>
  <div id="scan-list"><div style="text-align:center;padding:40px;"><div class="spinner"></div></div></div>`;

  const res = await apiFetch('/api/scans');
  if (!res) return;
  const scans = await res.json();

  document.getElementById('scan-count').textContent = `${scans.length} scan${scans.length !== 1 ? 's' : ''}`;

  const listEl = document.getElementById('scan-list');
  if (!scans.length) {
    listEl.innerHTML = `
    <div class="empty-state">
      <p>No scans yet. Start your first assessment.</p>
      <br>
      <button class="btn btn-primary" onclick="renderNewScan()">+ New Scan</button>
    </div>`;
    return;
  }
  listEl.innerHTML = `<div class="scan-list">${scans.map(scanItem).join('')}</div>`;
}

async function renderSchedulesTab() {
  const content = document.getElementById('dash-content');
  content.innerHTML = `
  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
    <div style="color:var(--text-dim); font-size:13px;" id="sched-count"></div>
    <button class="btn btn-primary" onclick="renderNewScan(true)">+ New Schedule</button>
  </div>
  <div id="sched-list"><div style="text-align:center;padding:40px;"><div class="spinner"></div></div></div>`;

  const res = await apiFetch('/api/schedules');
  if (!res) return;
  const schedules = await res.json();

  document.getElementById('sched-count').textContent = `${schedules.length} schedule${schedules.length !== 1 ? 's' : ''}`;

  const listEl = document.getElementById('sched-list');
  if (!schedules.length) {
    listEl.innerHTML = `
    <div class="empty-state">
      <p>No schedules yet. Create a recurring scan.</p>
      <br>
      <button class="btn btn-primary" onclick="renderNewScan(true)">+ New Schedule</button>
    </div>`;
    return;
  }
  listEl.innerHTML = `<div class="scan-list">${schedules.map(scheduleItem).join('')}</div>`;
}

function scheduleItem(s) {
  const targets = s.targets || [];
  const targetText = targets.length === 1
    ? (targets[0].label || targets[0].host)
    : `${targets.length} targets`;
  const lastRun = s.last_run_at ? new Date(s.last_run_at).toLocaleString() : 'Never';
  const nextRun = s.next_run_at ? new Date(s.next_run_at).toLocaleString() : '—';
  const modules = s.modules.map(m => `<span class="tag">${esc(moduleLabel(m))}</span>`).join(' ');

  return `
  <div class="scan-item" style="cursor:default;">
    <div class="scan-item-left" style="flex:1;">
      <div class="scan-item-target">${esc(s.scan_name)}</div>
      <div class="scan-item-meta">${esc(targetText)} &nbsp;·&nbsp; ${esc(s.interval_label)} at ${esc(s.run_time || '00:00')} &nbsp;·&nbsp; ${modules}</div>
      <div class="scan-item-meta" style="margin-top:2px;">Last run: ${lastRun} &nbsp;·&nbsp; Next: ${nextRun}</div>
    </div>
    <div class="scan-item-right" style="gap:8px; flex-wrap:wrap;">
      <span class="badge ${s.enabled ? 'badge-completed' : 'badge-pending'}">${s.enabled ? 'Active' : 'Paused'}</span>
      <button class="btn btn-secondary btn-sm" onclick="runScheduleNow(${s.id})">Run Now</button>
      <button class="btn btn-secondary btn-sm" onclick="toggleSchedule(${s.id})">${s.enabled ? 'Pause' : 'Resume'}</button>
      <button class="btn btn-danger btn-sm" onclick="deleteSchedule(${s.id})">Delete</button>
    </div>
  </div>`;
}

async function runScheduleNow(id) {
  const res = await apiFetch(`/api/schedules/${id}/run`, { method: 'POST' });
  if (res && res.ok) {
    const data = await res.json();
    location.hash = `#/scan/${data.scan_id}`;
  }
}

async function toggleSchedule(id) {
  await apiFetch(`/api/schedules/${id}/toggle`, { method: 'PATCH' });
  renderDashboard('schedules');
}

async function deleteSchedule(id) {
  if (!confirm('Delete this schedule?')) return;
  await apiFetch(`/api/schedules/${id}`, { method: 'DELETE' });
  renderDashboard('schedules');
}

function scanItem(scan) {
  const date = scan.created_at ? new Date(scan.created_at).toLocaleString() : '';
  const modules = scan.modules.map(m => `<span class="tag">${esc(m)}</span>`).join(' ');
  return `
  <div class="scan-item" onclick="location.hash='#/scan/${scan.id}'">
    <div class="scan-item-left">
      <div class="scan-item-target">${esc(scan.scan_name || scan.target)}</div>
      <div class="scan-item-meta">${esc(scan.target)} &nbsp;·&nbsp; ${date} &nbsp;·&nbsp; ${modules}</div>
    </div>
    <div class="scan-item-right">
      <span class="badge badge-${scan.status}">${scan.status === 'running' ? '<span class="pulse-dot"></span> ' : ''}${scan.status}</span>
      <button class="btn btn-danger btn-sm" onclick="event.stopPropagation(); deleteScan(${scan.id})">Delete</button>
    </div>
  </div>`;
}

async function deleteScan(id) {
  if (!confirm('Delete this scan?')) return;
  await apiFetch(`/api/scans/${id}`, { method: 'DELETE' });
  renderDashboard();
}

// ── New Scan ──────────────────────────────────────────────────────────────────

let portPreset = 'top1000';
let scheduleMode = false;

function selectPortPreset(preset) {
  portPreset = preset;
  document.querySelectorAll('.preset-btn').forEach(b =>
    b.classList.toggle('active', b.dataset.preset === preset)
  );
  const row = document.getElementById('custom-port-row');
  if (row) row.classList.toggle('hidden', preset !== 'custom');
}

function parseCSVLine(line) {
  const fields = [];
  let cur = '', inQuote = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') { inQuote = !inQuote; }
    else if (ch === ',' && !inQuote) { fields.push(cur.trim()); cur = ''; }
    else { cur += ch; }
  }
  fields.push(cur.trim());
  return fields;
}

function looksLikeIP(s) {
  return /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(s.trim());
}

function importTargetsFromFile(input) {
  const file = input.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (e) => {
    const text = e.target.result;
    const isCSV = file.name.toLowerCase().endsWith('.csv') || (
      !file.name.toLowerCase().endsWith('.json') && text.trim().split('\n')[0].includes(',') && !text.trim().startsWith('{') && !text.trim().startsWith('[')
    );

    let lines = [];

    if (isCSV) {
      const rows = text.trim().split('\n');
      // Detect header row — skip if first row contains no IP-looking values
      const firstData = parseCSVLine(rows[0]);
      const startRow = firstData.every(f => !looksLikeIP(f)) ? 1 : 0;

      for (let i = startRow; i < rows.length; i++) {
        const cols = parseCSVLine(rows[i]);
        if (!cols.length) continue;
        const label = cols[0] || null;
        // Collect all IP-looking columns (skip label col)
        const ips = cols.slice(1).map(c => c.trim()).filter(c => looksLikeIP(c));
        if (!ips.length) continue;
        for (const ip of ips) {
          lines.push(label ? `${label.trim()} | ${ip}` : ip);
        }
      }

      if (!lines.length) {
        alert('No valid targets found in the CSV.\n\nExpected columns: Name, IP Address 1[, IP Address 2, ...]');
        input.value = '';
        return;
      }
    } else {
      try {
        let data = JSON.parse(text);

        if (data && typeof data === 'object' && !Array.isArray(data)) {
          const wrapKey = ['clients','targets','hosts','ips','data','items','records'].find(k => Array.isArray(data[k]));
          if (wrapKey) data = data[wrapKey];
        }

        if (Array.isArray(data)) {
          for (const entry of data) {
            if (typeof entry === 'string') {
              lines.push(entry.trim());
            } else if (typeof entry === 'object' && entry !== null) {
              const hostVal = entry.ip ?? entry.host ?? entry.address ?? entry.ip_address ?? entry.target ?? null;
              const labelVal = entry.name ?? entry.label ?? entry.client ?? entry.client_name ?? entry.hostname ?? null;
              if (hostVal) {
                lines.push(labelVal ? `${String(labelVal).trim()} | ${String(hostVal).trim()}` : String(hostVal).trim());
              }
            }
          }
        } else if (typeof data === 'object' && data !== null) {
          for (const [k, v] of Object.entries(data)) {
            if (typeof v === 'string') lines.push(`${k.trim()} | ${v.trim()}`);
          }
        }

        if (!lines.length) {
          alert('No valid targets found in the JSON file.\n\nExpected formats:\n• [{name, ip}, ...]\n• [{client, address}, ...]\n• {"Client A": "1.2.3.4", ...}');
          input.value = '';
          return;
        }
      } catch {
        alert('Failed to parse file. Make sure it is valid JSON or CSV.');
        input.value = '';
        return;
      }
    }

    const textarea = document.getElementById('scan-targets');
    if (textarea) textarea.value = lines.join('\n');
    input.value = '';
  };
  reader.readAsText(file);
}


function toggleScheduleMode(on) {
  scheduleMode = on;
  document.querySelectorAll('.mode-btn').forEach(b =>
    b.classList.toggle('active', b.dataset.mode === (on ? 'schedule' : 'once'))
  );
  const schedCard = document.getElementById('schedule-card');
  if (schedCard) schedCard.classList.toggle('hidden', !on);
  const btn = document.getElementById('launch-btn');
  if (btn) btn.textContent = on ? 'Create Schedule' : 'Launch Scan';
}

function renderNewScan(startAsSchedule = false) {
  portPreset = 'top1000';
  scheduleMode = startAsSchedule;
  app().innerHTML = renderTopbar() + `
  <div class="main">
    <div class="page-header">
      <h1>New Scan</h1>
      <div class="subtitle">Configure and launch a vulnerability assessment</div>
    </div>

    <div class="card">
      <div class="card-title"><span class="accent">01</span> Targets</div>
      <div class="form-group">
        <label>Scan Name (optional)</label>
        <input type="text" id="scan-name" placeholder="e.g. Client Corp External Assessment">
      </div>
      <div class="form-group">
        <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:6px;">
          <label style="margin-bottom:0;">Targets — one per line</label>
          <button type="button" class="btn btn-secondary btn-sm" onclick="document.getElementById('import-input').click()">Import JSON / CSV</button>
          <input type="file" id="import-input" accept=".json,.csv,application/json,text/csv" style="display:none" onchange="importTargetsFromFile(this)">
        </div>
        <textarea id="scan-targets" rows="6" placeholder="Client Corp | 192.168.1.1&#10;Head Office | 10.0.0.0/24&#10;203.0.113.42&#10;Remote Access Server | 203.0.113.99"></textarea>
        <div style="font-size:11px; color:var(--text-faint); margin-top:5px;">Format: <span style="color:var(--accent); font-family:monospace;">Label | host</span> — or import a JSON / CSV file.</div>
      </div>
    </div>

    <div class="card">
      <div class="card-title"><span class="accent">02</span> Port Scope</div>
      <div class="form-group">
        <label>Preset</label>
        <div class="port-presets">
          <button class="preset-btn" data-preset="top100" onclick="selectPortPreset('top100')">Top 100</button>
          <button class="preset-btn active" data-preset="top1000" onclick="selectPortPreset('top1000')">Top 1 000</button>
          <button class="preset-btn" data-preset="top10k" onclick="selectPortPreset('top10k')">Top 10 000</button>
          <button class="preset-btn" data-preset="allports" onclick="selectPortPreset('allports')">All Ports</button>
          <button class="preset-btn" data-preset="custom" onclick="selectPortPreset('custom')">Custom</button>
        </div>
        <div id="custom-port-row" class="hidden" style="margin-top:8px;">
          <input type="text" id="custom-ports" placeholder="e.g. 22,80,443,8080-9090,55000-56000">
          <div style="font-size:11px; color:var(--text-faint); margin-top:4px;">Comma-separated ports and ranges — nmap port syntax</div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-title"><span class="accent">03</span> Run Mode</div>
      <div class="port-presets" style="margin-bottom:0;">
        <button class="mode-btn preset-btn ${scheduleMode ? '' : 'active'}" data-mode="once" onclick="toggleScheduleMode(false)">Run Once</button>
        <button class="mode-btn preset-btn ${scheduleMode ? 'active' : ''}" data-mode="schedule" onclick="toggleScheduleMode(true)">Recurring Schedule</button>
      </div>
      <div id="schedule-card" class="${scheduleMode ? '' : 'hidden'}" style="margin-top:16px;">
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px;">
          <div class="form-group" style="margin-bottom:0;">
            <label>Repeat Every</label>
            <select id="schedule-interval">
              <option value="1h">Every hour</option>
              <option value="6h">Every 6 hours</option>
              <option value="12h">Every 12 hours</option>
              <option value="daily" selected>Daily</option>
              <option value="3d">Every 3 days</option>
              <option value="weekly">Weekly</option>
              <option value="monthly">Monthly</option>
            </select>
          </div>
          <div class="form-group" style="margin-bottom:0;">
            <label>Run At</label>
            <input type="time" id="schedule-time" value="02:00">
          </div>
        </div>
      </div>
    </div>

    <div id="launch-alert"></div>
    <div style="display:flex; gap:12px;">
      <button class="btn btn-secondary" onclick="renderDashboard()">Cancel</button>
      <button class="btn btn-primary" onclick="launchScan()" id="launch-btn">${scheduleMode ? 'Create Schedule' : 'Launch Scan'}</button>
    </div>
  </div>`;
}

function moduleCheckbox(id, name, desc, checked) {
  return `
  <div class="module-checkbox">
    <input type="checkbox" id="mod-${id}" value="${id}" ${checked ? 'checked' : ''}>
    <label for="mod-${id}">
      <span class="m-name">${name}</span>
      <span class="m-desc">${desc}</span>
    </label>
  </div>`;
}

async function launchScan() {
  const targetsRaw = document.getElementById('scan-targets').value;
  const targets = targetsRaw.split('\n')
    .map(line => line.trim())
    .filter(Boolean)
    .map(line => {
      const pipe = line.indexOf('|');
      if (pipe !== -1) {
        const label = line.slice(0, pipe).trim();
        const host  = line.slice(pipe + 1).trim();
        return host ? { host, label: label || undefined } : null;
      }
      return { host: line };
    })
    .filter(Boolean);
  const name = document.getElementById('scan-name').value.trim();
  const modules = ['nmap'];
  const alertEl = document.getElementById('launch-alert');

  if (!targets.length) { alertEl.innerHTML = '<div class="alert alert-error">Enter at least one target.</div>'; return; }

  let ports = portPreset;
  if (portPreset === 'custom') {
    ports = (document.getElementById('custom-ports')?.value || '').trim();
    if (!ports) { alertEl.innerHTML = '<div class="alert alert-error">Enter a custom port range.</div>'; return; }
  }

  const btn = document.getElementById('launch-btn');
  btn.disabled = true;

  const firstTarget = targets[0];
  const scanName = name || (targets.length === 1 ? (firstTarget.label || firstTarget.host) : `${targets.length} hosts`);

  if (scheduleMode) {
    const interval = document.getElementById('schedule-interval')?.value || 'daily';
    const run_time = document.getElementById('schedule-time')?.value || '00:00';
    btn.innerHTML = '<span class="spinner"></span> Creating...';
    const res = await apiFetch('/api/schedules', {
      method: 'POST',
      body: JSON.stringify({ targets, scan_name: scanName, modules, ports, interval, run_time }),
    });
    if (res && res.ok) {
      renderDashboard('schedules');
    } else if (res) {
      const err = await res.json();
      alertEl.innerHTML = `<div class="alert alert-error">${esc(err.detail)}</div>`;
      btn.disabled = false;
      btn.textContent = 'Create Schedule';
    }
  } else {
    btn.innerHTML = '<span class="spinner"></span> Launching...';
    const res = await apiFetch('/api/scans', {
      method: 'POST',
      body: JSON.stringify({ targets, scan_name: scanName, modules, ports }),
    });
    if (res && res.ok) {
      const data = await res.json();
      location.hash = `#/scan/${data.id}`;
    } else if (res) {
      const err = await res.json();
      alertEl.innerHTML = `<div class="alert alert-error">${esc(err.detail)}</div>`;
      btn.disabled = false;
      btn.textContent = 'Launch Scan';
    }
  }
}

// ── Scan Detail ───────────────────────────────────────────────────────────────

async function renderScanDetail(id) {
  currentScanId = id;
  if (sseSource) { sseSource.close(); sseSource = null; }

  const res = await apiFetch(`/api/scans/${id}`);
  if (!res) return;
  const scan = await res.json();

  app().innerHTML = renderTopbar() + `
  <div class="main">
    <div class="page-header">
      <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:12px;">
        <div>
          <div style="display:flex; align-items:center; gap:12px; margin-bottom:4px;">
            <button class="btn btn-secondary btn-sm" onclick="location.hash='#/'">← Back</button>
            <h1>${esc(scan.scan_name || scan.target)}</h1>
            <span class="badge badge-${scan.status}" id="scan-status-badge">${scan.status}</span>
          </div>
          <div class="subtitle" id="scan-subtitle">${renderTargetSubtitle(scan)} &nbsp;·&nbsp; Modules: ${scan.modules.join(', ')}${scan.ports && scan.ports !== 'top1000' ? ` &nbsp;·&nbsp; Ports: ${esc(scan.ports)}` : ''}</div>
        </div>
        <div style="display:flex; gap:8px;" id="action-btns">
          ${scan.status === 'completed' ? `<button class="btn btn-success btn-sm" onclick="exportPDF(${id})">Export PDF</button>` : ''}
        </div>
      </div>
    </div>

    <div id="progress-section" class="${scan.status === 'completed' || scan.status === 'failed' ? 'hidden' : ''}">
      <div class="card">
        <div class="card-title"><span class="pulse-dot"></span> Scan Progress</div>
        <div class="progress-list" id="progress-list">
          ${renderProgressList(scan.progress)}
        </div>
      </div>
    </div>

    <div id="results-section">
      ${renderResults(scan)}
    </div>
  </div>`;

  if (scan.status === 'running' || scan.status === 'pending') {
    startSSE(id);
  }
}

function renderProgressList(progress) {
  return Object.entries(progress).map(([module, info]) => {
    const pct = info.percent || 0;
    const cls = info.status === 'completed' ? 'done' : info.status === 'failed' ? 'failed' : '';
    return `
    <div class="progress-item" id="prog-${module}">
      <div class="progress-header">
        <span class="progress-label">${moduleLabel(module)}</span>
        <span class="progress-msg" id="prog-msg-${module}">${esc(info.message || '')}</span>
      </div>
      <div class="progress-bar-bg">
        <div class="progress-bar ${cls}" id="prog-bar-${module}" style="width:${pct}%"></div>
      </div>
    </div>`;
  }).join('');
}

function renderTargetSubtitle(scan) {
  const targets = scan.targets || [{ host: scan.target }];
  if (targets.length === 1) {
    const t = targets[0];
    return t.label ? `${esc(t.label)} — ${esc(t.host)}` : `Target: ${esc(t.host)}`;
  }
  const names = targets.slice(0, 3).map(t => esc(t.label || t.host)).join(', ');
  return `${targets.length} targets: ${names}${targets.length > 3 ? ` +${targets.length - 3} more` : ''}`;
}

function moduleLabel(m) {
  return { nmap: 'Nmap', gobuster_dir: 'Gobuster Dir', gobuster_dns: 'Gobuster DNS', ssl: 'SSL/TLS', headers: 'HTTP Headers' }[m] || m;
}

function startSSE(scanId) {
  const token = getToken();
  sseSource = new EventSource(`/api/scans/${scanId}/stream?token=${encodeURIComponent(token)}`);

  sseSource.onmessage = (e) => {
    const data = JSON.parse(e.data);
    updateProgress(data);

    if (data.status === 'completed' || data.status === 'failed') {
      sseSource.close();
      sseSource = null;
      // Full refresh of results
      apiFetch(`/api/scans/${scanId}`).then(r => r && r.json()).then(scan => {
        if (scan) {
          document.getElementById('progress-section')?.classList.add('hidden');
          document.getElementById('results-section').innerHTML = renderResults(scan);
          const badge = document.getElementById('scan-status-badge');
          if (badge) { badge.className = `badge badge-${scan.status}`; badge.textContent = scan.status; }
          const actions = document.getElementById('action-btns');
          if (actions && scan.status === 'completed') {
            actions.innerHTML = `<button class="btn btn-success btn-sm" onclick="exportPDF(${scanId})">Export PDF</button>`;
          }
        }
      });
    }
  };

  sseSource.onerror = () => { sseSource.close(); sseSource = null; };
}

function updateProgress(data) {
  const progress = data.progress || {};
  Object.entries(progress).forEach(([module, info]) => {
    const bar = document.getElementById(`prog-bar-${module}`);
    const msg = document.getElementById(`prog-msg-${module}`);
    if (bar) {
      bar.style.width = `${info.percent || 0}%`;
      bar.className = `progress-bar ${info.status === 'completed' ? 'done' : info.status === 'failed' ? 'failed' : ''}`;
    }
    if (msg) msg.textContent = info.message || '';
  });
}

// ── Results rendering ─────────────────────────────────────────────────────────

function renderResults(scan) {
  if (scan.status === 'pending') return `<div class="alert alert-info">Scan queued — waiting to start...</div>`;
  if (scan.status === 'failed') return `<div class="alert alert-error">Scan failed: ${esc(scan.error_message)}</div>`;

  const results = scan.results || {};
  const modules = scan.modules || [];
  const completedModules = modules.filter(m => results[m]);

  if (!completedModules.length) {
    return `<div class="card"><div class="empty-state"><div class="spinner"></div><p>Waiting for results...</p></div></div>`;
  }

  const tabs = completedModules.map(m =>
    `<div class="tab ${m === completedModules[0] ? 'active' : ''}" onclick="switchTab('${m}')" data-tab="${m}">${moduleLabel(m)}</div>`
  ).join('');

  const targets = scan.targets || [{ host: scan.target }];
  const panels = completedModules.map(m =>
    `<div class="tab-content ${m === completedModules[0] ? 'active' : ''}" id="tab-${m}">
      ${renderModuleResult(m, results[m], targets)}
    </div>`
  ).join('');

  return `<div class="tabs">${tabs}</div><div>${panels}</div>`;
}

function switchTab(module) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelector(`[data-tab="${module}"]`)?.classList.add('active');
  document.getElementById(`tab-${module}`)?.classList.add('active');
}

function renderModuleResult(module, result, targets = []) {
  if (!result) return '<div class="alert alert-info">No results yet.</div>';
  if (result.error) return `<div class="alert alert-error">${esc(result.error)}</div>`;
  if (result.skipped) return `<div class="alert alert-info"><strong>Skipped:</strong> ${esc(result.reason)}</div>`;

  switch (module) {
    case 'nmap': return renderNmap(result, targets);
    case 'gobuster_dir': return renderGobusterDir(result);
    case 'gobuster_dns': return renderGobusterDns(result);
    case 'ssl': return renderSSL(result);
    case 'headers': return renderHeaders(result);
    default: return `<pre style="color:var(--text-dim);font-size:11px;">${esc(JSON.stringify(result, null, 2))}</pre>`;
  }
}

// ── Nmap ──────────────────────────────────────────────────────────────────────

function renderNmap(result, targets = []) {
  if (!result.hosts || !result.hosts.length) return '<div class="alert alert-info">No hosts found.</div>';

  const labelMap = {};
  targets.forEach(t => { if (t && t.label && t.host) labelMap[t.host] = t.label; });

  return result.hosts.map(host => {
    const ip = host.addresses?.[0]?.addr || 'Unknown';
    const hostnames = host.hostnames?.join(', ') || '';
    const os = host.os_matches?.[0];
    const label = labelMap[ip];

    return `
    <div class="card">
      <div class="card-title">
        ${label ? `<span style="color:var(--accent)">${esc(label)}</span><span style="color:var(--text-faint); font-weight:400; font-size:13px;"> — </span>` : ''}
        ${esc(ip)} ${hostnames ? `<span style="color:var(--text-dim); font-weight:400;">— ${esc(hostnames)}</span>` : ''}
        <span class="badge badge-${host.status === 'up' ? 'completed' : 'failed'}">${host.status}</span>
      </div>
      ${os ? `<div style="font-size:12px; color:var(--text-dim); margin-bottom:12px;">OS: ${esc(os.name)} (${os.accuracy}% confidence)</div>` : ''}
      ${renderPortTable(host.ports || [], ip)}
    </div>`;
  }).join('');
}

function portLink(ip, port, protocol) {
  if (protocol !== 'tcp') return `<strong class="mono">${port}/${protocol}</strong>`;
  const scheme = (port === 443 || port === 8443) ? 'https' : 'http';
  const url = `${scheme}://${ip}:${port}`;
  return `<a href="${url}" target="_blank" rel="noopener noreferrer" class="mono port-link">${port}/${protocol}</a>`;
}

function renderPortTable(ports, ip = '') {
  if (!ports.length) return '<div style="color:var(--text-dim); font-size:13px;">No open ports found.</div>';

  const rows = ports.map(p => {
    const cves = p.cves || [];
    const maxSev = cves.reduce((best, c) => {
      const rank = { critical: 4, high: 3, medium: 2, low: 1 };
      return (rank[c.severity] || 0) > (rank[best] || 0) ? c.severity : best;
    }, 'none');

    return `
    <tr>
      <td><strong class="mono">${portLink(ip, p.port, p.protocol)}</strong></td>
      <td><span class="badge badge-${p.state === 'open' ? 'completed' : 'pending'}">${p.state}</span></td>
      <td>${esc(p.service || '—')}</td>
      <td>${esc([p.product, p.version].filter(Boolean).join(' ') || '—')}</td>
      <td>
        ${cves.length
          ? `<span class="badge badge-${maxSev}">${cves.length} CVE${cves.length !== 1 ? 's' : ''}</span><div style="margin-top:8px;">${cves.slice(0, 3).map(cveCard).join('')}</div>`
          : p.cve_skip_reason
            ? `<span class="badge badge-info" title="${esc(p.cve_skip_reason)}">CDN/Proxy</span><div style="font-size:11px;color:var(--text-faint);margin-top:4px;">CVE lookup skipped — CDN/WAF proxy detected</div>`
            : '<span style="color:var(--text-faint)">None found</span>'}
        ${p.scripts?.length ? `<div style="margin-top:6px;">${p.scripts.map(s => `<div class="tag" style="margin-bottom:4px;">${esc(s.id)}: ${esc(s.output.slice(0,120))}</div>`).join('')}</div>` : ''}
      </td>
    </tr>`;
  }).join('');

  return `
  <table class="data-table">
    <thead><tr><th>Port</th><th>State</th><th>Service</th><th>Version</th><th>Findings</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

function cveCard(cve) {
  return `
  <div class="cve-card ${esc(cve.severity)}" style="margin-bottom:6px;">
    <div class="cve-header">
      <span class="cve-id">${esc(cve.id)}</span>
      <div style="display:flex; align-items:center; gap:8px;">
        <span class="cve-score">CVSS ${cve.cvss_score ?? 'N/A'}</span>
        <span class="badge badge-${esc(cve.severity)}">${esc(cve.severity)}</span>
      </div>
    </div>
    <div class="cve-desc">${esc(cve.description)}</div>
    ${cve.references?.length ? `<div class="cve-refs">${cve.references.slice(0,2).map(r => `<a href="${esc(r)}" target="_blank">${esc(r.slice(0,60))}…</a>`).join(' ')}</div>` : ''}
  </div>`;
}

// ── Gobuster Dir ──────────────────────────────────────────────────────────────

function renderGobusterDir(result) {
  if (!result.paths?.length) return '<div class="alert alert-info">No paths discovered.</div>';

  const rows = result.paths.map(p => {
    const statusClass = p.status?.startsWith('2') ? 'badge-completed' : p.status?.startsWith('3') ? 'badge-info' : p.status?.startsWith('4') ? 'badge-medium' : 'badge-high';
    return `
    <tr>
      <td class="mono">${esc(p.path)}</td>
      <td><span class="badge ${statusClass}">${esc(p.status || '?')}</span></td>
      <td style="color:var(--text-dim);">${esc(p.size || '—')}</td>
    </tr>`;
  }).join('');

  return `
  ${result.note ? `<div class="alert alert-info" style="margin-bottom:12px;">${esc(result.note)}</div>` : ''}
  <div style="font-size:13px; color:var(--text-dim); margin-bottom:12px;">
    Found <strong style="color:var(--text)">${result.paths.length}</strong> paths
    using wordlist <span class="tag">${esc(result.wordlist || '')}</span>
  </div>
  <table class="data-table">
    <thead><tr><th>Path</th><th>Status</th><th>Size</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

// ── Gobuster DNS ──────────────────────────────────────────────────────────────

function renderGobusterDns(result) {
  if (!result.subdomains?.length) return '<div class="alert alert-info">No subdomains discovered.</div>';

  return `
  <div style="font-size:13px; color:var(--text-dim); margin-bottom:12px;">
    Found <strong style="color:var(--text)">${result.subdomains.length}</strong> subdomains for <strong style="color:var(--accent)">${esc(result.domain)}</strong>
  </div>
  <table class="data-table">
    <thead><tr><th>Subdomain</th></tr></thead>
    <tbody>${result.subdomains.map(s => `<tr><td class="mono">${esc(s)}</td></tr>`).join('')}</tbody>
  </table>`;
}

// ── SSL/TLS ───────────────────────────────────────────────────────────────────

function renderSSL(result) {
  const cert = result.certificate || {};
  const grade = result.grade || '?';
  const gradeClass = grade.startsWith('A') ? 'grade-A' : grade.startsWith('B') ? 'grade-B' : grade.startsWith('C') ? 'grade-C' : 'grade-F';

  return `
  <div class="ssl-grade-display">
    <div class="grade-circle ${gradeClass}">${grade}</div>
    <div>
      <div style="font-size:16px; font-weight:700;">${esc(result.host)}:${result.port}</div>
      <div style="font-size:12px; color:var(--text-dim);">SSL/TLS Security Grade</div>
    </div>
  </div>

  ${cert.error ? `<div class="alert alert-error">${esc(cert.error)}</div>` : cert.subject ? `
  <div class="card" style="margin-bottom:16px;">
    <div class="card-title">Certificate</div>
    <table class="data-table">
      <tbody>
        <tr><td style="width:160px; color:var(--text-dim);">Common Name</td><td>${esc(cert.subject?.commonName || '—')}</td></tr>
        <tr><td style="color:var(--text-dim);">Issuer</td><td>${esc(cert.issuer?.organizationName || '—')}</td></tr>
        <tr><td style="color:var(--text-dim);">Valid Until</td><td>
          ${esc(cert.not_after || '—')}
          ${cert.is_expired ? '<span class="badge badge-critical" style="margin-left:8px;">EXPIRED</span>' :
            cert.expiring_soon ? `<span class="badge badge-medium" style="margin-left:8px;">${cert.days_until_expiry}d remaining</span>` :
            cert.days_until_expiry != null ? `<span class="badge badge-low" style="margin-left:8px;">${cert.days_until_expiry}d remaining</span>` : ''}
        </td></tr>
        <tr><td style="color:var(--text-dim);">Protocol</td><td>${esc(cert.negotiated_protocol || '—')}</td></tr>
        <tr><td style="color:var(--text-dim);">Cipher</td><td class="mono">${esc(cert.negotiated_cipher || '—')}</td></tr>
        ${cert.subject_alt_names?.length ? `<tr><td style="color:var(--text-dim);">SANs</td><td class="mono" style="font-size:11px;">${esc(cert.subject_alt_names.join(', '))}</td></tr>` : ''}
      </tbody>
    </table>
  </div>` : ''}

  ${result.protocols?.length ? `
  <div class="card" style="margin-bottom:16px;">
    <div class="card-title">Protocol Support</div>
    <table class="data-table">
      <thead><tr><th>Protocol</th><th>Supported</th><th>Status</th></tr></thead>
      <tbody>
        ${result.protocols.map(p => `
        <tr>
          <td>${esc(p.protocol)}</td>
          <td>${p.supported ? '<span style="color:var(--success)">Yes</span>' : '<span style="color:var(--text-faint)">No</span>'}</td>
          <td>${p.supported && p.deprecated ? '<span class="badge badge-high">Deprecated — Disable</span>' : p.supported ? '<span class="badge badge-completed">OK</span>' : '<span class="badge badge-info">Not supported</span>'}</td>
        </tr>`).join('')}
      </tbody>
    </table>
  </div>` : ''}

  ${result.vulnerabilities?.length ? `
  <div class="card-title" style="margin-bottom:12px;">Findings</div>
  ${result.vulnerabilities.map(v => `
  <div class="cve-card ${esc(v.severity)}" style="margin-bottom:8px;">
    <div class="cve-header">
      <span class="badge badge-${esc(v.severity)}">${esc(v.severity)}</span>
      <span style="font-size:12px; color:var(--text-dim);">${esc(v.type?.replace(/_/g, ' '))}</span>
    </div>
    <div class="cve-desc" style="margin-top:6px;">${esc(v.description)}</div>
  </div>`).join('')}` : '<div class="alert alert-info" style="margin-top:12px;">No SSL/TLS vulnerabilities found.</div>'}`;
}

// ── Headers ───────────────────────────────────────────────────────────────────

function renderHeaders(result) {
  const score = result.score ?? 0;
  const scoreColor = score >= 80 ? 'var(--success)' : score >= 60 ? 'var(--info)' : score >= 40 ? 'var(--medium)' : 'var(--critical)';

  return `
  <div style="display:flex; align-items:center; gap:20px; margin-bottom:20px;">
    <div class="score-ring" style="background: ${scoreColor}22; border: 2px solid ${scoreColor}; color: ${scoreColor};">${score}</div>
    <div>
      <div style="font-size:16px; font-weight:700;">Security Header Score</div>
      <div style="font-size:12px; color:var(--text-dim); word-break:break-all; overflow-wrap:break-word;">${esc((result.final_url || '').length > 100 ? result.final_url.slice(0, 100) + '…' : result.final_url || '')}</div>
    </div>
  </div>

  ${result.findings?.length ? result.findings.map(f => `
  <div class="cve-card ${esc(f.severity)}" style="margin-bottom:8px;">
    <div class="cve-header" style="flex-wrap:wrap; gap:6px;">
      <div style="display:flex; gap:8px; align-items:center;">
        <span class="badge badge-${esc(f.severity)}">${esc(f.severity)}</span>
        <strong style="font-size:13px;">${esc(f.name)}</strong>
        ${f.value ? `<span class="tag mono">${esc(f.value.slice(0, 60))}</span>` : ''}
      </div>
    </div>
    <div class="cve-desc" style="margin-top:6px;">${esc(f.description)}</div>
    <div style="margin-top:8px; padding:6px 10px; background:rgba(16,185,129,0.08); border-radius:4px; font-size:12px; color:var(--success);">
      Recommendation: ${esc(f.recommendation)}
    </div>
  </div>`).join('') : '<div class="alert alert-info">All required security headers are present.</div>'}`;
}

// ── PDF Export ────────────────────────────────────────────────────────────────

async function exportPDF(scanId) {
  const btn = event?.target;
  if (btn) { btn.disabled = true; btn.textContent = 'Generating…'; }

  const token = getToken();
  const res = await fetch(`/api/scans/${scanId}/pdf`, {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (res.ok) {
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `webhaunter-scan-${scanId}.pdf`;
    a.click();
    URL.revokeObjectURL(url);
  } else {
    const err = await res.json().catch(() => ({ detail: 'PDF generation failed' }));
    alert(err.detail || 'PDF generation failed');
  }

  if (btn) { btn.disabled = false; btn.textContent = 'Export PDF'; }
}
