/**
 * src/ui/dashboardHtml.ts
 * ──────────────────────────────────────────────────────────────────────────────
 * Self-contained dark-mode glassmorphic Web Dashboard & Password Manager
 * for Native Secrets Vault. Served at GET /, GET /ui, and GET /passwords.
 */

export function renderVaultDashboardHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Native Secrets Vault — Password Manager &amp; Cryptographic Control Plane</title>
  <style>
    :root {
      --bg-0: #090d16;
      --bg-1: #111827;
      --bg-card: rgba(17, 24, 39, 0.88);
      --border: rgba(56, 189, 248, 0.24);
      --accent: #38bdf8;
      --emerald: #10b981;
      --amber: #f59e0b;
      --rose: #f43f5e;
      --text: #f8fafc;
      --muted: #94a3b8;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: radial-gradient(circle at top right, #1e293b 0%, #090d16 65%);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, ui-sans-serif, sans-serif;
      min-height: 100vh;
    }
    header {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      padding: 16px 24px;
      border-bottom: 1px solid var(--border);
      background: rgba(9, 13, 22, 0.92);
      backdrop-filter: blur(12px);
      position: sticky;
      top: 0;
      z-index: 20;
    }
    .brand { display: flex; align-items: center; gap: 12px; }
    .brand-icon {
      width: 40px; height: 40px; border-radius: 10px;
      background: linear-gradient(135deg, #0284c7, #10b981);
      display: flex; align-items: center; justify-content: center; font-size: 1.2rem;
    }
    .brand h1 { margin: 0; font-size: 1.15rem; letter-spacing: 0.3px; }
    .brand small { color: var(--muted); font-size: 0.78rem; }
    .token-bar { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
    input, textarea, select {
      background: rgba(15, 23, 42, 0.94);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 9px 12px;
      border-radius: 8px;
      font-family: inherit;
      font-size: 0.86rem;
      min-height: 40px;
    }
    button {
      background: linear-gradient(135deg, #0284c7, #0ea5e9);
      color: #fff;
      border: none;
      padding: 8px 14px;
      border-radius: 8px;
      font-weight: 700;
      cursor: pointer;
      font-size: 0.84rem;
      min-height: 40px;
    }
    button:hover { opacity: 0.92; }
    button.btn-ghost {
      background: rgba(56, 189, 248, 0.14);
      border: 1px solid var(--border);
      color: var(--text);
    }
    button.btn-danger {
      background: rgba(244, 63, 94, 0.18);
      border: 1px solid rgba(244, 63, 94, 0.45);
      color: #fda4af;
    }
    button.btn-sm {
      padding: 5px 10px;
      min-height: 36px;
      font-size: 0.78rem;
    }
    .container { max-width: 1400px; margin: 20px auto; padding: 0 20px 48px; }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
      gap: 14px;
      margin-bottom: 18px;
    }
    .stat-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 14px 16px;
    }
    .stat-label { color: var(--muted); font-size: 0.74rem; text-transform: uppercase; letter-spacing: 0.9px; }
    .stat-value { font-size: 1.45rem; font-weight: 800; margin-top: 5px; }
    .nav-tabs {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 18px;
      border-bottom: 1px solid rgba(255,255,255,0.08);
      padding-bottom: 12px;
    }
    .nav-tab {
      background: rgba(15, 23, 42, 0.85);
      border: 1px solid rgba(148, 163, 184, 0.25);
      color: var(--muted);
      padding: 9px 16px;
      border-radius: 10px;
      min-height: 44px;
    }
    .nav-tab.active {
      background: linear-gradient(135deg, rgba(2, 132, 199, 0.35), rgba(16, 185, 129, 0.25));
      border-color: var(--accent);
      color: var(--text);
    }
    .tab-pane { display: none; }
    .tab-pane.active { display: block; }
    .panel {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 18px;
      margin-bottom: 18px;
    }
    .panel h2 {
      margin: 0 0 12px;
      font-size: 1rem;
      color: var(--accent);
      border-bottom: 1px solid rgba(255,255,255,0.08);
      padding-bottom: 8px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 8px;
    }
    .main-grid { display: grid; grid-template-columns: 340px 1fr; gap: 20px; }
    @media (max-width: 900px) { .main-grid { grid-template-columns: 1fr; } }
    .toolbar {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
      margin-bottom: 14px;
    }
    .toolbar input[type="search"] { flex: 1 1 280px; }
    .filter-pills { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 14px; }
    .pill {
      background: rgba(15, 23, 42, 0.75);
      border: 1px solid rgba(148, 163, 184, 0.28);
      color: var(--muted);
      border-radius: 999px;
      padding: 6px 14px;
      font-size: 0.8rem;
      font-weight: 600;
      min-height: 36px;
    }
    .pill.active {
      background: rgba(56, 189, 248, 0.2);
      border-color: var(--accent);
      color: var(--text);
    }
    .auth-box {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 16px;
      margin-bottom: 14px;
    }
    .auth-card {
      background: rgba(15, 23, 42, 0.75);
      border: 1px solid rgba(56, 189, 248, 0.2);
      border-radius: 10px;
      padding: 14px;
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .auth-card h3 { margin: 0; font-size: 0.92rem; color: var(--text); }
    .path-item {
      padding: 10px 12px;
      border-radius: 8px;
      border: 1px solid rgba(255,255,255,0.06);
      margin-bottom: 8px;
      cursor: pointer;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .path-item:hover { border-color: var(--accent); background: rgba(56, 189, 248, 0.08); }
    .table-wrap { overflow-x: auto; }
    .kv-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    .kv-table th, .kv-table td {
      text-align: left;
      padding: 10px;
      border-bottom: 1px solid rgba(255,255,255,0.08);
      vertical-align: middle;
    }
    .kv-table th { color: var(--muted); font-size: 0.76rem; text-transform: uppercase; letter-spacing: 0.7px; }
    .kv-table td code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    .origin-link { color: #7dd3fc; text-decoration: none; font-weight: 600; word-break: break-all; }
    .origin-link:hover { text-decoration: underline; }
    .actions-cell { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
    .sforms-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(310px, 1fr));
      gap: 14px;
      margin-top: 14px;
    }
    .sform-card {
      background: rgba(15, 23, 42, 0.85);
      border: 1px solid rgba(56, 189, 248, 0.22);
      border-radius: 10px;
      padding: 14px;
    }
    .cat-badge {
      display: inline-block;
      font-size: 0.72rem;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: 999px;
      text-transform: uppercase;
      background: rgba(16, 185, 129, 0.16);
      color: #6ee7b7;
      border: 1px solid rgba(16, 185, 129, 0.35);
    }
    .cat-badge.card { background: rgba(245, 158, 11, 0.16); color: #fcd34d; border-color: rgba(245, 158, 11, 0.35); }
    .cat-badge.android { background: rgba(56, 189, 248, 0.16); color: #7dd3fc; border-color: rgba(56, 189, 248, 0.35); }
    .badge-ok { color: var(--emerald); font-weight: 700; }
    .badge-warn { color: var(--amber); font-weight: 700; }
    .badge-err { color: var(--rose); font-weight: 700; }
    .muted { color: var(--muted); font-size: 0.84rem; }
    .hidden { display: none !important; }
    .toast {
      position: fixed; bottom: 20px; right: 20px; z-index: 50;
      background: #0f172a; border: 1px solid var(--emerald); color: var(--text);
      padding: 10px 16px; border-radius: 10px; font-size: 0.85rem; box-shadow: 0 10px 25px rgba(0,0,0,0.45);
    }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <div class="brand-icon">🔐</div>
      <div>
        <h1>Native Secrets Vault <small>v1.0.0</small></h1>
        <small>Password Manager • AES-256-GCM Envelope Encryption • Shamir GF(256) • SHA-256 Audit Chain</small>
      </div>
    </div>
    <div class="token-bar">
      <input id="vaultToken" type="password" placeholder="X-Vault-Token (nsv_root_... or nsv_usr_...)" style="width: 270px;" />
      <button onclick="authenticateWithToken()">Unlock</button>
      <button id="btnClearAuth" class="btn-ghost hidden" onclick="clearSession()">Lock</button>
    </div>
  </header>

  <div class="container">
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">Seal Status</div>
        <div class="stat-value" id="stSeal">Checking...</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Saved Logins</div>
        <div class="stat-value" id="stLogins">-</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Synced Passkeys</div>
        <div class="stat-value" id="stPasskeys">-</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Cards / Apps / Docs</div>
        <div class="stat-value" id="stForms">-</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Secret Namespaces</div>
        <div class="stat-value" id="stPaths">-</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">SHA-256 Audit Chain</div>
        <div class="stat-value" id="stAudit">-</div>
      </div>
    </div>

    <div class="nav-tabs" role="tablist">
      <button class="nav-tab" data-tab="passwords" onclick="switchTab('passwords')">🔐 Password Manager</button>
      <button class="nav-tab" data-tab="kv" onclick="switchTab('kv')">🗄️ KV v2 Secrets</button>
      <button class="nav-tab" data-tab="ingest" onclick="switchTab('ingest')">⚡ Smart Ingest</button>
      <button class="nav-tab" data-tab="audit" onclick="switchTab('audit')">📜 Audit Ledger</button>
    </div>

    <!-- TAB 1: PASSWORD MANAGER -->
    <section id="tab-passwords" class="tab-pane">
      <div id="pmUnlockPanel" class="panel">
        <h2>Unlock Your Password Vault</h2>
        <div class="auth-box">
          <div class="auth-card">
            <h3>Sign In with Winome Account</h3>
            <input id="winomeUser" type="text" placeholder="Username or email (e.g. god)" autocomplete="username" />
            <input id="winomePass" type="password" placeholder="Winome account password" autocomplete="current-password" />
            <button onclick="loginWithWinome()">Sign In &amp; Load Passwords</button>
            <div id="winomeLoginMsg" class="muted"></div>
          </div>
          <div class="auth-card">
            <h3>Or Unlock with Vault Token</h3>
            <p class="muted" style="margin:0;">Paste your <code>nsv_usr_...</code> browser token or <code>nsv_root_...</code> operator token into the top bar and click <strong>Unlock</strong>.</p>
            <input id="manualUserId" type="text" placeholder="Optional Browser User ID override" />
            <button class="btn-ghost" onclick="loadPasswordsDashboard()">Load with Current Token</button>
          </div>
        </div>
      </div>

      <div id="pmMainPanel" class="panel hidden">
        <h2>
          <span>Saved Passwords, Cards &amp; Android Apps <small id="pmSessionMeta" class="muted"></small></span>
          <span style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
            <select id="pmUserSelect" class="hidden" onchange="onUserSelected()"></select>
            <button class="btn-ghost btn-sm" onclick="toggleAddLogin()">+ Add Login</button>
            <button class="btn-ghost btn-sm" onclick="exportFilteredCsv()">Export CSV</button>
            <button class="btn-ghost btn-sm" onclick="loadPasswordsDashboard()">Refresh</button>
          </span>
        </h2>

        <div id="addLoginForm" class="auth-card hidden" style="margin-bottom:14px;">
          <h3>Add / Update Login</h3>
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px;">
            <input id="newOrigin" type="url" placeholder="https://example.com" />
            <input id="newUser" type="text" placeholder="Username / Email" />
            <input id="newPass" type="password" placeholder="Password" />
            <input id="newTotp" type="text" placeholder="2FA TOTP Base32 (optional)" />
            <input id="newNotes" type="text" placeholder="Notes (optional)" />
          </div>
          <div style="display:flex;gap:8px;">
            <button onclick="saveNewLogin()">Save to Vault</button>
            <button class="btn-ghost" onclick="toggleAddLogin()">Cancel</button>
            <span id="addLoginMsg" class="muted"></span>
          </div>
        </div>

        <div class="toolbar">
          <input id="pmSearch" type="search" placeholder="Search domain, URL, username, email, app, card last 4, or notes (e.g. x.com, github, aetna)..." oninput="renderPasswordManager()" />
        </div>

        <div class="filter-pills">
          <button class="pill active" data-filter="all" onclick="setPmFilter('all')">All (<span id="cntAll">0</span>)</button>
          <button class="pill" data-filter="passkeys" onclick="setPmFilter('passkeys')">🔑 Passkeys (<span id="cntPasskeys">0</span>)</button>
          <button class="pill" data-filter="logins" onclick="setPmFilter('logins')">Website Logins (<span id="cntLogins">0</span>)</button>
          <button class="pill" data-filter="totp" onclick="setPmFilter('totp')">Has 2FA (<span id="cntTotp">0</span>)</button>
          <button class="pill" data-filter="android" onclick="setPmFilter('android')">Android Apps (<span id="cntAndroid">0</span>)</button>
          <button class="pill" data-filter="cards" onclick="setPmFilter('cards')">Payment Cards (<span id="cntCards">0</span>)</button>
          <button class="pill" data-filter="identity" onclick="setPmFilter('identity')">Addresses &amp; IDs (<span id="cntIdentity">0</span>)</button>
        </div>

        <div id="pmLoginsWrap" class="table-wrap">
          <table class="kv-table">
            <thead>
              <tr>
                <th>Site / Origin</th>
                <th>Username</th>
                <th>Password</th>
                <th>2FA / Notes</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody id="pmLoginsBody"></tbody>
          </table>
        </div>

        <div id="pmFormsWrap" class="sforms-grid"></div>
      </div>
    </section>

    <!-- TAB 2: KV V2 SECRETS -->
    <section id="tab-kv" class="tab-pane">
      <div class="main-grid">
        <div class="panel">
          <h2>KV v2 Namespaces</h2>
          <label class="muted" style="display:flex;align-items:center;gap:6px;margin-bottom:10px;cursor:pointer;">
            <input id="chkShowBrowserPaths" type="checkbox" style="min-height:auto;" onchange="loadPathsList()" />
            Show raw <code>winome/*/logins</code> entries
          </label>
          <div id="pathsList"><small class="muted">Unlock with X-Vault-Token (nsv_root_...) to list namespaces.</small></div>
        </div>
        <div class="panel">
          <h2 id="activePathTitle">Secret Inspector</h2>
          <div id="secretInspector">
            <p class="muted">Select a namespace on the left to inspect encrypted keys or reveal values.</p>
          </div>
        </div>
      </div>
    </section>

    <!-- TAB 3: SMART INGEST -->
    <section id="tab-ingest" class="tab-pane">
      <div class="panel">
        <h2>Smart Batch Ingest (CSV • .env • KV JSON • SHA-256 Dedup)</h2>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin-bottom:10px;">
          <select id="ingestFormat">
            <option value="auto">Auto-Detect Format</option>
            <option value="csv">Browser Passwords CSV (RFC-4180)</option>
            <option value="dotenv">Dotenv (.env Auto-Classified)</option>
            <option value="kv-bundle-json">KV v2 JSON Bundle</option>
            <option value="browser-logins-json">Winome Logins + Cards JSON</option>
          </select>
          <input id="ingestUserId" type="text" placeholder="User ID (default: active user)" />
          <input id="ingestTargetPath" type="text" placeholder="Override Path (optional, e.g. infra/r7000)" />
          <input id="ingestFile" type="file" accept=".csv,.env,.json,.txt" onchange="loadIngestFile(this)" />
        </div>
        <textarea id="ingestPayload" rows="6" style="width:100%;margin-bottom:10px;" placeholder="Paste CSV export, .env file, or JSON bundle here (unchanged secrets are skipped automatically with 0 disk writes)..."></textarea>
        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
          <button class="btn-ghost" onclick="runSmartIngest(true)">Dry-Run Preview</button>
          <button onclick="runSmartIngest(false)">Smart Ingest Now</button>
          <span id="ingestResult" class="muted"></span>
        </div>
      </div>
    </section>

    <!-- TAB 4: AUDIT LEDGER -->
    <section id="tab-audit" class="tab-pane">
      <div class="panel">
        <h2>Recent Hash-Chained Audit Events</h2>
        <div id="auditList"><small class="muted">Authenticate with an operator token (nsv_root_...) to view audit events.</small></div>
      </div>
    </section>
  </div>

  <div id="toast" class="toast hidden"></div>

  <script>
    var state = {
      activeTab: 'passwords',
      pmFilter: 'all',
      tokenInfo: null,
      activeUserId: '',
      logins: [],
      passkeys: [],
      sensitiveForms: [],
      revealedIds: new Set()
    };

    function escapeHtml(val) {
      return String(val === undefined || val === null ? '' : val)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    function safeHref(rawUrl) {
      var s = String(rawUrl || '').trim();
      if (/^https?:\\/\\//i.test(s)) return s;
      return '';
    }

    function showToast(msg) {
      var el = document.getElementById('toast');
      el.textContent = msg;
      el.classList.remove('hidden');
      clearTimeout(window.__toastTimer);
      window.__toastTimer = setTimeout(function() { el.classList.add('hidden'); }, 2200);
    }

    function copyText(text, label) {
      if (!navigator.clipboard) {
        showToast('Clipboard unavailable over insecure context');
        return;
      }
      navigator.clipboard.writeText(String(text || '')).then(function() {
        showToast((label || 'Value') + ' copied');
      });
    }

    function getToken() {
      var el = document.getElementById('vaultToken');
      if (el.value.trim()) {
        sessionStorage.setItem('nsv_token', el.value.trim());
      } else if (sessionStorage.getItem('nsv_token')) {
        el.value = sessionStorage.getItem('nsv_token');
      }
      var tok = el.value.trim();
      document.getElementById('btnClearAuth').classList.toggle('hidden', !tok);
      return tok;
    }

    function setToken(tok, preferredUserId) {
      document.getElementById('vaultToken').value = tok || '';
      if (tok) sessionStorage.setItem('nsv_token', tok);
      else sessionStorage.removeItem('nsv_token');
      if (preferredUserId) sessionStorage.setItem('nsv_uid', preferredUserId);
      document.getElementById('btnClearAuth').classList.toggle('hidden', !tok);
    }

    function clearSession() {
      setToken('', '');
      sessionStorage.removeItem('nsv_uid');
      state.tokenInfo = null;
      state.activeUserId = '';
      state.logins = [];
      state.passkeys = [];
      state.sensitiveForms = [];
      state.revealedIds.clear();
      document.getElementById('pmUnlockPanel').classList.remove('hidden');
      document.getElementById('pmMainPanel').classList.add('hidden');
      document.getElementById('stLogins').textContent = '-';
      document.getElementById('stPasskeys').textContent = '-';
      document.getElementById('stForms').textContent = '-';
      document.getElementById('pathsList').innerHTML = '<small class="muted">Locked. Unlock above.</small>';
      document.getElementById('auditList').innerHTML = '<small class="muted">Locked.</small>';
    }

    function switchTab(tabName) {
      state.activeTab = tabName;
      document.querySelectorAll('.nav-tab').forEach(function(btn) {
        btn.classList.toggle('active', btn.getAttribute('data-tab') === tabName);
      });
      document.querySelectorAll('.tab-pane').forEach(function(pane) {
        pane.classList.toggle('active', pane.id === 'tab-' + tabName);
      });
    }

    async function authenticateWithToken() {
      var tok = getToken();
      if (!tok) {
        showToast('Paste a Vault token or sign in with Winome');
        return;
      }
      await loadDashboard();
    }

    async function loginWithWinome() {
      var u = document.getElementById('winomeUser').value.trim();
      var p = document.getElementById('winomePass').value;
      var msgEl = document.getElementById('winomeLoginMsg');
      if (!u || !p) {
        msgEl.innerHTML = '<span class="badge-err">Enter username/email and password.</span>';
        return;
      }
      msgEl.textContent = 'Signing in...';
      try {
        var res = await fetch('/api/v1/browser/auth/winome-login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: u, password: p })
        });
        var body = await res.json();
        if (!res.ok || !body.token) {
          msgEl.innerHTML = '<span class="badge-err">' + escapeHtml((body.errors && body.errors[0]) || 'Sign-in failed') + '</span>';
          return;
        }
        document.getElementById('winomePass').value = '';
        setToken(body.token, body.userId);
        msgEl.innerHTML = '<span class="badge-ok">Signed in as ' + escapeHtml(body.displayName || body.username) + '</span>';
        switchTab('passwords');
        await loadDashboard();
      } catch (err) {
        msgEl.innerHTML = '<span class="badge-err">' + escapeHtml(err.message) + '</span>';
      }
    }

    async function loadDashboard() {
      try {
        var res = await fetch('/api/v1/status');
        var st = await res.json();
        document.getElementById('stSeal').innerHTML = st.sealed
          ? '<span class="badge-err">SEALED</span>'
          : '<span class="badge-ok">UNSEALED</span>';
        document.getElementById('stPaths').textContent = st.secretPathsTotal;
        document.getElementById('stAudit').innerHTML = st.auditChainValid
          ? '<span class="badge-ok">VERIFIED (' + st.auditEntriesTotal + ')</span>'
          : '<span class="badge-err">TAMPERED</span>';
      } catch (_) {}

      var token = getToken();
      if (!token) return;

      try {
        var selfRes = await fetch('/api/v1/tokens/self', { headers: { 'X-Vault-Token': token } });
        if (selfRes.ok) {
          state.tokenInfo = await selfRes.json();
        } else {
          state.tokenInfo = null;
        }
      } catch (_) {
        state.tokenInfo = null;
      }

      await loadPasswordsDashboard();
      await loadPathsList();
      await loadAuditList();
    }

    async function loadPasswordsDashboard() {
      var token = getToken();
      if (!token) return;

      var manualUid = document.getElementById('manualUserId').value.trim();
      var detectedIds = (state.tokenInfo && state.tokenInfo.browserUserIds) || [];
      var storedUid = sessionStorage.getItem('nsv_uid') || '';
      var uidList = detectedIds.slice();
      if (manualUid && uidList.indexOf(manualUid) === -1) uidList.unshift(manualUid);
      if (storedUid && uidList.indexOf(storedUid) === -1) uidList.unshift(storedUid);

      var sel = document.getElementById('pmUserSelect');
      sel.innerHTML = uidList.map(function(id) {
        return '<option value="' + escapeHtml(id) + '">' + escapeHtml(id) + '</option>';
      }).join('');
      sel.classList.toggle('hidden', uidList.length <= 1);

      var targetUid = manualUid || (sel.value || '') || storedUid || uidList[0] || '';
      if (!targetUid) {
        document.getElementById('pmUnlockPanel').classList.remove('hidden');
        document.getElementById('pmMainPanel').classList.add('hidden');
        return;
      }
      state.activeUserId = targetUid;
      sel.value = targetUid;
      document.getElementById('ingestUserId').placeholder = 'User ID (default: ' + targetUid + ')';

      var [loginsRes, passkeysRes, formsRes] = await Promise.all([
        fetch('/api/v1/browser/' + encodeURIComponent(targetUid) + '/logins', { headers: { Authorization: 'Bearer ' + token } }),
        fetch('/api/v1/browser/' + encodeURIComponent(targetUid) + '/passkeys', { headers: { Authorization: 'Bearer ' + token } }),
        fetch('/api/v1/browser/' + encodeURIComponent(targetUid) + '/sensitive-forms', { headers: { Authorization: 'Bearer ' + token } })
      ]);

      if (!loginsRes.ok) {
        var errBody = await loginsRes.json().catch(function() { return {}; });
        document.getElementById('winomeLoginMsg').innerHTML = '<span class="badge-err">' + escapeHtml((errBody.errors && errBody.errors[0]) || 'Unauthorized') + '</span>';
        return;
      }

      var loginsData = await loginsRes.json();
      var passkeysData = passkeysRes.ok ? await passkeysRes.json() : { passkeys: [] };
      var formsData = formsRes.ok ? await formsRes.json() : { entries: [] };
      state.logins = Array.isArray(loginsData.logins) ? loginsData.logins : [];
      state.passkeys = Array.isArray(passkeysData.passkeys) ? passkeysData.passkeys : [];
      state.sensitiveForms = Array.isArray(formsData.entries) ? formsData.entries : [];

      document.getElementById('pmUnlockPanel').classList.add('hidden');
      document.getElementById('pmMainPanel').classList.remove('hidden');
      document.getElementById('pmSessionMeta').textContent = '• User ' + targetUid;
      document.getElementById('stLogins').textContent = state.logins.length;
      document.getElementById('stPasskeys').textContent = state.passkeys.length;
      document.getElementById('stForms').textContent = state.sensitiveForms.length;

      updateFilterCounts();
      renderPasswordManager();
    }

    function onUserSelected() {
      var uid = document.getElementById('pmUserSelect').value;
      sessionStorage.setItem('nsv_uid', uid);
      document.getElementById('manualUserId').value = '';
      loadPasswordsDashboard();
    }

    function setPmFilter(filterName) {
      state.pmFilter = filterName;
      document.querySelectorAll('.pill').forEach(function(p) {
        p.classList.toggle('active', p.getAttribute('data-filter') === filterName);
      });
      renderPasswordManager();
    }

    function isAndroidEntry(f) {
      return f && f.category === 'secret_field' && f.fields && f.fields.kind === 'android_app_login';
    }

    function updateFilterCounts() {
      var lCount = state.logins.length;
      var pkCount = state.passkeys.length;
      var totpCount = state.logins.filter(function(l) { return Boolean(l.hasTotp || l.totpSecret); }).length;
      var androidCount = state.sensitiveForms.filter(isAndroidEntry).length;
      var cardCount = state.sensitiveForms.filter(function(f) { return f.category === 'payment_card'; }).length;
      var idCount = state.sensitiveForms.filter(function(f) { return f.category === 'identity_document' || (f.category === 'secret_field' && !isAndroidEntry(f)); }).length;
      document.getElementById('cntAll').textContent = lCount + pkCount + state.sensitiveForms.length;
      document.getElementById('cntPasskeys').textContent = pkCount;
      document.getElementById('cntLogins').textContent = lCount;
      document.getElementById('cntTotp').textContent = totpCount;
      document.getElementById('cntAndroid').textContent = androidCount;
      document.getElementById('cntCards').textContent = cardCount;
      document.getElementById('cntIdentity').textContent = idCount;
    }

    function renderPasswordManager() {
      var q = document.getElementById('pmSearch').value.trim().toLowerCase();
      var f = state.pmFilter;

      var showLogins = f === 'all' || f === 'logins' || f === 'totp';
      var showPasskeys = f === 'all' || f === 'passkeys';
      var showForms = f === 'all' || f === 'android' || f === 'cards' || f === 'identity';

      var filteredPasskeys = !showPasskeys ? [] : state.passkeys.filter(function(pk) {
        if (!q) return true;
        var hay = [pk.rpId, pk.rpName, pk.origin, pk.userName, pk.userDisplayName, pk.credentialId].join(' ').toLowerCase();
        return hay.indexOf(q) !== -1;
      });

      var filteredLogins = !showLogins ? [] : state.logins.filter(function(l) {
        if (f === 'totp' && !l.hasTotp && !l.totpSecret) return false;
        if (!q) return true;
        var hay = [l.origin, l.signonRealm, l.username, l.notes, (l.urls || []).join(' ')].join(' ').toLowerCase();
        return hay.indexOf(q) !== -1;
      });

      var filteredForms = !showForms ? [] : state.sensitiveForms.filter(function(sf) {
        if (f === 'android' && !isAndroidEntry(sf)) return false;
        if (f === 'cards' && sf.category !== 'payment_card') return false;
        if (f === 'identity' && !(sf.category === 'identity_document' || (sf.category === 'secret_field' && !isAndroidEntry(sf)))) return false;
        if (!q) return true;
        var fieldVals = Object.keys(sf.fields || {}).map(function(k) { return k + ':' + sf.fields[k]; }).join(' ');
        var hay = [sf.label, sf.category, (sf.origins || []).join(' '), fieldVals].join(' ').toLowerCase();
        return hay.indexOf(q) !== -1;
      });

      document.getElementById('pmLoginsWrap').classList.toggle('hidden', filteredLogins.length === 0);
      var tbody = document.getElementById('pmLoginsBody');
      tbody.innerHTML = '';

      filteredLogins.slice(0, 500).forEach(function(login) {
        var tr = document.createElement('tr');
        var isRev = state.revealedIds.has(login.id);
        var url = safeHref(login.origin) || safeHref((login.urls || [])[0]);

        var tdOrigin = document.createElement('td');
        if (url) {
          var a = document.createElement('a');
          a.href = url;
          a.target = '_blank';
          a.rel = 'noopener noreferrer';
          a.className = 'origin-link';
          a.textContent = login.origin;
          tdOrigin.appendChild(a);
        } else {
          tdOrigin.textContent = login.origin || '';
        }

        var tdUser = document.createElement('td');
        var userSpan = document.createElement('span');
        userSpan.className = 'mono';
        userSpan.textContent = login.username || '(none)';
        tdUser.appendChild(userSpan);

        var tdPass = document.createElement('td');
        var passCode = document.createElement('code');
        passCode.textContent = isRev ? (login.password || '') : '••••••••••••';
        tdPass.appendChild(passCode);

        var tdMeta = document.createElement('td');
        if (login.totpSecret || login.hasTotp) {
          var totpBtn = document.createElement('button');
          totpBtn.className = 'btn-ghost btn-sm';
          totpBtn.textContent = login.totpCode ? ('2FA: ' + login.totpCode + ' (' + (login.totpRemainingSeconds || 30) + 's)') : 'Get 2FA';
          totpBtn.onclick = function() {
            refreshTotp(login, totpBtn);
          };
          tdMeta.appendChild(totpBtn);
        }
        if (login.notes) {
          var noteDiv = document.createElement('div');
          noteDiv.className = 'muted';
          noteDiv.style.marginTop = '4px';
          noteDiv.textContent = login.notes.slice(0, 90);
          tdMeta.appendChild(noteDiv);
        }

        var tdAct = document.createElement('td');
        tdAct.className = 'actions-cell';

        var btnCopyUser = document.createElement('button');
        btnCopyUser.className = 'btn-ghost btn-sm';
        btnCopyUser.textContent = 'Copy User';
        btnCopyUser.onclick = function() { copyText(login.username || '', 'Username'); };

        var btnRev = document.createElement('button');
        btnRev.className = 'btn-ghost btn-sm';
        btnRev.textContent = isRev ? 'Hide' : 'Show';
        btnRev.onclick = function() {
          if (state.revealedIds.has(login.id)) state.revealedIds.delete(login.id);
          else state.revealedIds.add(login.id);
          renderPasswordManager();
        };

        var btnCopyPw = document.createElement('button');
        btnCopyPw.className = 'btn-sm';
        btnCopyPw.textContent = 'Copy Pass';
        btnCopyPw.onclick = function() { copyText(login.password || '', 'Password'); };

        var btnDel = document.createElement('button');
        btnDel.className = 'btn-danger btn-sm';
        btnDel.textContent = 'Delete';
        btnDel.onclick = function() { deleteLoginItem(login); };

        tdAct.appendChild(btnCopyUser);
        tdAct.appendChild(btnRev);
        tdAct.appendChild(btnCopyPw);
        tdAct.appendChild(btnDel);

        tr.appendChild(tdOrigin);
        tr.appendChild(tdUser);
        tr.appendChild(tdPass);
        tr.appendChild(tdMeta);
        tr.appendChild(tdAct);
        tbody.appendChild(tr);
      });

      var formsWrap = document.getElementById('pmFormsWrap');
      formsWrap.innerHTML = '';

      filteredPasskeys.forEach(function(pk) {
        var card = document.createElement('div');
        card.className = 'sform-card';
        var head = document.createElement('div');
        head.style.cssText = 'display:flex;justify-content:space-between;align-items:flex-start;gap:8px;margin-bottom:8px;';
        var titleWrap = document.createElement('div');
        var badge = document.createElement('span');
        badge.className = 'cat-badge';
        badge.textContent = '🔑 Passkey • ' + (pk.alg === -8 ? 'Ed25519' : 'ES256 P-256');
        var hTitle = document.createElement('div');
        hTitle.style.cssText = 'font-weight:700;margin-top:6px;';
        hTitle.textContent = (pk.userName || pk.userDisplayName || 'Passkey') + ' @ ' + pk.rpId;
        titleWrap.appendChild(badge);
        titleWrap.appendChild(hTitle);

        var delBtn = document.createElement('button');
        delBtn.className = 'btn-danger btn-sm';
        delBtn.textContent = 'Delete';
        delBtn.onclick = function() { deletePasskeyItem(pk); };
        head.appendChild(titleWrap);
        head.appendChild(delBtn);
        card.appendChild(head);

        var metaRows = [
          ['RP ID', pk.rpId],
          ['Account', pk.userDisplayName && pk.userDisplayName !== pk.userName ? pk.userName + ' (' + pk.userDisplayName + ')' : pk.userName],
          ['Credential ID', String(pk.credentialId || '').slice(0, 22) + '…'],
          ['Vault Sync', 'Multi-Workstation (BE+BS • Private Key Non-Exportable)'],
          ['Sign-Ins', String(pk.usageCount || 0) + ' • Last used ' + String(pk.lastUsedAt || pk.createdAt || '').slice(0, 19).replace('T', ' ')]
        ];
        metaRows.forEach(function(pair) {
          var row = document.createElement('div');
          row.style.cssText = 'display:flex;justify-content:space-between;align-items:center;gap:8px;padding:5px 0;border-top:1px solid rgba(255,255,255,0.06);font-size:0.82rem;';
          var left = document.createElement('span');
          left.className = 'muted';
          left.textContent = pair[0];
          var right = document.createElement('code');
          right.textContent = pair[1] || '-';
          row.appendChild(left);
          row.appendChild(right);
          card.appendChild(row);
        });
        formsWrap.appendChild(card);
      });
      filteredForms.forEach(function(sf) {
        var card = document.createElement('div');
        card.className = 'sform-card';

        var head = document.createElement('div');
        head.style.cssText = 'display:flex;justify-content:space-between;align-items:flex-start;gap:8px;margin-bottom:8px;';
        var titleWrap = document.createElement('div');
        var badge = document.createElement('span');
        badge.className = 'cat-badge ' + (sf.category === 'payment_card' ? 'card' : isAndroidEntry(sf) ? 'android' : '');
        badge.textContent = sf.category === 'payment_card' ? 'Payment Card' : isAndroidEntry(sf) ? 'Android App' : 'Address / ID';
        var hTitle = document.createElement('div');
        hTitle.style.cssText = 'font-weight:700;margin-top:6px;';
        hTitle.textContent = sf.label || sf.id;
        titleWrap.appendChild(badge);
        titleWrap.appendChild(hTitle);

        var delBtn = document.createElement('button');
        delBtn.className = 'btn-danger btn-sm';
        delBtn.textContent = 'Delete';
        delBtn.onclick = function() { deleteSensitiveFormItem(sf); };
        head.appendChild(titleWrap);
        head.appendChild(delBtn);
        card.appendChild(head);

        Object.keys(sf.fields || {}).forEach(function(fk) {
          var val = String(sf.fields[fk] || '');
          if (!val) return;
          var isSecretField = /password|cardnumber|cvv|secret|totp/i.test(fk);
          var fKey = sf.id + ':' + fk;
          var rev = state.revealedIds.has(fKey);

          var row = document.createElement('div');
          row.style.cssText = 'display:flex;justify-content:space-between;align-items:center;gap:8px;padding:5px 0;border-top:1px solid rgba(255,255,255,0.06);';
          var left = document.createElement('div');
          left.style.cssText = 'min-width:0;overflow-wrap:anywhere;';
          var kSpan = document.createElement('span');
          kSpan.className = 'muted';
          kSpan.textContent = fk + ': ';
          var vCode = document.createElement('code');
          vCode.textContent = isSecretField && !rev ? '••••••••' : val;
          left.appendChild(kSpan);
          left.appendChild(vCode);

          var btns = document.createElement('div');
          btns.style.cssText = 'display:flex;gap:4px;flex-shrink:0;';
          if (isSecretField) {
            var rBtn = document.createElement('button');
            rBtn.className = 'btn-ghost btn-sm';
            rBtn.textContent = rev ? 'Hide' : 'Show';
            rBtn.onclick = function() {
              if (state.revealedIds.has(fKey)) state.revealedIds.delete(fKey);
              else state.revealedIds.add(fKey);
              renderPasswordManager();
            };
            btns.appendChild(rBtn);
          }
          var cBtn = document.createElement('button');
          cBtn.className = 'btn-ghost btn-sm';
          cBtn.textContent = 'Copy';
          cBtn.onclick = function() { copyText(val, fk); };
          btns.appendChild(cBtn);

          row.appendChild(left);
          row.appendChild(btns);
          card.appendChild(row);
        });

        formsWrap.appendChild(card);
      });

      if (filteredLogins.length === 0 && filteredPasskeys.length === 0 && filteredForms.length === 0) {
        var empty = document.createElement('p');
        empty.className = 'muted';
        empty.textContent = 'No matching credentials found.';
        formsWrap.appendChild(empty);
      }
    }

    async function refreshTotp(login, btn) {
      var token = getToken();
      if (!token || !login.totpSecret) return;
      try {
        var r = await fetch('/api/v1/browser/' + encodeURIComponent(state.activeUserId) + '/totp/generate', {
          method: 'POST',
          headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
          body: JSON.stringify({ secret: login.totpSecret })
        });
        if (r.ok) {
          var d = await r.json();
          login.totpCode = d.code;
          login.totpRemainingSeconds = d.remainingSeconds;
          btn.textContent = '2FA: ' + d.code + ' (' + d.remainingSeconds + 's)';
          copyText(d.code, '2FA Code');
        }
      } catch (_) {}
    }

    function toggleAddLogin() {
      document.getElementById('addLoginForm').classList.toggle('hidden');
    }

    async function saveNewLogin() {
      var token = getToken();
      var msg = document.getElementById('addLoginMsg');
      var payload = {
        origin: document.getElementById('newOrigin').value.trim(),
        username: document.getElementById('newUser').value.trim(),
        password: document.getElementById('newPass').value,
        totpSecret: document.getElementById('newTotp').value.trim() || undefined,
        notes: document.getElementById('newNotes').value.trim() || undefined
      };
      if (!payload.origin || !payload.password) {
        msg.innerHTML = '<span class="badge-err">Origin and password are required.</span>';
        return;
      }
      var r = await fetch('/api/v1/browser/' + encodeURIComponent(state.activeUserId) + '/logins', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      var d = await r.json();
      if (!r.ok) {
        msg.innerHTML = '<span class="badge-err">' + escapeHtml((d.errors && d.errors[0]) || 'Save failed') + '</span>';
        return;
      }
      document.getElementById('newPass').value = '';
      document.getElementById('newTotp').value = '';
      showToast('Login saved to encrypted Vault');
      toggleAddLogin();
      await loadPasswordsDashboard();
    }

    async function deleteLoginItem(login) {
      if (!confirm('Cryptographically delete saved login for ' + login.origin + ' (' + (login.username || 'no user') + ')?')) return;
      var token = getToken();
      var r = await fetch('/api/v1/browser/' + encodeURIComponent(state.activeUserId) + '/logins/' + encodeURIComponent(login.id), {
        method: 'DELETE',
        headers: { Authorization: 'Bearer ' + token }
      });
      if (r.ok) {
        showToast('Login deleted');
        await loadPasswordsDashboard();
      }
    }

    async function deleteSensitiveFormItem(sf) {
      if (!confirm('Cryptographically delete "' + (sf.label || sf.id) + '"?')) return;
      var token = getToken();
      var r = await fetch('/api/v1/browser/' + encodeURIComponent(state.activeUserId) + '/sensitive-forms/' + encodeURIComponent(sf.id), {
        method: 'DELETE',
        headers: { Authorization: 'Bearer ' + token }
      });
      if (r.ok) {
        showToast('Item deleted');
        await loadPasswordsDashboard();
      }
    }

    async function deletePasskeyItem(pk) {
      if (!confirm('Cryptographically delete Vault passkey for ' + pk.rpId + ' (' + (pk.userName || pk.id) + ')?')) return;
      var token = getToken();
      var r = await fetch('/api/v1/browser/' + encodeURIComponent(state.activeUserId) + '/passkeys/' + encodeURIComponent(pk.id), {
        method: 'DELETE',
        headers: { Authorization: 'Bearer ' + token }
      });
      if (r.ok) {
        showToast('Passkey deleted');
        await loadPasswordsDashboard();
      }
    }

    function exportFilteredCsv() {
      var q = document.getElementById('pmSearch').value.trim().toLowerCase();
      var rows = state.logins.filter(function(l) {
        if (!q) return true;
        var hay = [l.origin, l.signonRealm, l.username, l.notes, (l.urls || []).join(' ')].join(' ').toLowerCase();
        return hay.indexOf(q) !== -1;
      });
      function escCsv(s) {
        return '"' + String(s || '').replace(/"/g, '""') + '"';
      }
      var lines = ['name,url,username,password,note'];
      rows.forEach(function(l) {
        lines.push([l.origin, (l.urls && l.urls[0]) || l.origin, l.username || '', l.password || '', l.notes || ''].map(escCsv).join(','));
      });
      var blob = new Blob([lines.join('\\n') + '\\n'], { type: 'text/csv;charset=utf-8' });
      var a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'vault-passwords.csv';
      a.click();
    }

    async function loadPathsList() {
      var token = getToken();
      if (!token) return;
      var pRes = await fetch('/api/v1/paths', { headers: { 'X-Vault-Token': token } });
      if (!pRes.ok) {
        document.getElementById('pathsList').innerHTML = '<small class="muted">KV namespace listing requires operator scope.</small>';
        return;
      }
      var pData = await pRes.json();
      var showBrowser = document.getElementById('chkShowBrowserPaths').checked;
      var list = (pData.paths || []).filter(function(item) {
        return showBrowser || !/^winome\\/[^/]+\\/(logins|sensitive-forms|passkeys)\\//.test(item.path);
      });
      var listEl = document.getElementById('pathsList');
      listEl.innerHTML = '';
      if (list.length === 0) {
        listEl.innerHTML = '<small class="muted">No KV paths in scope.</small>';
        return;
      }
      list.forEach(function(item) {
        var row = document.createElement('div');
        row.className = 'path-item';
        row.innerHTML = '<div><strong>' + escapeHtml(item.path) + '</strong><br/><small class="muted">v' + item.currentVersion + ' • ' + item.keyCount + ' keys</small></div><span style="color:var(--accent)">→</span>';
        row.onclick = function() { inspectPath(item.path); };
        listEl.appendChild(row);
      });
    }

    async function inspectPath(secretPath) {
      var token = getToken();
      var res = await fetch('/v1/secret/data/' + secretPath, { headers: { 'X-Vault-Token': token } });
      if (!res.ok) return;
      var body = await res.json();
      var data = (body.data && body.data.data) || {};
      var meta = (body.data && body.data.metadata) || {};

      document.getElementById('activePathTitle').textContent = 'Namespace: secret/' + secretPath + ' (v' + meta.version + ')';
      var wrap = document.getElementById('secretInspector');
      wrap.innerHTML = '<p class="muted">Click any masked value below to reveal decrypted plaintext.</p>';
      var tbl = document.createElement('table');
      tbl.className = 'kv-table';
      tbl.innerHTML = '<thead><tr><th>Key</th><th>Decrypted Value (Click to Reveal)</th></tr></thead><tbody></tbody>';
      var tbody = tbl.querySelector('tbody');
      Object.keys(data).sort().forEach(function(k) {
        var v = String(data[k]);
        var masked = v.length > 8 ? v.slice(0, 4) + '••••••••' + v.slice(-4) : '••••••••';
        var tr = document.createElement('tr');
        var tdK = document.createElement('td');
        tdK.innerHTML = '<strong><code>' + escapeHtml(k) + '</code></strong>';
        var tdV = document.createElement('td');
        var code = document.createElement('code');
        code.style.cursor = 'pointer';
        code.title = 'Click to reveal';
        code.textContent = masked;
        code.onclick = function() {
          code.textContent = code.textContent === masked ? v : masked;
        };
        tdV.appendChild(code);
        tr.appendChild(tdK);
        tr.appendChild(tdV);
        tbody.appendChild(tr);
      });
      wrap.appendChild(tbl);
    }

    async function loadAuditList() {
      var token = getToken();
      if (!token) return;
      var aRes = await fetch('/api/v1/audit', { headers: { 'X-Vault-Token': token } });
      if (!aRes.ok) {
        document.getElementById('auditList').innerHTML = '<small class="muted">Audit inspection requires operator scope.</small>';
        return;
      }
      var aData = await aRes.json();
      var rows = (aData.entries || []).slice(0, 25).map(function(e) {
        return '<tr><td>#' + e.index + '</td><td>' + escapeHtml(e.timestamp) + '</td><td>' + escapeHtml(e.actor) +
          '</td><td><code>' + escapeHtml(e.action) + '</code></td><td><code>' + escapeHtml(e.path) +
          '</code></td><td>' + escapeHtml(e.status) + '</td><td><code>' + escapeHtml(String(e.hash || '').slice(0, 12)) + '…</code></td></tr>';
      }).join('');
      document.getElementById('auditList').innerHTML = '<div class="table-wrap"><table class="kv-table"><thead><tr><th>#</th><th>Time</th><th>Actor</th><th>Action</th><th>Path</th><th>Status</th><th>SHA-256</th></tr></thead><tbody>' + rows + '</tbody></table></div>';
    }

    function loadIngestFile(input) {
      var file = input && input.files && input.files[0];
      if (!file) return;
      var reader = new FileReader();
      reader.onload = function(ev) {
        document.getElementById('ingestPayload').value = String(ev.target.result || '');
      };
      reader.readAsText(file);
    }

    async function runSmartIngest(dryRun) {
      var token = getToken();
      var resEl = document.getElementById('ingestResult');
      if (!token) {
        resEl.innerHTML = '<span class="badge-err">Authenticate first.</span>';
        return;
      }
      var payloadText = document.getElementById('ingestPayload').value;
      if (!payloadText.trim()) {
        resEl.innerHTML = '<span class="badge-warn">Paste or choose a file to ingest.</span>';
        return;
      }
      resEl.textContent = dryRun ? 'Running dry-run...' : 'Ingesting...';
      var resp = await fetch('/api/v1/ingest/smart', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Vault-Token': token },
        body: JSON.stringify({
          format: document.getElementById('ingestFormat').value,
          userId: document.getElementById('ingestUserId').value.trim() || state.activeUserId || undefined,
          targetPath: document.getElementById('ingestTargetPath').value.trim() || undefined,
          dryRun: Boolean(dryRun),
          payload: payloadText
        })
      });
      var out = await resp.json();
      if (!resp.ok) {
        resEl.innerHTML = '<span class="badge-err">' + escapeHtml((out.errors && out.errors[0]) || 'Ingest failed') + '</span>';
        return;
      }
      resEl.innerHTML = '<span class="badge-ok">[' + escapeHtml(out.detectedFormat) + (out.dryRun ? ' DRY-RUN' : '') + ']</span> ' +
        'Mutated: <strong>' + out.mutated + '</strong> • Skipped unchanged: <strong>' + out.skippedUnchanged + '</strong> • Rejected: ' + out.rejected +
        ' • Paths: <code>' + escapeHtml((out.targetPaths || []).join(', ')) + '</code>';
      if (!dryRun) loadDashboard();
    }

    switchTab('passwords');
    loadDashboard();
  </script>
</body>
</html>`;
}
