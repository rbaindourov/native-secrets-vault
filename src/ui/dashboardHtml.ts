/**
 * src/ui/dashboardHtml.ts
 * ──────────────────────────────────────────────────────────────────────────────
 * Self-contained dark-mode glassmorphic Web Dashboard for Native Secrets Vault.
 * Served at GET /ui (and GET /).
 */

export function renderVaultDashboardHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Native Secrets Vault — Cryptographic Control Plane</title>
  <style>
    :root {
      --bg-0: #090d16;
      --bg-1: #111827;
      --bg-card: rgba(17, 24, 39, 0.85);
      --border: rgba(56, 189, 248, 0.22);
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
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, monospace;
      min-height: 100vh;
    }
    header {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      padding: 18px 28px;
      border-bottom: 1px solid var(--border);
      background: rgba(9, 13, 22, 0.9);
      backdrop-filter: blur(12px);
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .brand-icon {
      width: 38px;
      height: 38px;
      border-radius: 10px;
      background: linear-gradient(135deg, #0284c7, #10b981);
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 900;
      font-size: 1.1rem;
    }
    .brand h1 {
      margin: 0;
      font-size: 1.2rem;
      letter-spacing: 0.5px;
    }
    .brand small {
      color: var(--muted);
      font-size: 0.78rem;
    }
    .token-bar {
      display: flex;
      gap: 8px;
      align-items: center;
    }
    input, textarea, select {
      background: rgba(15, 23, 42, 0.9);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 8px 12px;
      border-radius: 8px;
      font-family: inherit;
      font-size: 0.85rem;
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
    }
    button:hover { opacity: 0.92; }
    .container {
      max-width: 1360px;
      margin: 24px auto;
      padding: 0 24px;
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .stat-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px 18px;
    }
    .stat-label {
      color: var(--muted);
      font-size: 0.76rem;
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    .stat-value {
      font-size: 1.55rem;
      font-weight: 800;
      margin-top: 6px;
    }
    .main-grid {
      display: grid;
      grid-template-columns: 340px 1fr;
      gap: 20px;
    }
    @media (max-width: 900px) {
      .main-grid { grid-template-columns: 1fr; }
    }
    .panel {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 18px;
    }
    .panel h2 {
      margin: 0 0 14px;
      font-size: 1rem;
      color: var(--accent);
      border-bottom: 1px solid rgba(255,255,255,0.08);
      padding-bottom: 8px;
    }
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
    .path-item:hover {
      border-color: var(--accent);
      background: rgba(56, 189, 248, 0.08);
    }
    .kv-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
    }
    .kv-table th, .kv-table td {
      text-align: left;
      padding: 9px 10px;
      border-bottom: 1px solid rgba(255,255,255,0.07);
    }
    .badge-ok { color: var(--emerald); font-weight: 700; }
    .badge-warn { color: var(--amber); font-weight: 700; }
    .badge-err { color: var(--rose); font-weight: 700; }
    pre {
      background: #05080f;
      padding: 12px;
      border-radius: 8px;
      overflow-x: auto;
      font-size: 0.8rem;
      border: 1px solid rgba(255,255,255,0.08);
    }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <div class="brand-icon">🔒</div>
      <div>
        <h1>Native Secrets Vault <small>v1.0.0 (MIT Open Source)</small></h1>
        <small>AES-256-GCM Envelope Encryption • Shamir GF(256) • KV v2 Compatible • SHA-256 Audit Chain</small>
      </div>
    </div>
    <div class="token-bar">
      <input id="vaultToken" type="password" placeholder="X-Vault-Token (nsv_root_...)" style="width: 260px;" />
      <button onclick="loadDashboard()">Authenticate &amp; Refresh</button>
    </div>
  </header>

  <div class="container">
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">Seal Status</div>
        <div class="stat-value" id="stSeal">Checking...</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Secret Namespaces</div>
        <div class="stat-value" id="stPaths">-</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Encrypted Keys / Versions</div>
        <div class="stat-value" id="stKeys">-</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">SHA-256 Audit Chain</div>
        <div class="stat-value" id="stAudit">-</div>
      </div>
    </div>

    <div class="main-grid">
      <div class="panel">
        <h2>KV v2 Secret Namespaces</h2>
        <div id="pathsList"><small style="color:var(--muted)">Enter X-Vault-Token above to list namespaces.</small></div>
      </div>

      <div class="panel">
        <h2 id="activePathTitle">Secret Inspector &amp; Audit Ledger</h2>
        <div id="secretInspector">
          <p style="color:var(--muted);font-size:0.9rem;">Select a namespace on the left after authenticating to inspect encrypted keys, version history, or export lossless <code>.env</code> bundles.</p>
        </div>
        <h2 style="margin-top:24px;">Recent Hash-Chained Audit Events</h2>
        <div id="auditList"><small style="color:var(--muted)">Authenticate to view tamper-evident audit trail.</small></div>
      </div>
    </div>
  </div>

  <script>
    function getToken() {
      var el = document.getElementById('vaultToken');
      if (el.value) {
        sessionStorage.setItem('nsv_token', el.value);
      } else if (sessionStorage.getItem('nsv_token')) {
        el.value = sessionStorage.getItem('nsv_token');
      }
      return el.value.trim();
    }

    async function loadDashboard() {
      var token = getToken();
      var res = await fetch('/api/v1/status');
      var st = await res.json();

      document.getElementById('stSeal').innerHTML = st.sealed
        ? '<span class="badge-err">SEALED</span>'
        : '<span class="badge-ok">UNSEALED (ACTIVE)</span>';
      document.getElementById('stPaths').textContent = st.secretPathsTotal;
      document.getElementById('stKeys').textContent = st.secretKeysTotal + ' keys (' + st.secretVersionsTotal + ' v)';
      document.getElementById('stAudit').innerHTML = st.auditChainValid
        ? '<span class="badge-ok">VERIFIED (' + st.auditEntriesTotal + ')</span>'
        : '<span class="badge-err">TAMPERED</span>';

      if (!token) return;

      var pRes = await fetch('/api/v1/paths', { headers: { 'X-Vault-Token': token } });
      if (pRes.ok) {
        var pData = await pRes.json();
        var html = (pData.paths || []).map(function(item) {
          return '<div class="path-item" onclick="inspectPath(\\'' + item.path + '\\')">' +
            '<div><strong>' + item.path + '</strong><br/><small style="color:var(--muted)">v' + item.currentVersion + ' • ' + item.keyCount + ' keys</small></div>' +
            '<span style="color:var(--accent)">→</span></div>';
        }).join('');
        document.getElementById('pathsList').innerHTML = html || '<small>No paths stored yet.</small>';
      }

      var aRes = await fetch('/api/v1/audit', { headers: { 'X-Vault-Token': token } });
      if (aRes.ok) {
        var aData = await aRes.json();
        var rows = (aData.entries || []).slice(0, 12).map(function(e) {
          return '<tr><td>#' + e.index + '</td><td>' + e.timestamp + '</td><td>' + e.actor + '</td><td><code>' + e.action + '</code></td><td><code>' + e.path + '</code></td><td>' + e.status + '</td><td><code>' + e.hash.slice(0, 12) + '…</code></td></tr>';
        }).join('');
        document.getElementById('auditList').innerHTML = '<table class="kv-table"><thead><tr><th>#</th><th>Time</th><th>Actor</th><th>Action</th><th>Path</th><th>Status</th><th>SHA-256</th></tr></thead><tbody>' + rows + '</tbody></table>';
      }
    }

    async function inspectPath(secretPath) {
      var token = getToken();
      var res = await fetch('/v1/secret/data/' + secretPath, { headers: { 'X-Vault-Token': token } });
      if (!res.ok) return;
      var body = await res.json();
      var data = (body.data && body.data.data) || {};
      var meta = (body.data && body.data.metadata) || {};

      document.getElementById('activePathTitle').textContent = 'Namespace: secret/' + secretPath + ' (v' + meta.version + ')';
      var rows = Object.keys(data).sort().map(function(k) {
        var v = String(data[k]);
        var masked = v.length > 8 ? v.slice(0, 4) + '••••••••' + v.slice(-4) : '••••••••';
        return '<tr><td><strong><code>' + k + '</code></strong></td><td><code data-full="' + encodeURIComponent(v) + '" onclick="this.textContent=decodeURIComponent(this.getAttribute(\\'data-full\\'))" title="Click to reveal">' + masked + '</code></td></tr>';
      }).join('');
      document.getElementById('secretInspector').innerHTML =
        '<p><small style="color:var(--muted)">Click any masked value below to reveal its decrypted plaintext.</small></p>' +
        '<table class="kv-table"><thead><tr><th>Key</th><th>Decrypted Value (Click to Reveal)</th></tr></thead><tbody>' + rows + '</tbody></table>';
    }

    loadDashboard();
  </script>
</body>
</html>`;
}
