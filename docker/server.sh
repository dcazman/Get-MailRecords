'use strict';

const express  = require('express');
const { execFile } = require('child_process');
const path     = require('path');
const app      = express();
const PORT     = 7777;
const GMR_PATH = path.join(__dirname, 'gmr.ps1');

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ── Favicon ───────────────────────────────────────────────────────────────────
app.get('/favicon.svg', (req, res) => {
  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'public, max-age=86400');
  const svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">' +
    '<rect width="32" height="32" rx="6" fill="#3d6b1f"/>' +
    '<text x="50%" y="54%" font-family="monospace" font-weight="bold" font-size="14" ' +
    'fill="white" text-anchor="middle" dominant-baseline="middle">G</text>' +
    '</svg>';
  res.send(svg);
});

// ── Input form ────────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(inputFormHtml());
});

// ── Query endpoint ────────────────────────────────────────────────────────────
app.post('/query', (req, res) => {
  const {
    domain, selector, server, rectype,
    sub, justsub, doexport, exportfmt
  } = req.body;

  console.log(JSON.stringify({ ts: new Date().toISOString(), domain: (domain || '').trim(), rectype: rectype || 'ALL', server: server || '8.8.8.8' }));

  if (!domain || !domain.trim()) {
    return res.status(400).send(errorHtml('Please provide a domain.'));
  }

  // Build pwsh args
  const args = [
    '-NoProfile', '-NonInteractive', '-File', GMR_PATH,
    '-Domain', domain.trim()
  ];

  if (server && server.trim())   args.push('-Server',     server.trim());
  if (selector && selector.trim()) args.push('-Selector', selector.trim());
  if (rectype)                   args.push('-RecordType', rectype);
  if (sub === '1')               args.push('-Sub');
  if (justsub === '1')           args.push('-JustSub');

  // Always get JSON output from pwsh
  // We append ConvertTo-Json via -Command after dot-sourcing the file
  const psCommand = `
    . '${GMR_PATH}'
    $result = Get-MailRecords ${buildPsParams(req.body)}
    $result | ConvertTo-Json -Depth 10 -Compress
  `;

  execFile('pwsh', ['-NoProfile', '-NonInteractive', '-Command', psCommand], {
    timeout: 30000,
    maxBuffer: 1024 * 1024 * 5
  }, (err, stdout, stderr) => {
    if (err) {
      console.error('pwsh error:', stderr || err.message);
      return res.status(500).send(errorHtml(`DNS query failed: ${stderr || err.message}`));
    }

    let results;
    try {
      // Strip any Write-Host / Write-Warning lines that may precede or follow the JSON.
      // PowerShell's Write-Host can bleed into stdout when spawned as a subprocess.
      // The JSON payload will be the first line that starts with '[' or '{'.
      const jsonLine = stdout.split('\n').map(l => l.trim()).find(l => l.startsWith('[') || l.startsWith('{'));
      if (!jsonLine) throw new Error('No JSON found in pwsh output');
      const raw = JSON.parse(jsonLine);
      results = (Array.isArray(raw) ? raw : [raw]).filter(r => r !== null && r !== undefined);
    } catch (e) {
      console.error('JSON parse error:', e.message, '\nstdout:', stdout);
      return res.status(500).send(errorHtml('Failed to parse DNS results.'));
    }

    // Always send results HTML
    // If export requested, embed the download data as well
    const exportData = doexport === '1' ? {
      fmt: (exportfmt || 'csv').toLowerCase(),
      data: (exportfmt || 'csv').toLowerCase() === 'json' ? JSON.stringify(results, null, 2) : toCsv(results),
      filename: `GMR_${domain}_${timestamp()}.${(exportfmt || 'csv').toLowerCase()}`
    } : null;

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(resultsHtml(results, domain, exportData));
  });
});

// ── Helpers ───────────────────────────────────────────────────────────────────
function buildPsParams(body) {
  const { domain, selector, server, rectype, sub, justsub } = body;
  let p = `-Domain '${esc(domain)}'`;
  if (server && server.trim())     p += ` -Server '${esc(server)}'`;
  if (selector && selector.trim()) p += ` -Selector '${esc(selector)}'`;
  if (rectype)                     p += ` -RecordType '${esc(rectype)}'`;
  if (sub === '1')                 p += ' -Sub';
  if (justsub === '1')             p += ' -JustSub';
  return p;
}

function esc(s) {
  return String(s || '').replace(/'/g, "''").replace(/[^\x20-\x7E]/g, '');
}

function escHtml(s) {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, '-').slice(0, 16);
}

function toCsv(results) {
  if (!results.length) return '';
  const keys = Object.keys(results[0]);
  const header = keys.join(',');
  const rows = results.map(r =>
    keys.map(k => `"${String(r[k] || '').replace(/"/g, '""')}"`).join(',')
  );
  return [header, ...rows].join('\r\n');
}

// ── HTML: Input Form ──────────────────────────────────────────────────────────
function inputFormHtml() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GMR — Get Mail Records</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@300;400;500&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:#f7f6f3; --surface:#fff; --border:#e2ddd6; --border-focus:#3d6b1f;
    --text:#0a0a08; --muted:#1a1815; --accent:#3d6b1f; --accent-hover:#2e5016;
    --ok-bg:#edf2e6; --ok-text:#2e5016;
    --mono:'IBM Plex Mono',monospace; --sans:'IBM Plex Sans',sans-serif;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);font-family:var(--sans);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:40px 20px}
  .wrap{width:100%;max-width:520px}
  .brand{display:flex;align-items:baseline;gap:12px;margin-bottom:32px}
  .brand-name{font-family:var(--mono);font-size:2rem;font-weight:600;color:var(--accent);letter-spacing:-.04em}
  .brand-sub{font-size:12px;font-weight:300;color:var(--muted);letter-spacing:.05em}
  .panel{background:var(--surface);border:1px solid var(--border);border-radius:8px;overflow:hidden}
  .section{padding:20px 22px;border-bottom:1px solid var(--border)}
  .section:last-child{border-bottom:none}
  .sec-label{font-family:var(--mono);font-size:10px;font-weight:500;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin-bottom:14px}
  .field{margin-bottom:12px}
  .field:last-child{margin-bottom:0}
  .field label{display:block;font-size:11px;font-weight:500;color:var(--muted);margin-bottom:5px;font-family:var(--mono);letter-spacing:.06em}
  input[type=text],select{width:100%;padding:9px 12px;background:var(--bg);border:1px solid var(--border);border-radius:5px;font-family:var(--mono);font-size:13px;color:var(--text);outline:none;transition:border-color .15s,box-shadow .15s}
  input[type=text]:focus,select:focus{border-color:var(--border-focus);box-shadow:0 0 0 3px rgba(61,107,31,.1)}
  input::placeholder{color:var(--muted);opacity:.6}
  .two-col{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  .check-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
  .check-item{display:flex;align-items:flex-start;gap:9px;padding:9px 11px;border:1px solid var(--border);border-radius:5px;cursor:pointer;transition:border-color .12s,background .12s}
  .check-item:hover{border-color:var(--border-focus);background:var(--ok-bg)}
  .check-item input{margin-top:2px;accent-color:var(--accent);width:13px;height:13px;flex-shrink:0;cursor:pointer}
  .check-label{font-family:var(--mono);font-size:11px;color:var(--text);font-weight:500}
  .check-desc{font-size:10px;color:var(--muted);margin-top:2px}
  .export-toggle{display:flex;align-items:center;gap:8px;margin-bottom:10px;cursor:pointer}
  .export-toggle input{accent-color:var(--accent);width:13px;height:13px}
  .export-toggle span{font-family:var(--mono);font-size:12px;color:var(--text)}
  .export-fields{display:none;grid-template-columns:1fr 1fr;gap:10px;margin-top:10px}
  .export-fields.on{display:grid}
  .run-btn{width:100%;padding:12px;background:var(--accent);color:#fff;border:none;border-radius:5px;font-family:var(--mono);font-size:13px;font-weight:600;letter-spacing:.06em;cursor:pointer;transition:background .15s}
  .run-btn:hover{background:var(--accent-hover)}
  .run-btn:disabled{opacity:.5;cursor:not-allowed}
  .spinner-row{display:none;align-items:center;gap:10px;margin-top:12px;font-family:var(--mono);font-size:11px;color:var(--muted)}
  .spinner{width:14px;height:14px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite}
  @keyframes spin{to{transform:rotate(360deg)}}
  .err{display:none;margin-top:10px;padding:9px 13px;background:#fdf0f0;border:1px solid #e8c0c0;border-radius:5px;font-family:var(--mono);font-size:11px;color:#8b1a1a}
  footer{text-align:center;margin-top:20px;font-size:10px;color:var(--muted);font-family:var(--mono);letter-spacing:.06em}
  footer a{color:var(--muted);text-decoration:none;border-bottom:1px solid var(--border)}
  footer a:hover{color:var(--accent)}
</style>
</head>
<body>
<div class="wrap">
  <div class="brand">
    <span class="brand-name">GMR</span>
    <span class="brand-sub">Get Mail Records</span>
  </div>

  <div class="panel">
    <div class="section">
      <div class="sec-label">Target</div>
      <div class="field">
        <label>Domain / Email / URL</label>
        <input type="text" id="domain" name="domain" placeholder="http://www.example.com or address@example.com or example.com" autocomplete="off" spellcheck="false">
      </div>
      <div class="two-col">
        <div class="field">
          <label>DKIM Selector <span style="font-weight:400;opacity:.7">(auto if blank)</span></label>
          <input type="text" id="selector" name="selector" placeholder="selector1" autocomplete="off">
        </div>
        <div class="field">
          <label>DNS Server</label>
          <input type="text" id="server" name="server" placeholder="8.8.8.8" value="8.8.8.8" autocomplete="off">
        </div>
      </div>
    </div>

    <div class="section">
      <div class="sec-label">Options</div>
      <div class="check-grid">
        <label class="check-item">
          <input type="radio" name="rectype" value="TXT" checked>
          <div><div class="check-label">TXT</div><div class="check-desc">SPF / DMARC / DKIM</div></div>
        </label>
        <label class="check-item">
          <input type="radio" name="rectype" value="CNAME">
          <div><div class="check-label">CNAME</div><div class="check-desc">Follow chain</div></div>
        </label>
        <label class="check-item">
          <input type="radio" name="rectype" value="BOTH">
          <div><div class="check-label">BOTH</div><div class="check-desc">TXT + CNAME</div></div>
        </label>
        <label class="check-item">
          <input type="checkbox" id="sub" name="sub" value="1">
          <div><div class="check-label">-Sub</div><div class="check-desc">Also base domain</div></div>
        </label>
        <label class="check-item">
          <input type="checkbox" id="justsub" name="justsub" value="1">
          <div><div class="check-label">-JustSub</div><div class="check-desc">Subdomain only</div></div>
        </label>
      </div>
    </div>

    <div class="section">
      <div class="sec-label">Export</div>
      <label class="export-toggle">
        <input type="checkbox" id="do-export" onchange="toggleExport()">
        <span>Download results as file</span>
      </label>
      <div class="export-fields" id="export-fields">
        <div class="field">
          <label>Format</label>
          <select id="exportfmt" name="exportfmt">
            <option value="csv">CSV</option>
            <option value="json">JSON</option>
          </select>
        </div>
      </div>
    </div>

    <div class="section">
      <button class="run-btn" id="btn-run" onclick="runQuery()">Run Query →</button>
      <div class="spinner-row" id="spinner">
        <div class="spinner"></div>
        <span>Querying DNS…</span>
      </div>
      <div class="err" id="err"></div>
    </div>
  </div>

  <footer>
    <a href="https://github.com/dcazman/Get-MailRecords" target="_blank">GitHub</a>
     &middot;  built by Dan Casmas  &middot;  powered by GMR
  </footer>
</div>

<script>
  document.getElementById('domain').addEventListener('keydown', e => {
    if (e.key === 'Enter') runQuery();
  });
  document.getElementById('sub').addEventListener('change', function() {
    if (this.checked) document.getElementById('justsub').checked = false;
  });
  document.getElementById('justsub').addEventListener('change', function() {
    if (this.checked) document.getElementById('sub').checked = false;
  });
  function toggleExport() {
    document.getElementById('export-fields').classList.toggle('on', document.getElementById('do-export').checked);
  }
  function runQuery() {
    const domain = document.getElementById('domain').value.trim();
    if (!domain) { showErr('Please enter a domain, email, or URL.'); return; }
    hideErr();
    // Use a hidden form with target="_blank" - browsers always allow this
    // as it is a direct user action, no popup blocker issues
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = '/query';
    form.target = '_blank';
    const fields = {
      domain,
      selector:  document.getElementById('selector').value.trim(),
      server:    document.getElementById('server').value.trim() || '8.8.8.8',
      rectype:   document.querySelector('input[name="rectype"]:checked').value,
      sub:       document.getElementById('sub').checked ? '1' : '0',
      justsub:   document.getElementById('justsub').checked ? '1' : '0',
      doexport:  document.getElementById('do-export').checked ? '1' : '0',
      exportfmt: document.getElementById('exportfmt') ? document.getElementById('exportfmt').value : 'csv',
    };
    for (const [k, v] of Object.entries(fields)) {
      const i = document.createElement('input');
      i.type = 'hidden'; i.name = k; i.value = v;
      form.appendChild(i);
    }
    document.body.appendChild(form);
    form.submit();
    document.body.removeChild(form);
  }
  function setLoading(on) {
    document.getElementById('btn-run').disabled = on;
    document.getElementById('spinner').style.display = on ? 'flex' : 'none';
  }
  function showErr(m) { const e = document.getElementById('err'); e.textContent = '⚠ ' + m; e.style.display = 'block'; }
  function hideErr()  { document.getElementById('err').style.display = 'none'; }
</script>
</body>
</html>`;
}

// ── HTML: Results Page ────────────────────────────────────────────────────────
function resultsHtml(results, domain, exportData = null) {
  const queried = new Date().toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' });
  const server  = results[0] && results[0].SERVER ? results[0].SERVER : '8.8.8.8';

  const blocks = results.map(item => {
    const rt      = item.RECORDTYPE || 'TXT';
    const selNote = item.SELECTOR && item.SELECTOR !== 'unprovided' ? `sel: ${item.SELECTOR}` : 'auto-discovered';

    const rows = [
      { rec: 'A Record',     det: '',           val: item.A ? 'Resolved' : 'Not found',         status: item.A ? 'ok' : 'warn' },
      { rec: 'MX',           det: '',           val: item.MX || '—',                              status: item.MX ? 'ok' : 'none' },
      { rec: 'SPF',          det: `type: ${rt}`,val: item[`SPF_${rt}`]   || '—',                 status: item[`SPF_${rt}`]   ? 'ok' : 'none' },
      { rec: 'DMARC',        det: `type: ${rt}`,val: item[`DMARC_${rt}`] || '—',                 status: item[`DMARC_${rt}`] ? 'ok' : 'none' },
      { rec: 'DKIM',         det: selNote,      val: item[`DKIM_${rt}`]  || '—',                 status: item[`DKIM_${rt}`]  ? 'ok' : 'none' },
      { rec: 'NS (first 2)', det: '',           val: item.NS_First2 || '—',                       status: item.NS_First2      ? 'ok' : 'none' },
    ];

    const rowsHtml = rows.map(r => {
      const badgeLabel = { ok: 'Found', none: 'None', warn: 'Check' }[r.status];
      return `<tr>
        <td class="rec">${escHtml(r.rec)}</td>
        <td class="det">${escHtml(r.det)}</td>
        <td class="val">${escHtml(r.val)}</td>
        <td><span class="badge ${r.status}">${badgeLabel}</span></td>
      </tr>`;
    }).join('');

    return `
    <div class="result-block">
      <div class="block-hdr">${escHtml(item.DOMAIN)}</div>
      <table>
        <thead><tr><th>Record</th><th>Detail</th><th>Value</th><th>Status</th></tr></thead>
        <tbody>${rowsHtml}</tbody>
      </table>
    </div>`;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GMR — ${escHtml(domain)}</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@300;400;500&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#f7f6f3;--surface:#fff;--border:#e2ddd6;--text:#0a0a08;--muted:#1a1815;
    --accent:#3d6b1f;--ok-bg:#edf2e6;--ok-text:#173510;
    --none-bg:#f0ede8;--none-text:#3d3a35;--warn-bg:#fdf6e3;--warn-text:#4a3500;
    --mono:'IBM Plex Mono',monospace;--sans:'IBM Plex Sans',sans-serif;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);font-family:var(--sans);color:var(--text);padding:36px 24px 80px}
  .wrap{max-width:900px;margin:0 auto}
  header{display:flex;align-items:baseline;justify-content:space-between;margin-bottom:28px;padding-bottom:18px;border-bottom:1px solid var(--border)}
  .brand{display:flex;align-items:baseline;gap:12px}
  .brand-name{font-family:var(--mono);font-size:1.6rem;font-weight:600;color:var(--accent);letter-spacing:-.04em}
  .brand-domain{font-family:var(--mono);font-size:13px;color:var(--muted)}
  .new-query{font-family:var(--mono);font-size:11px;color:var(--accent);text-decoration:none;border-bottom:1px solid var(--ok-bg);padding-bottom:1px}
  .new-query:hover{border-color:var(--accent)}
  .result-block{background:var(--surface);border:1px solid var(--border);border-radius:8px;margin-bottom:20px;overflow:hidden}
  .block-hdr{background:#f0ede8;border-bottom:1px solid var(--border);padding:10px 18px;font-family:var(--mono);font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:#1a1815}
  table{width:100%;border-collapse:collapse;font-size:12px}
  th{padding:9px 16px;text-align:left;font-family:var(--mono);font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:#1a1815;background:#f8f6f2;border-bottom:1px solid var(--border);white-space:nowrap}
  td{padding:10px 16px;border-bottom:1px solid var(--border);vertical-align:top}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:#faf9f6}
  td.rec{font-family:var(--mono);font-size:12px;font-weight:500;white-space:nowrap}
  td.det{font-size:10px;color:var(--muted);font-family:var(--mono);white-space:nowrap}
  td.val{font-family:var(--mono);font-size:11px;word-break:break-all;white-space:pre-wrap;max-width:540px}
  .badge{display:inline-block;padding:2px 9px;border-radius:3px;font-size:10px;font-weight:500;font-family:var(--mono);letter-spacing:.05em}
  .ok  {background:var(--ok-bg);  color:var(--ok-text)}
  .none{background:var(--none-bg);color:var(--none-text)}
  .warn{background:var(--warn-bg);color:var(--warn-text)}
  .ts{font-family:var(--mono);font-size:10px;color:var(--muted);margin-top:28px;text-align:right}
  footer{text-align:center;margin-top:40px;font-size:10px;color:var(--muted);font-family:var(--mono)}
  footer a{color:var(--muted);text-decoration:none;border-bottom:1px solid var(--border)}
  footer a:hover{color:var(--accent)}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand">
      <span class="brand-name">GMR</span>
      <span class="brand-domain">${escHtml(domain)}</span>
    </div>
    <a class="new-query" href="javascript:window.close()">&larr; close</a>
  </header>
  ${blocks}
  <div class="ts">Queried ${queried}  &middot;  Server: ${escHtml(server)}</div>
  <footer>
    <a href="https://github.com/dcazman/Get-MailRecords" target="_blank">GitHub</a>
     &middot;  built by Dan Casmas  &middot;  powered by GMR
  </footer>
</div>
${exportData ? `
<script>
(function() {
  const d = ${JSON.stringify(exportData)};
  setTimeout(function() {
    const blob = new Blob([d.data], { type: d.fmt === 'json' ? 'application/json' : 'text/csv' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = d.filename; a.click();
    URL.revokeObjectURL(url);
  }, 600);
})();
</script>` : ''}
</body>
</html>`;
}

function errorHtml(msg) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8">
  <style>body{font-family:monospace;padding:40px;background:#f7f6f3;color:#8b1a1a}</style>
  </head><body><strong>GMR Error</strong><br><br>${escHtml(msg)}<br><br><a href="/">← Back</a></body></html>`;
}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`GMR server running on 0.0.0.0:${PORT}`);
});
