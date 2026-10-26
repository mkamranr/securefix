// Shared helpers. No external libraries: everything is served locally for the air-gapped network.
const CSRF = document.querySelector('meta[name="csrf-token"]').content;

async function api(path, opts = {}) {
  const res = await fetch(path, {
    method: opts.method || 'GET',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
    credentials: 'same-origin',
  });
  if (res.status === 401) { location.href = '/login'; throw new Error('Signed out'); }
  let data = null;
  try { data = await res.json(); } catch (_) { /* empty body */ }
  if (!res.ok) throw Object.assign(new Error((data && data.detail) || `Request failed (${res.status})`), { status: res.status });
  return data;
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function debounce(fn, ms = 300) {
  let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

function when(iso) {
  if (!iso) return '';
  const d = new Date(iso), mins = Math.round((Date.now() - d) / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins} min ago`;
  if (mins < 1440) return `${Math.round(mins / 60)} h ago`;
  return d.toISOString().slice(0, 10);
}

// Connection state for the header and sidebar, cached for a minute so page changes don't re-check.
async function systemHealth(force = false) {
  const KEY = 'vt-health';
  if (!force) {
    try {
      const c = JSON.parse(sessionStorage.getItem(KEY) || 'null');
      if (c && Date.now() - c.at < 60000) return c.h;
    } catch (_) { /* storage unavailable */ }
  }
  const h = await api('/api/health');
  try { sessionStorage.setItem(KEY, JSON.stringify({ at: Date.now(), h })); } catch (_) { /* ignore */ }
  return h;
}

(async () => {
  const conn = document.getElementById('gitlab-conn'), dot = document.getElementById('status-dot');
  if (!conn && !dot) return;
  try {
    const h = await systemHealth();
    if (conn) {
      conn.dataset.state = h.gitlab.ok ? 'ok' : 'bad';
      conn.querySelector('.conn-label').textContent = h.gitlab.ok ? 'Connected to GitLab' : 'GitLab not connected';
      conn.title = h.gitlab.detail || '';
    }
    if (dot) {
      dot.dataset.state = h.gitlab.ok && h.llm.ok ? 'ok' : 'bad';
      dot.title = h.gitlab.ok && h.llm.ok ? 'GitLab and the model are reachable' : 'Something is unreachable';
    }
  } catch (_) {
    if (conn) { conn.dataset.state = 'bad'; conn.querySelector('.conn-label').textContent = 'Status unknown'; }
    if (dot) dot.dataset.state = 'bad';
  }
})();

// Close the account menu when clicking elsewhere.
document.addEventListener('click', e => {
  document.querySelectorAll('details.usermenu[open]').forEach(d => { if (!d.contains(e.target)) d.open = false; });
});

// Forms that need confirmation carry data-confirm (no inline handlers: the proxy's CSP blocks them).
document.addEventListener('submit', e => {
  const msg = e.target.dataset && e.target.dataset.confirm;
  if (msg && !confirm(msg)) e.preventDefault();
});
