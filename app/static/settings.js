(async () => {
  const el = document.getElementById('health');
  try {
    const h = await systemHealth(true);
    const row = (name, s) => `<dt>${name}</dt><dd class="${s.ok ? 'ok' : 'bad'}">${s.ok ? 'Reachable' : 'Problem'}${s.detail ? ': ' + esc(s.detail) : ''}</dd>`;
    el.innerHTML = row('GitLab', h.gitlab) + row('Local model', h.llm);
  } catch (e) {
    el.innerHTML = `<dt>Check</dt><dd class="bad">${esc(e.message)}</dd>`;
  }
})();
