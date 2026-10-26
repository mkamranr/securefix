(() => {
  const $ = id => document.getElementById(id);
  const PER_PAGE = 20;  // GitLab page size used by /api/projects/:id/commits
  const state = { project: null, branch: null, page: 1, commits: [], scans: {}, details: {}, selected: null };
  const icon = name => `<svg class="i" aria-hidden="true"><use href="/static/icons.svg#${name}"/></svg>`;
  const SCAN = {
    finished: ['Available', 'check-circle'], running: ['Scan running', 'clock'], pending: ['Checking…', 'clock'],
    none: ['Not Available', 'minus-circle'], failed: ['Scan failed', 'x-circle'],
  };

  // ---------------------------------------------------------------- steps
  function setStep(n) {
    document.querySelectorAll('#steps .step').forEach(s => {
      const k = Number(s.dataset.step);
      s.classList.toggle('done', k < n);
      s.classList.toggle('current', k === n);
    });
  }

  // ---------------------------------------------------------------- severities
  const SEV_KEY = 'vt-severities';
  const sevBoxes = [...document.querySelectorAll('#severities input[name=severity]')];
  const chosenSeverities = () => sevBoxes.filter(b => b.checked).map(b => b.value);
  try {  // restore this browser's last choice; the page defaults to critical + high
    const saved = JSON.parse(localStorage.getItem(SEV_KEY) || 'null');
    if (Array.isArray(saved) && saved.length) sevBoxes.forEach(b => { b.checked = saved.includes(b.value); });
  } catch (e) { /* keep the defaults */ }
  sevBoxes.forEach(b => b.addEventListener('change', () => {
    try { localStorage.setItem(SEV_KEY, JSON.stringify(chosenSeverities())); } catch (e) { /* storage unavailable */ }
    updateReady();
  }));

  // ---------------------------------------------------------------- 1. project (searchable list)
  const pInput = $('project-input'), pList = $('projects');
  let projectItems = [];

  function openList(open) { pList.hidden = !open; pInput.setAttribute('aria-expanded', String(open)); }

  async function loadProjects(search = '') {
    pList.innerHTML = '<li class="muted">Loading…</li>'; openList(true);
    try {
      projectItems = await api(`/api/projects?search=${encodeURIComponent(search)}`);
      if (!projectItems.length) { pList.innerHTML = '<li class="muted">No projects match. Your token only sees projects you are a member of.</li>'; return; }
      pList.innerHTML = projectItems.map((p, i) => `<li role="option" id="po-${i}" data-i="${i}" aria-selected="${i === 0}">
        <span class="name">${esc(p.path)}</span><span class="sub">${esc(p.name)}</span></li>`).join('');
    } catch (e) { pList.innerHTML = `<li class="error">${esc(e.message)}</li>`; }
  }

  function chooseProject(p) {
    state.project = p; state.branch = null;
    pInput.value = p.path; openList(false);
    $('project-link').href = p.web_url || '#'; $('project-link').hidden = !p.web_url;
    $('pi-path').textContent = p.path; $('pi-id').textContent = `ID: ${p.id}`; $('pi-group').textContent = `Group: ${p.group}`;
    $('project-info').hidden = false;
    setStep(2);
    loadBranches();
  }

  pInput.addEventListener('focus', () => { if (!projectItems.length) loadProjects(''); else openList(true); });
  pInput.addEventListener('input', debounce(() => loadProjects(pInput.value.trim())));
  pInput.addEventListener('keydown', e => {
    const opts = [...pList.querySelectorAll('li[role=option]')];
    let i = opts.findIndex(o => o.getAttribute('aria-selected') === 'true');
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault(); if (!opts.length) return;
      i = (i + (e.key === 'ArrowDown' ? 1 : -1) + opts.length) % opts.length;
      opts.forEach((o, k) => o.setAttribute('aria-selected', String(k === i)));
      opts[i].scrollIntoView({ block: 'nearest' }); pInput.setAttribute('aria-activedescendant', opts[i].id);
    } else if (e.key === 'Enter' && i >= 0 && !pList.hidden) {
      e.preventDefault(); chooseProject(projectItems[opts[i].dataset.i]);
    } else if (e.key === 'Escape') { openList(false); }
  });
  pList.addEventListener('mousedown', e => {  // mousedown: before the input loses focus
    const li = e.target.closest('li[role=option]');
    if (li) { e.preventDefault(); chooseProject(projectItems[li.dataset.i]); }
  });
  document.addEventListener('click', e => { if (!e.target.closest('.project-pick')) openList(false); });

  // ---------------------------------------------------------------- 2. branch
  const bSelect = $('branch');
  async function loadBranches() {
    const keep = state.branch && state.branch.name;
    bSelect.disabled = true; $('branch-refresh').disabled = true;
    bSelect.innerHTML = '<option>Loading branches…</option>';
    resetCommits('Loading…');
    try {
      const items = await api(`/api/projects/${state.project.id}/branches`);
      items.sort((a, b) => (b.default - a.default) || (b.committed_date || '').localeCompare(a.committed_date || ''));
      state.branches = items;
      if (!items.length) { bSelect.innerHTML = '<option>This project has no branches</option>'; resetCommits('No branches.'); return; }
      bSelect.innerHTML = items.map((b, i) => `<option value="${i}">${esc(b.name)}${b.default ? ' (default)' : ''}</option>`).join('');
      const k = Math.max(0, items.findIndex(b => b.name === keep));
      bSelect.value = String(k);
      bSelect.disabled = false; $('branch-refresh').disabled = false;
      chooseBranch(items[k]);
    } catch (e) { bSelect.innerHTML = `<option>${esc(e.message)}</option>`; resetCommits(e.message); }
  }
  function chooseBranch(b) { state.branch = b; state.page = 1; setStep(3); loadCommits(); }
  bSelect.addEventListener('change', () => chooseBranch(state.branches[Number(bSelect.value)]));
  $('branch-refresh').addEventListener('click', loadBranches);

  // ---------------------------------------------------------------- 3. commits
  const tbody = $('commits');
  function resetCommits(text) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty">${esc(text)}</td></tr>`;
    $('pager-text').textContent = ''; $('prev-page').disabled = $('next-page').disabled = true;
    $('commit-search').disabled = true;
    clearSelection();
  }

  const shortDate = iso => {
    if (!iso) return '';
    const d = new Date(iso), p = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
  };
  const scanBadge = s => {
    const [label, ic] = SCAN[s.state] || SCAN.none;
    const n = s.finding_count != null ? ` · ${s.finding_count}` : '';
    return `<span class="sast sast-${esc(s.state)}" title="${esc(s.label || '')}">${icon(ic)}${label}${n}</span>`;
  };

  async function loadCommits() {
    resetCommits('Loading commits…');
    $('page-n').textContent = state.page;
    try {
      const items = await api(`/api/projects/${state.project.id}/commits?ref=${encodeURIComponent(state.branch.name)}&page=${state.page}`);
      state.commits = items;
      if (!items.length) { resetCommits(state.page === 1 ? 'This branch has no commits.' : 'No older commits.'); $('prev-page').disabled = state.page === 1; return; }
      tbody.innerHTML = items.map((c, i) => `
        <tr data-i="${i}" data-sha="${esc(c.sha)}" aria-selected="false">
          <td><input type="radio" name="commit" aria-label="Select commit ${esc(c.short)}"></td>
          <td><code>${esc(c.short)}</code></td>
          <td><span class="msg" title="${esc(c.title)}">${esc(c.title)}</span>${c.job ? `<a class="prior" href="/jobs/${c.job.id}">Analysis #${c.job.id}: ${esc(c.job.status)}</a>` : ''}</td>
          <td>${esc(c.author)}</td>
          <td>${esc(shortDate(c.date))}</td>
          <td class="scan-cell">${scanBadge(state.scans[c.sha] || { state: 'pending' })}</td>
        </tr>`).join('');
      const first = (state.page - 1) * PER_PAGE + 1;
      $('pager-text').textContent = `Showing ${first}–${first + items.length - 1} (page ${state.page})`;
      $('prev-page').disabled = state.page === 1; $('next-page').disabled = items.length < PER_PAGE;
      $('commit-search').disabled = false; $('commit-search').value = '';
      items.forEach(c => { if (!state.scans[c.sha]) fetchScan(c.sha); });
    } catch (e) { resetCommits(e.message); }
  }

  async function fetchScan(sha, detail = false) {
    try {
      const s = await api(`/api/projects/${state.project.id}/commits/${sha}/scan?path=${encodeURIComponent(state.project.path)}${detail ? '&detail=1' : ''}`);
      state.scans[sha] = { ...(state.scans[sha] || {}), ...s };
    } catch (e) {
      state.scans[sha] = { state: 'failed', label: e.message };
    }
    const cell = tbody.querySelector(`tr[data-sha="${sha}"] .scan-cell`);
    if (cell) cell.innerHTML = scanBadge(state.scans[sha]);
    if (state.selected && state.selected.sha === sha) showScan();
    return state.scans[sha];
  }

  tbody.addEventListener('click', e => {
    if (e.target.closest('a')) return;
    const tr = e.target.closest('tr[data-i]');
    if (tr) selectCommit(tr);
  });
  $('commit-search').addEventListener('input', e => {
    const q = e.target.value.trim().toLowerCase();
    tbody.querySelectorAll('tr[data-i]').forEach(tr => {
      const c = state.commits[tr.dataset.i];
      tr.hidden = q && !`${c.sha} ${c.title} ${c.author}`.toLowerCase().includes(q);
    });
  });
  $('prev-page').addEventListener('click', () => { if (state.page > 1) { state.page -= 1; loadCommits(); } });
  $('next-page').addEventListener('click', () => { state.page += 1; loadCommits(); });

  // ---------------------------------------------------------------- 4. selected commit
  function clearSelection() {
    state.selected = null;
    $('d-selected').hidden = true;
    ['d-sha', 'd-msg', 'd-author', 'd-date', 'd-branch'].forEach(id => { $(id).textContent = '—'; });
    $('d-prior').hidden = true;
    setScanLine('none', 'minus-circle', 'No commit selected', 'Pick a commit to see its scan.');
    setCounts(null);
    updateReady();
  }

  function selectCommit(tr) {
    tbody.querySelectorAll('tr[aria-selected="true"]').forEach(r => { r.setAttribute('aria-selected', 'false'); r.querySelector('input').checked = false; });
    tr.setAttribute('aria-selected', 'true'); tr.querySelector('input').checked = true;
    const c = state.commits[tr.dataset.i];
    state.selected = c;
    $('d-selected').hidden = false;
    $('d-sha').innerHTML = `<code>${esc(c.short)}</code>${c.web_url ? ` <a href="${esc(c.web_url)}" target="_blank" rel="noopener" aria-label="Open the commit in GitLab">${icon('external')}</a>` : ''}`;
    $('d-msg').textContent = c.title;
    $('d-author').innerHTML = `<span class="avatar">${esc((c.author || '?').slice(0, 1).toUpperCase())}</span>${esc(c.author)}`;
    $('d-date').textContent = shortDate(c.date);
    $('d-branch').innerHTML = `${icon('branch')}${esc(state.branch.name)}`;
    const prior = $('d-prior');
    prior.hidden = !c.job;
    if (c.job) prior.innerHTML = `Already analyzed: <a href="/jobs/${c.job.id}">analysis #${c.job.id}</a> (${esc(c.job.status)}, by ${esc(c.job.by)}).`;
    setStep(4);
    showScan();
    const s = state.scans[c.sha];
    if (!s || (s.state === 'finished' && !s.severity_counts)) fetchScan(c.sha, true);
  }

  function setScanLine(kind, ic, title, sub) {
    $('s-line').className = `status-line status-${kind}`;
    $('s-icon').innerHTML = `<svg class="big-i" aria-hidden="true"><use href="/static/icons.svg#${ic}"/></svg>`;
    $('s-title').textContent = title; $('s-sub').textContent = sub;
  }

  function setCounts(s) {
    const counts = (s && s.severity_counts) || null;
    $('n-total').textContent = s && s.finding_count != null ? s.finding_count : '–';
    for (const k of ['critical', 'high', 'medium', 'low']) $(`n-${k}`).textContent = counts ? (counts[k] || 0) : '–';
  }

  function showScan() {
    const c = state.selected; if (!c) return;
    const s = state.scans[c.sha];
    if (!s || s.state === 'pending') setScanLine('wait', 'clock', 'Checking the scan…', 'Looking up the pipeline for this commit.');
    else if (s.state === 'finished') setScanLine('ok', 'check-circle', 'Report available for this commit', 'Advanced SAST results will be fetched from GitLab.');
    else if (s.state === 'running') setScanLine('wait', 'clock', 'Scan still running', 'Wait for the SAST job to finish, then analyze.');
    else if (s.state === 'failed') setScanLine('bad', 'x-circle', 'Scan failed', s.label || 'The SAST job failed for this commit.');
    else setScanLine('none', 'minus-circle', 'No SAST report', s.label || 'This commit has no SAST job.');
    setCounts(s);
    updateReady();
  }

  // ---------------------------------------------------------------- 5. start
  const startBtn = $('start');
  function updateReady() {
    const c = state.selected, s = c && state.scans[c.sha], picked = chosenSeverities();
    $('severity-hint').hidden = picked.length > 0;
    const running = c && c.job && ['queued', 'running'].includes(c.job.status);
    startBtn.querySelector('span').textContent = running ? `Open running analysis #${c.job.id}` : (c && c.job ? 'Analyze Again' : 'Start Analysis');
    if (!c) { $('r-text').textContent = 'Select a commit whose SAST scan has finished.'; startBtn.disabled = true; return; }
    if (running) { $('r-text').textContent = 'This commit is already being analyzed.'; startBtn.disabled = false; return; }
    const ready = s && s.state === 'finished' && s.finding_count !== 0;
    $('r-text').textContent = ready
      ? 'This commit has a SAST report available. Start AI analysis to classify findings and get suggested fixes.'
      : (s && s.state === 'finished' ? 'The scan found nothing to analyze.' : 'This commit can be analyzed once its SAST scan has finished.');
    startBtn.disabled = !ready || !picked.length;
  }

  startBtn.addEventListener('click', async () => {
    const c = state.selected; if (!c) return;
    if (c.job && ['queued', 'running'].includes(c.job.status)) { location.href = `/jobs/${c.job.id}`; return; }
    const label = startBtn.querySelector('span').textContent;
    startBtn.disabled = true; startBtn.querySelector('span').textContent = 'Starting…';
    try {
      const r = await api('/api/jobs', { method: 'POST', body: { project_id: state.project.id, project_path: state.project.path, branch: state.branch.name, sha: c.sha, severities: chosenSeverities() } });
      setStep(5);
      location.href = `/jobs/${r.id}`;
    } catch (e) {
      startBtn.querySelector('span').textContent = label; startBtn.disabled = false;
      alert(e.message);
    }
  });

  clearSelection();
})();
