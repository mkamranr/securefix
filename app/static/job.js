(() => {
  const root = document.getElementById('job');
  const jobId = root.dataset.jobId;
  const canAct = root.dataset.canAct === '1';  // only the user who started the analysis; others view it read-only
  const $ = id => document.getElementById(id);
  const rows = new Map();      // finding id -> {el, sig, f}
  const selected = new Set();  // finding ids picked for posting to GitLab
  let filter = 'all', timer = null, job = null, posting = false;
  const eligible = f => canAct && f.status === 'done' && !f.posted;
  const pct = c => c != null ? `${Math.round(c * 100)}%` : '';
  const secs = s => { s = Math.round(s); return s < 60 ? `${s} s` : `${Math.floor(s / 60)} m ${String(s % 60).padStart(2, '0')} s`; };
  const modelRan = f => f.status === 'done' && !f.copied_from && f.duration_s != null;

  const VERDICT = {
    true_positive: ['Real', 'v-real'],
    false_positive: ['False positive', 'v-fp'],
    needs_review: ['Needs review', 'v-review'],
  };
  const VALIDATION = {
    passed: 'Fix applied, built, tested and re-scanned cleanly.',
    failed: 'Fix did not pass validation.',
    not_configured: 'Fix not validated: no build, test or re-scan command is set for this project (Admin).',
  };

  function stamp(f) {
    if (f.status === 'pending') return '<span class="stamp v-wait">Waiting</span>';
    if (f.status === 'analyzing') return '<span class="stamp v-wait busy">Analyzing</span>';
    if (f.status === 'skipped') return '<span class="stamp v-skip">Skipped</span>';
    if (f.status === 'error') return '<span class="stamp v-err">Error</span>';
    const [label, cls] = VERDICT[f.verdict] || ['Unknown', 'v-skip'];
    return `<span class="stamp ${cls}">${label}</span>`;
  }

  function diffHtml(diff) {
    return diff.split('\n').map(l => {
      const cls = l.startsWith('+++') || l.startsWith('---') ? 'd-file' : l.startsWith('@@') ? 'd-hunk'
        : l.startsWith('+') ? 'd-add' : l.startsWith('-') ? 'd-del' : '';
      return `<span class="${cls}">${esc(l) || ' '}</span>`;
    }).join('');
  }

  function detailHtml(f) {
    const parts = [];
    if (f.gitlab_url) {
      const label = f.vulnerability_gid ? 'Open vulnerability in GitLab' : 'Open in pipeline security report';
      parts.push(`<p class="ext"><a class="ext-link" href="${esc(f.gitlab_url)}" target="_blank" rel="noopener">${label} <span aria-hidden="true">↗</span><span class="visually-hidden"> (opens in a new tab)</span></a></p>`);
    }
    if (f.error) parts.push(`<p class="error">${esc(f.error)}</p>`);
    const c = f.copied_from;
    if (c && f.status === 'done') {
      const why = c.why === 'same code and prompt' ? 'the same code and prompt' : 'the same vulnerability, file, lines and code';
      parts.push(`<p class="copied-note">Copied from an earlier scan: <a href="/jobs/${esc(c.job)}">analysis #${esc(c.job)}</a> at commit <code>${esc((c.sha || '').slice(0, 8))}</code>${
        c.at ? `, ${esc(when(c.at))}` : ''}. It had ${why}, so the model wasn’t asked again.</p>`);
    }
    if (f.injection_suspected) parts.push('<p class="warn">The code around this finding contains text addressed to an AI or reviewer. Treat the verdict with suspicion and check it yourself.</p>');
    if (f.verdict) {
      const conf = f.confidence != null ? `${Math.round(f.confidence * 100)}%` : 'n/a';
      const votes = (f.votes || []).map(v => (VERDICT[v.verdict] || [v.verdict])[0]).join(', ');
      const cost = modelRan(f) ? ` · analyzed in ${secs(f.duration_s)}${f.completion_tokens ? ` · ${f.completion_tokens.toLocaleString()} tokens generated` : ''}` : '';
      parts.push(`<p class="meta">Confidence ${conf}${votes ? `; independent runs: ${esc(votes)}` : ''}${cost}</p>`);
    }
    if (f.reasoning) parts.push(`<h3>Why</h3><div class="prose">${esc(f.reasoning)}</div>`);
    if ((f.evidence || []).length) parts.push(`<h3>Evidence</h3><ul class="evidence">${f.evidence.map(e => `<li><code>${esc(e)}</code></li>`).join('')}</ul>`);
    if (f.fix) {
      parts.push('<h3>Proposed fix</h3>');
      if (f.validation_status) parts.push(`<p class="validation val-${f.validation_status}">${esc(VALIDATION[f.validation_status] || f.validation_status)}</p>`);
      if (f.fix.explanation) parts.push(`<div class="prose">${esc(f.fix.explanation)}</div>`);
      if (f.diff) parts.push(`<pre class="diff" tabindex="0">${diffHtml(f.diff)}</pre>`);
      if (f.fix.suggested_test) parts.push(`<details><summary>Suggested test</summary><pre class="code">${esc(f.fix.suggested_test)}</pre></details>`);
      if (f.validation_log) parts.push(`<details><summary>Validation output</summary><pre class="code">${esc(f.validation_log)}</pre></details>`);
    }
    const flows = (f.code_flows || []).map(s => `<li><code>${esc(s.file)}:${s.line}</code> ${esc(s.kind || '')}</li>`).join('');
    if (flows) parts.push(`<details><summary>Scanner taint trace (${f.code_flows.length} steps)</summary><ol class="flow">${flows}</ol></details>`);
    if (f.description) parts.push(`<details><summary>Scanner description</summary><div class="prose">${esc(f.description)}</div></details>`);
    if ((f.context_files || []).length) {
      parts.push(`<details><summary>Code the model saw (${f.context_files.length} excerpts, ${f.context_tokens.toLocaleString()} tokens)</summary><ul class="ctx">${
        f.context_files.map(c => `<li><code>${esc(c.path)}:${c.start}-${c.end}</code> ${esc(c.reason)}</li>`).join('')}</ul></details>`);
    }
    if (f.status === 'done' && !canAct) {
      const p = f.posted;
      if (p) parts.push(`<p class="act-msg">Posted${p.issue_iid ? ` on issue #${esc(p.issue_iid)}` : ''} by ${esc(p.by)}, ${esc(when(p.at))}${
        p.url ? ` (<a href="${esc(p.url)}" target="_blank" rel="noopener">open comment</a>)` : ''}.</p>`);
    } else if (f.status === 'done') {
      const p = f.posted;
      const btns = [p ? '<button data-act="note" class="done" disabled>Analysis posted ✓</button>'
                      : '<button data-act="note">Post analysis to GitLab issue</button>'];
      if (f.fix && f.diff) btns.push('<button class="primary" data-act="mr">Open fix merge request</button>');
      if (f.vulnerability_gid && f.verdict !== 'true_positive') btns.push('<button class="danger" data-act="dismiss">Dismiss as false positive</button>');
      const posted = p ? `Already posted${p.issue_iid ? ` on issue #${esc(p.issue_iid)}` : ''}${
        p.copied_from_job ? ` from the earlier <a href="/jobs/${esc(p.copied_from_job)}">analysis #${esc(p.copied_from_job)}</a>` : ''} by ${esc(p.by)}, ${esc(when(p.at))}${
        p.url ? ` (<a href="${esc(p.url)}" target="_blank" rel="noopener">open comment</a>)` : ''}.` : '';
      parts.push(`<div class="actions">${btns.join('')}<span class="act-msg" role="status">${posted}</span></div>`);
      if (!p) parts.push('<p class="hint">The analysis is added once as a comment on this vulnerability’s GitLab issue. If it has none yet, a confidential issue is created first and assigned to you.</p>');
    }
    if ((f.actions || []).length) {
      parts.push(`<ul class="audit">${f.actions.map(a => `<li>${esc(a.type)} by ${esc(a.by)}, ${esc(when(a.at))}${a.url ? ` (<a href="${esc(a.url)}" target="_blank" rel="noopener">open</a>)` : ''}</li>`).join('')}</ul>`);
    }
    return parts.join('');
  }

  function rowEl(f) {
    const el = document.createElement('article');
    el.className = 'finding';
    el.innerHTML = `
      <label class="pick"><input type="checkbox"><span class="visually-hidden"></span></label>
      <button class="finding-head" aria-expanded="false" aria-controls="fd-${f.id}">
        <span class="sev sev-${esc(f.severity)}">${esc(f.severity)}</span>
        <span class="verdict-slot"></span>
        <span class="f-conf"></span>
        <span class="f-title"></span>
        <span class="f-loc"></span>
        <span class="f-time"></span>
        <span class="f-posted"></span>
      </button>
      <div class="finding-body" id="fd-${f.id}" hidden></div>`;
    const head = el.querySelector('.finding-head'), body = el.querySelector('.finding-body');
    if (!canAct) el.querySelector('.pick').style.visibility = 'hidden';  // keeps the column, shows no checkbox
    el.querySelector('.pick input').addEventListener('change', e => {
      if (e.target.checked) selected.add(f.id); else selected.delete(f.id);
      updateBulk();
    });
    head.addEventListener('click', () => {
      const open = head.getAttribute('aria-expanded') !== 'true';
      head.setAttribute('aria-expanded', String(open)); body.hidden = !open;
    });
    body.addEventListener('click', e => { const b = e.target.closest('button[data-act]'); if (b) act(f.id, b.dataset.act, b); });
    return el;
  }

  function fill(el, f) {
    el.querySelector('.verdict-slot').innerHTML = stamp(f);
    el.querySelector('.f-title').textContent = f.title;
    if (f.copied_from && f.status === 'done') {
      el.querySelector('.f-title').insertAdjacentHTML('beforeend', ' <span class="tag-copied" title="Analysis copied from an earlier scan">Copied</span>');
    }
    el.querySelector('.f-loc').textContent = `${f.file}${f.start_line ? ':' + f.start_line : ''}`;
    const conf = f.status === 'done' ? pct(f.confidence) : '';
    el.querySelector('.f-conf').textContent = conf || '—';
    el.querySelector('.f-conf').title = conf ? `Confidence ${conf}` : '';
    const time = el.querySelector('.f-time');
    if (f.status === 'done' && f.copied_from) { time.textContent = 'Copied'; time.title = 'Copied from an earlier scan: the model wasn’t asked'; }
    else if (f.duration_s != null && f.status !== 'analyzing') { time.textContent = secs(f.duration_s); time.title = 'Time spent analyzing this finding'; }
    else { time.textContent = f.status === 'analyzing' ? '…' : '—'; time.title = ''; }
    time.classList.toggle('muted', !(f.duration_s != null && !f.copied_from));
    el.querySelector('.finding-body').innerHTML = detailHtml(f);
    el.querySelector('.pick .visually-hidden').textContent = `Select ${f.title} for posting to GitLab`;
    el.querySelector('.f-posted').innerHTML = f.posted
      ? `<span class="posted posted-yes">Posted${f.posted.issue_iid ? ` #${esc(f.posted.issue_iid)}` : ''}</span>`
      : f.status === 'done' ? '<span class="posted">Not posted</span>' : '<span class="posted posted-none">—</span>';
    el.dataset.verdict = f.verdict || f.status;
    el.hidden = filter !== 'all' && el.dataset.verdict !== filter;
    if (!eligible(f)) selected.delete(f.id);
    syncBox(el, f);
  }

  // ---- selecting several findings and posting their analyses in one go
  function syncBox(el, f) {
    const box = el.querySelector('.pick input');
    box.disabled = posting || !eligible(f);
    box.checked = selected.has(f.id);
    box.title = f.posted ? 'The analysis is already posted to GitLab'
      : f.status !== 'done' ? 'Not analyzed yet' : 'Select to post this analysis to GitLab';
  }

  function updateBulk() {
    const all = [...rows.values()];
    const pickable = all.filter(r => !r.el.hidden && eligible(r.f));
    const picked = pickable.filter(r => selected.has(r.f.id)).length, n = selected.size;
    $('ledger-head').hidden = !all.length;
    $('bulkbar').hidden = !canAct || !all.some(r => r.f.status === 'done');
    $('sel-count').textContent = n ? `${n} finding${n === 1 ? '' : 's'} selected` : 'No findings selected';
    $('post-selected').disabled = posting || !n;
    $('post-selected').textContent = n ? `Post ${n} to GitLab issues` : 'Post analysis to GitLab issues';
    $('clear-sel').hidden = posting || !n;
    const pickAll = $('pick-all');
    if (!canAct) pickAll.closest('.pick').style.visibility = 'hidden';
    pickAll.disabled = posting || !pickable.length;
    pickAll.checked = !!pickable.length && picked === pickable.length;
    pickAll.indeterminate = picked > 0 && picked < pickable.length;
    pickAll.title = pickable.length ? 'Select every analyzed finding that isn’t posted yet' : 'Nothing left to post';
  }

  function syncAll() { rows.forEach(r => syncBox(r.el, r.f)); updateBulk(); }

  async function postSelected() {
    const ids = [...rows.values()].filter(r => selected.has(r.f.id) && eligible(r.f)).map(r => r.f.id);
    if (!ids.length) return;
    const many = ids.length === 1 ? 'this finding' : `these ${ids.length} findings`;
    if (!confirm(`Post the analysis of ${many} to GitLab? Each is added as a comment on its vulnerability’s issue; a finding without an issue gets a new confidential issue assigned to you.`)) return;
    posting = true; syncAll();
    const msg = $('bulk-msg'), failed = [];
    let ok = 0, already = 0, stopped = false;
    for (const [i, id] of ids.entries()) {
      msg.textContent = `Posting ${i + 1} of ${ids.length}…`;
      try {
        await api(`/api/findings/${id}/note`, { method: 'POST' });
        ok++; selected.delete(id);
      } catch (e) {
        if (e.status === 409) { already++; selected.delete(id); continue; }
        failed.push(`${rows.get(id).f.title}: ${e.message}`);
        if (e.status === 401 || e.status === 403) { stopped = true; break; }  // the rest would fail the same way
      }
    }
    posting = false;
    const out = [`Posted ${ok} of ${ids.length}.`];
    if (already) out.push(`${already} had already been posted.`);
    if (failed.length) out.push(`${stopped ? 'Stopped after an error' : `${failed.length} failed`}: ${failed.join('; ')}`);
    msg.textContent = out.join(' ');
    rows.forEach(r => { r.sig = ''; });  // redraw every row with its new posted state
    await refresh();
    syncAll();
  }

  async function act(fid, kind, btn) {
    const msg = btn.parentElement.querySelector('.act-msg');
    if (kind === 'dismiss' && !confirm('Dismiss this vulnerability in GitLab as a false positive? The model’s reasoning is added as the comment.')) return;
    if (kind === 'mr' && !confirm('Create a branch and open a merge request with this fix?')) return;
    btn.disabled = true; msg.textContent = 'Working…';
    try {
      const r = await api(`/api/findings/${fid}/${kind}`, { method: 'POST' });
      msg.innerHTML = kind === 'dismiss' ? 'Dismissed in GitLab.'
        : kind === 'mr' ? `Opened <a href="${esc(r.url)}" target="_blank" rel="noopener">merge request !${r.iid}</a>.`
        : `Posted on ${esc(r.where)}${r.url ? ` (<a href="${esc(r.url)}" target="_blank" rel="noopener">open</a>)` : ''}.`;
      rows.get(fid).sig = '';  // refresh the audit list on next poll
      refresh();
    } catch (e) {
      msg.textContent = e.message;
      if (e.status === 409 && kind === 'note') { rows.get(fid).sig = ''; refresh(); } else btn.disabled = false;
    }
  }

  function summary(fs) {
    const c = { true_positive: 0, false_positive: 0, needs_review: 0 };
    let done = 0, copied = 0, ran = 0, total = 0;
    fs.forEach(f => {
      if (modelRan(f)) { ran++; total += f.duration_s; }
      if (['done', 'skipped', 'error'].includes(f.status)) done++;
      if (c[f.verdict] !== undefined) c[f.verdict]++;
      if (f.copied_from && f.status === 'done') copied++;
    });
    $('summary').hidden = !fs.length;
    $('summary').innerHTML = `
      <div><b>${fs.length}</b><span>findings</span></div>
      <div class="s-real"><b>${c.true_positive}</b><span>real</span></div>
      <div class="s-review"><b>${c.needs_review}</b><span>need review</span></div>
      <div class="s-fp"><b>${c.false_positive}</b><span>false positives</span></div>
      <div><b>${done}/${fs.length}</b><span>analyzed</span></div>${
        ran ? `<div><b>${secs(total / ran)}</b><span>avg time per finding</span></div>` : ''}${
        copied ? `<div><b>${copied}</b><span>copied from earlier scans</span></div>` : ''}`;
    $('filters').hidden = !fs.length;
  }

  function render(j) {
    job = j;
    const st = $('job-status');
    st.textContent = j.status.charAt(0).toUpperCase() + j.status.slice(1);
    st.className = `state state-${j.status}`;
    $('job-progress').textContent = j.status === 'done' ? `Finished ${when(j.finished_at)}.` : j.progress || '';
    $('job-error').hidden = !j.error; $('job-error').textContent = j.error || '';
    $('cancel').hidden = !canAct || !['queued', 'running'].includes(j.status);
    $('rerun').hidden = ['queued', 'running'].includes(j.status);
    $('rerun-other').hidden = $('rerun').hidden;
    const failed = j.findings.filter(f => f.status === 'error').length;
    $('retry-failed').hidden = !canAct || !failed || ['queued', 'running'].includes(j.status);
    $('retry-failed').textContent = `Retry ${failed} failed`;
    $('download-report').hidden = !j.findings.length;
    summary(j.findings);
    const list = $('findings');
    if (!j.findings.length) {
      list.innerHTML = j.status === 'done' ? '<p class="empty">This commit has no SAST findings.</p>' : '';
      return;
    }
    if (list.querySelector('.empty')) list.innerHTML = '';
    for (const f of j.findings) {
      const sig = JSON.stringify(f);
      let r = rows.get(f.id);
      if (!r) { r = { el: rowEl(f), sig: '' }; rows.set(f.id, r); list.appendChild(r.el); }
      r.f = f;
      if (r.sig !== sig) { fill(r.el, f); r.sig = sig; }
    }
    updateBulk();
  }

  async function refresh() {
    clearTimeout(timer);
    try {
      const j = await api(`/api/jobs/${jobId}`);
      render(j);
      if (['queued', 'running'].includes(j.status)) timer = setTimeout(refresh, 3000);
    } catch (e) {
      $('job-error').hidden = false; $('job-error').textContent = e.message;
      timer = setTimeout(refresh, 10000);
    }
  }

  $('filters').addEventListener('click', e => {
    const b = e.target.closest('button[data-filter]'); if (!b) return;
    filter = b.dataset.filter;
    $('filters').querySelectorAll('button').forEach(x => x.setAttribute('aria-pressed', String(x === b)));
    rows.forEach(r => {
      r.el.hidden = filter !== 'all' && r.el.dataset.verdict !== filter;
      if (r.el.hidden) selected.delete(r.f.id);  // only post what is on screen
    });
    syncAll();
  });
  $('pick-all').addEventListener('change', e => {
    rows.forEach(r => {
      if (r.el.hidden || !eligible(r.f)) return;
      if (e.target.checked) selected.add(r.f.id); else selected.delete(r.f.id);
    });
    syncAll();
  });
  $('post-selected').addEventListener('click', postSelected);
  $('clear-sel').addEventListener('click', () => { selected.clear(); $('bulk-msg').textContent = ''; syncAll(); });
  $('cancel').addEventListener('click', async () => {
    if (!confirm('Cancel this analysis? Findings already analyzed are kept.')) return;
    await api(`/api/jobs/${jobId}/cancel`, { method: 'POST' }); refresh();
  });
  $('retry-failed').addEventListener('click', async () => {
    const btn = $('retry-failed'); btn.disabled = true;
    try {
      await api(`/api/jobs/${jobId}/retry-failed`, { method: 'POST' });
      rows.forEach(r => { r.sig = ''; });
      await refresh();
    } catch (e) { alert(e.message); }
    btn.disabled = false;
  });
  $('rerun').addEventListener('click', async () => {
    try { const r = await api(`/api/jobs/${jobId}/rerun`, { method: 'POST' }); location.href = `/jobs/${r.id}`; }
    catch (e) { alert(e.message); }
  });
  $('rerun-other').addEventListener('click', async () => {  // the same commit with the other thinking mode, to compare
    const thinking = $('rerun-other').dataset.thinking;
    try { const r = await api(`/api/jobs/${jobId}/rerun`, { method: 'POST', body: { thinking } }); location.href = `/jobs/${r.id}`; }
    catch (e) { alert(e.message); }
  });
  refresh();
})();
