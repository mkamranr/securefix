(async () => {
  // Model status and the served models for the Model field (Local model page).
  const state = document.getElementById('llm-state');
  if (!state) return;
  try {
    const h = await systemHealth(true);
    state.textContent = h.llm.ok ? 'Reachable' : 'Problem';
    state.className = `badge ${h.llm.ok ? 'badge-on' : 'badge-bad'}`;
    state.title = h.llm.detail || '';
    document.getElementById('llm-models').innerHTML = (h.llm.models || []).map(m => `<option value="${esc(m)}">`).join('');
  } catch (e) {
    state.textContent = 'Unknown';
    state.title = e.message;
  }
})();

(() => {
  // Security team page: search a GitLab group, then tick the members who are assigned posted analyses.
  const form = document.getElementById('team-form');
  const search = document.getElementById('team-search');
  if (!form || !search) return;
  const $ = id => document.getElementById(id);
  const saved = new Set((form.dataset.members || '').split(',').filter(Boolean).map(Number));
  const msg = $('team-msg');

  async function loadMembers(id, path) {
    $('team-group-id').value = id; $('team-group-path').value = path;
    $('team-groups').hidden = true;
    $('team-members').hidden = true;
    msg.textContent = `Loading the members of ${path}…`;
    try {
      const members = await api(`/api/admin/gitlab/groups/${id}/members`);
      const keep = String(id) === form.dataset.groupId ? saved : new Set();
      $('team-group-name').textContent = path;
      $('team-member-list').innerHTML = members.map(m => `
        <label class="form-check">
          <input class="form-check-input" type="checkbox" name="member" value="${esc(m.id)}"${keep.has(m.id) ? ' checked' : ''}>
          <span class="form-check-label"><strong>${esc(m.name)}</strong> <span class="text-secondary">@${esc(m.username)}</span></span>
        </label>`).join('') || '<p class="text-secondary">This group has no active members.</p>';
      $('team-members').hidden = false;
      msg.textContent = `${members.length} active member${members.length === 1 ? '' : 's'}.`;
    } catch (e) { msg.textContent = e.message; }
  }

  async function findGroups() {
    msg.textContent = 'Searching…';
    try {
      const groups = await api(`/api/admin/gitlab/groups?search=${encodeURIComponent(search.value.trim())}`);
      const list = $('team-groups');
      list.innerHTML = groups.map(g => `<button type="button" class="list-group-item list-group-item-action" data-id="${esc(g.id)}" data-path="${esc(g.path)}">
        <strong>${esc(g.name)}</strong> <span class="text-secondary small">${esc(g.path)}</span></button>`).join('');
      list.hidden = !groups.length;
      msg.textContent = groups.length ? 'Pick the group.' : 'No groups found that your GitLab token can see.';
    } catch (e) { msg.textContent = e.message; }
  }

  $('team-search-btn').addEventListener('click', findGroups);
  search.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); findGroups(); } });
  $('team-groups').addEventListener('click', e => {
    const b = e.target.closest('button[data-id]');
    if (b) { search.value = b.dataset.path; loadMembers(b.dataset.id, b.dataset.path); }
  });
  form.addEventListener('submit', e => {
    if ($('team-members').hidden) { e.preventDefault(); msg.textContent = 'Pick a group and tick its members first.'; return; }
    if (!form.querySelector('input[name="member"]:checked')
        && !confirm('No one is ticked. Save anyway and clear the security team?')) e.preventDefault();
  });
  if (form.dataset.groupId) loadMembers(form.dataset.groupId, form.dataset.groupPath);
})();
