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
