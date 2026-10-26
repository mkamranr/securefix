(async () => {
  // Highlight the section in view in the side navigation.
  const links = [...document.querySelectorAll('.subnav a')];
  const mark = id => links.forEach(a => a.classList.toggle('active', a.getAttribute('href') === `#${id}`));
  if ('IntersectionObserver' in window) {
    const seen = new IntersectionObserver(es => es.forEach(e => { if (e.isIntersecting) mark(e.target.id); }),
      { rootMargin: '-80px 0px -60% 0px' });
    document.querySelectorAll('section.panel[id]').forEach(s => seen.observe(s));
  }

  // Model status and the served models for the Model field.
  const state = document.getElementById('llm-state');
  try {
    const h = await systemHealth(true);
    state.textContent = h.llm.ok ? 'Reachable' : 'Problem';
    state.className = `badge ${h.llm.ok ? 'badge-on' : ''}`;
    state.title = h.llm.detail || '';
    document.getElementById('llm-models').innerHTML = (h.llm.models || []).map(m => `<option value="${esc(m)}">`).join('');
  } catch (e) {
    state.textContent = 'Unknown';
    state.title = e.message;
  }
})();
