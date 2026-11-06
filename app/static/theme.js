// Light, dark or system theme. Loaded in <head> without defer so the theme is set before the page paints.
(() => {
  const KEY = 'sf-theme', root = document.documentElement;
  const dark = window.matchMedia('(prefers-color-scheme: dark)');
  const read = () => { try { return localStorage.getItem(KEY) || 'system'; } catch (_) { return 'system'; } };
  const ICON = { system: 'device-desktop', light: 'sun', dark: 'moon' };

  function apply(choice) {
    root.dataset.bsTheme = choice === 'system' ? (dark.matches ? 'dark' : 'light') : choice;
    root.dataset.themeChoice = choice;
    document.querySelectorAll('[data-theme-choice]').forEach(b => {
      const on = b.dataset.themeChoice === choice;
      b.classList.toggle('active', on);
      b.setAttribute('aria-checked', String(on));
    });
    document.querySelectorAll('.theme-btn use').forEach(u => u.setAttribute('href', `/static/icons.svg#${ICON[choice]}`));
  }

  apply(read());
  dark.addEventListener('change', () => { if (read() === 'system') apply('system'); });
  document.addEventListener('DOMContentLoaded', () => {
    apply(read());
    document.addEventListener('click', e => {
      const b = e.target.closest('[data-theme-choice]');
      if (!b) return;
      try { localStorage.setItem(KEY, b.dataset.themeChoice); } catch (_) { /* storage unavailable: this page only */ }
      apply(b.dataset.themeChoice);
    });
  });
})();
