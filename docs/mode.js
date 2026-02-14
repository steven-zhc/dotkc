(() => {
  const KEY = 'dotkc-docs-guide';
  const buttons = Array.from(document.querySelectorAll('.mode-switch__btn'));

  function setGuide(next) {
    const g = next === 'agent' ? 'agent' : 'human';
    document.body.dataset.guide = g;
    try { localStorage.setItem(KEY, g); } catch {}

    for (const b of buttons) {
      const on = b.dataset.guide === g;
      b.classList.toggle('is-active', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    }
  }

  for (const b of buttons) {
    b.addEventListener('click', () => setGuide(b.dataset.guide));
  }

  const saved = (() => {
    try { return localStorage.getItem(KEY); } catch { return null; }
  })();

  setGuide(saved || 'human');
})();
