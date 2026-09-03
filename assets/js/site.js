(function () {
  const toggle = document.querySelector('.menu-toggle');
  const menu = document.querySelector('.nav-links');

  if (!toggle || !menu) return;

  const navLinks = menu.querySelectorAll('a');
  const defaultActiveLink = menu.querySelector('a.active');
  const connectLink = menu.querySelector('[data-nav="connect"]');

  const syncActiveNavigation = () => {
    navLinks.forEach((link) => {
      link.classList.remove('active');
      link.removeAttribute('aria-current');
    });

    if (window.location.hash === '#contact' && connectLink) {
      connectLink.classList.add('active');
      connectLink.setAttribute('aria-current', 'location');
    } else if (defaultActiveLink) {
      defaultActiveLink.classList.add('active');
      defaultActiveLink.setAttribute('aria-current', 'page');
    }
  };

  const closeMenu = () => {
    toggle.setAttribute('aria-expanded', 'false');
    document.body.classList.remove('menu-open');
  };

  toggle.addEventListener('click', () => {
    const opening = toggle.getAttribute('aria-expanded') !== 'true';
    toggle.setAttribute('aria-expanded', String(opening));
    document.body.classList.toggle('menu-open', opening);
  });

  menu.addEventListener('click', closeMenu);
  window.addEventListener('hashchange', syncActiveNavigation);
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') closeMenu();
  });

  syncActiveNavigation();
})();
