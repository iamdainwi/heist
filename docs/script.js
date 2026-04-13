/* ═══════════════════════════════════════════════════════════════════════════
   heist — Landing Page Interactions
   Terminal typing, scroll reveals, tab switching, copy-to-clipboard.
   ═══════════════════════════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {
  initNavScroll();
  initMobileNav();
  initScrollReveal();
  initTerminalTyping();
  initCommandTabs();
  initCopyButtons();
  initCountUp();
});

/* ── Navbar scroll effect ──────────────────────────────────────────────── */

function initNavScroll() {
  const nav = document.querySelector('.nav');
  if (!nav) return;

  const update = () => {
    nav.classList.toggle('scrolled', window.scrollY > 40);
  };
  window.addEventListener('scroll', update, { passive: true });
  update();
}

/* ── Mobile nav toggle ─────────────────────────────────────────────────── */

function initMobileNav() {
  const toggle = document.querySelector('.nav-mobile-toggle');
  const links = document.querySelector('.nav-links');
  if (!toggle || !links) return;

  toggle.addEventListener('click', () => {
    links.classList.toggle('open');
    const spans = toggle.querySelectorAll('span');
    toggle.classList.toggle('active');
  });

  links.querySelectorAll('a').forEach(a => {
    a.addEventListener('click', () => links.classList.remove('open'));
  });
}

/* ── Scroll reveal (Intersection Observer) ─────────────────────────────── */

function initScrollReveal() {
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('visible');
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.1, rootMargin: '0px 0px -40px 0px' }
  );

  document.querySelectorAll('.reveal').forEach(el => observer.observe(el));
}

/* ── Terminal typing animation ─────────────────────────────────────────── */

function initTerminalTyping() {
  const terminal = document.getElementById('hero-terminal');
  if (!terminal) return;

  const scenes = [
    [
      { type: 'cmd', prompt: '$ ', text: 'heist init', delay: 60 },
      { type: 'output', text: 'Enter master password: ************', delay: 20 },
      { type: 'output', text: 'Confirm master password: ************', delay: 20 },
      { type: 'success', text: '✓ Vault created at ~/.heist/vault.heist', delay: 20 },
      { type: 'empty' },
      { type: 'cmd', prompt: '$ ', text: 'heist set aws/access-key --tags "aws,prod"', delay: 50 },
      { type: 'output', text: 'Enter secret value: ************', delay: 20 },
      { type: 'output', text: 'Master password: ************', delay: 20 },
      { type: 'success', text: "✓ Stored secret 'aws/access-key'", delay: 20 },
      { type: 'empty' },
      { type: 'cmd', prompt: '$ ', text: 'heist get aws/access-key', delay: 50 },
      { type: 'output', text: 'Master password: ************', delay: 20 },
      { type: 'value', text: 'AKIAIOSFODNN7EXAMPLE', delay: 20 },
    ],
    [
      { type: 'cmd', prompt: '$ ', text: 'heist list', delay: 60 },
      { type: 'output', text: 'Master password: ************', delay: 20 },
      { type: 'empty' },
      { type: 'table-header', text: ' KEY                  TAGS        UPDATED' },
      { type: 'table-sep',    text: '─────────────────────────────────────────────' },
      { type: 'table-row',    text: ' aws/prod/access-key  aws, prod   2026-04-13' },
      { type: 'table-row',    text: ' aws/prod/secret-key  aws, prod   2026-04-13' },
      { type: 'table-row',    text: ' database/prod/url    db, prod    2026-04-12' },
      { type: 'table-row',    text: ' github/token         github      2026-04-11' },
      { type: 'empty' },
      { type: 'output', text: '  4 secrets' },
      { type: 'empty' },
      { type: 'cmd', prompt: '$ ', text: 'heist exec aws/prod/access-key -- terraform apply', delay: 50 },
      { type: 'success', text: '✓ Injected AWS_PROD_ACCESS_KEY into subprocess', delay: 20 },
    ],
  ];

  let sceneIndex = 0;

  async function playScene(scene) {
    const body = terminal.querySelector('.terminal-body');
    body.innerHTML = '';

    for (let i = 0; i < scene.length; i++) {
      const step = scene[i];
      const line = document.createElement('div');
      line.className = 'terminal-line';
      line.style.animationDelay = `${i * 0.05}s`;

      if (step.type === 'empty') {
        line.innerHTML = '&nbsp;';
      } else if (step.type === 'cmd') {
        const promptSpan = `<span class="terminal-prompt">${step.prompt}</span>`;
        line.innerHTML = promptSpan;
        body.appendChild(line);
        await typeText(line, step.text, step.delay || 50, 'terminal-cmd');
        await sleep(300);
        continue;
      } else if (step.type === 'success') {
        line.innerHTML = `<span class="terminal-success">${escapeHtml(step.text)}</span>`;
      } else if (step.type === 'value') {
        line.innerHTML = `<span class="terminal-value">${escapeHtml(step.text)}</span>`;
      } else if (step.type === 'table-header') {
        line.innerHTML = `<span class="terminal-key">${escapeHtml(step.text)}</span>`;
      } else if (step.type === 'table-sep') {
        line.innerHTML = `<span class="terminal-comment">${step.text}</span>`;
      } else if (step.type === 'table-row') {
        line.innerHTML = `<span class="terminal-output">${escapeHtml(step.text)}</span>`;
      } else {
        line.innerHTML = `<span class="terminal-output">${escapeHtml(step.text)}</span>`;
      }

      body.appendChild(line);
      await sleep(step.delay || 80);
    }

    // Blinking cursor at the end.
    const cursorLine = document.createElement('div');
    cursorLine.className = 'terminal-line';
    cursorLine.style.animationDelay = '0s';
    cursorLine.innerHTML = `<span class="terminal-prompt">$ </span><span class="terminal-cursor"></span>`;
    body.appendChild(cursorLine);

    await sleep(4000);

    sceneIndex = (sceneIndex + 1) % scenes.length;
    playScene(scenes[sceneIndex]);
  }

  // Start once the terminal is in view.
  const observer = new IntersectionObserver(
    (entries) => {
      if (entries[0].isIntersecting) {
        observer.disconnect();
        playScene(scenes[0]);
      }
    },
    { threshold: 0.3 }
  );
  observer.observe(terminal);
}

function typeText(parent, text, delay, className) {
  return new Promise(resolve => {
    const span = document.createElement('span');
    span.className = className;
    parent.appendChild(span);

    let i = 0;
    const cursor = document.createElement('span');
    cursor.className = 'terminal-cursor';
    parent.appendChild(cursor);

    const interval = setInterval(() => {
      if (i < text.length) {
        span.textContent += text[i];
        i++;
      } else {
        clearInterval(interval);
        cursor.remove();
        resolve();
      }
    }, delay);
  });
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

/* ── Command tabs ──────────────────────────────────────────────────────── */

function initCommandTabs() {
  const tabs = document.querySelectorAll('.cmd-tab');
  const panels = document.querySelectorAll('.cmd-panel');

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const target = tab.dataset.tab;

      tabs.forEach(t => t.classList.remove('active'));
      panels.forEach(p => p.classList.remove('active'));

      tab.classList.add('active');
      document.getElementById(`panel-${target}`)?.classList.add('active');
    });
  });
}

/* ── Copy to clipboard ─────────────────────────────────────────────────── */

function initCopyButtons() {
  document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const cmd = btn.closest('.install-cmd');
      const text = cmd?.querySelector('.cmd-text')?.textContent?.trim();
      if (!text) return;

      navigator.clipboard.writeText(text).then(() => {
        const original = btn.textContent;
        btn.textContent = '✓';
        btn.style.color = 'var(--accent-green)';
        setTimeout(() => {
          btn.textContent = original;
          btn.style.color = '';
        }, 2000);
      });
    });
  });
}

/* ── Count-up animation for stats ──────────────────────────────────────── */

function initCountUp() {
  const stats = document.querySelectorAll('[data-count]');
  if (!stats.length) return;

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const el = entry.target;
          const target = parseInt(el.dataset.count, 10);
          const suffix = el.dataset.suffix || '';
          animateCount(el, 0, target, 1500, suffix);
          observer.unobserve(el);
        }
      });
    },
    { threshold: 0.5 }
  );

  stats.forEach(el => observer.observe(el));
}

function animateCount(el, start, end, duration, suffix) {
  const range = end - start;
  const startTime = performance.now();

  function step(now) {
    const elapsed = now - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(start + range * eased) + suffix;
    if (progress < 1) requestAnimationFrame(step);
  }

  requestAnimationFrame(step);
}
