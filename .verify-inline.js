
    // Mobile menu
    const menuBtn = document.getElementById('menuBtn');
    const mobileMenu = document.getElementById('mobileMenu');
    menuBtn.addEventListener('click', () => mobileMenu.classList.toggle('hidden'));
    mobileMenu.querySelectorAll('a').forEach(a => a.addEventListener('click', () => mobileMenu.classList.add('hidden')));

    document.getElementById('year').textContent = new Date().getFullYear();
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // Typing effect
    const words = ['24/7 Threat Monitoring', 'Penetration Testing', 'Cloud Security Operations', 'Incident Response', 'Security Awareness Training'];
    const typed = document.getElementById('typed');
    let w = 0, c = 0, del = false;
    (function type() {
      const word = words[w];
      typed.textContent = word.slice(0, c);
      if (!del && c < word.length) c++;
      else if (!del) { del = true; return setTimeout(type, 1600); }
      else if (c > 0) c--;
      else { del = false; w = (w + 1) % words.length; }
      setTimeout(type, del ? 40 : 75);
    })();

    // Sliding video background
    const vids = [...document.querySelectorAll('.vslide')];
    const vdots = [...document.querySelectorAll('.vdot')];
    let vi = 0, vtimer;
    function showV(n) {
      vi = (n + vids.length) % vids.length;
      vids.forEach((v, i) => {
        v.classList.toggle('active', i === vi);
        if (i === vi) { v.play().catch(() => {}); } else { v.pause(); }
      });
      vdots.forEach((d, i) => d.classList.toggle('active', i === vi));
    }
    vdots.forEach((d, i) => d.addEventListener('click', () => { showV(i); restartV(); }));
    function restartV() { clearInterval(vtimer); if (!reduced) vtimer = setInterval(() => showV(vi + 1), 7000); }
    if (reduced) vids.forEach(v => v.pause()); else vids[0].play().catch(() => {});
    restartV();

    // Animated counters
    const cio = new IntersectionObserver((entries) => {
      entries.forEach(e => {
        if (!e.isIntersecting) return;
        const el = e.target, target = +el.dataset.target, suffix = el.dataset.suffix || '';
        const step = Math.max(1, Math.ceil(target / 50));
        let cur = 0;
        const id = setInterval(() => {
          cur += step;
          if (cur >= target) { cur = target; clearInterval(id); }
          el.textContent = cur + suffix;
        }, 30);
        cio.unobserve(el);
      });
    }, { threshold: 0.5 });
    document.querySelectorAll('.counter').forEach(el => cio.observe(el));

    // Scroll reveal
    const io = new IntersectionObserver((entries) => {
      entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); } });
    }, { threshold: 0.15 });
    document.querySelectorAll('.reveal').forEach(el => io.observe(el));

    // Live threat intelligence — talks only to our own server route
    const intelForm = document.getElementById('intelForm');
    const intelQuery = document.getElementById('intelQuery');
    const intelSubmit = document.getElementById('intelSubmit');
    const intelStatus = document.getElementById('intelStatus');
    const intelResults = document.getElementById('intelResults');

    function setIntelStatus(message, tone) {
      const tones = { info: 'text-slate-400', error: 'text-rose-300', empty: 'text-amber-300' };
      intelStatus.textContent = message || '';
      intelStatus.className = 'mt-6 max-w-3xl mx-auto text-sm ' + (tones[tone] || tones.info) + (message ? '' : ' hidden');
    }

    function renderIntelResult(result) {
      const card = document.createElement('article');
      card.className = 'rounded-2xl border border-line bg-panel p-5 hover:border-sky-400/60 transition';

      const link = document.createElement('a');
      link.href = result.url;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      link.className = 'text-base font-bold text-white hover:text-sky-300 transition break-words';
      link.textContent = result.title || result.url;
      card.appendChild(link);

      const meta = [];
      if (result.author) meta.push(result.author);
      if (result.publishedDate) meta.push(new Date(result.publishedDate).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }));
      meta.push(new URL(result.url).hostname.replace(/^www\./, ''));

      const metaLine = document.createElement('p');
      metaLine.className = 'mt-1 text-xs font-mono text-slate-500 break-words';
      metaLine.textContent = meta.join(' · ');
      card.appendChild(metaLine);

      (result.highlights || []).slice(0, 2).forEach((highlight) => {
        const passage = document.createElement('p');
        passage.className = 'mt-3 text-sm text-slate-300 leading-relaxed';
        passage.textContent = highlight;
        card.appendChild(passage);
      });

      const source = document.createElement('a');
      source.href = result.url;
      source.target = '_blank';
      source.rel = 'noopener noreferrer';
      source.className = 'mt-4 inline-flex items-center gap-1.5 text-sm font-semibold text-sky-400 hover:text-sky-300 transition';
      source.textContent = 'Read the source →';
      card.appendChild(source);

      return card;
    }

    async function runIntelSearch(rawQuery) {
      const query = rawQuery.trim().replace(/\s+/g, ' ');
      if (!query) {
        setIntelStatus('Type a topic, vulnerability or campaign to search for.', 'error');
        intelQuery.focus();
        return;
      }

      intelSubmit.disabled = true;
      intelResults.replaceChildren();
      setIntelStatus('Searching the web for “' + query + '”…', 'info');

      try {
        const response = await fetch('/api/threat-search?q=' + encodeURIComponent(query), { headers: { accept: 'application/json' } });
        let payload = {};
        try { payload = await response.json(); } catch (err) { payload = {}; }

        if (!response.ok) {
          setIntelStatus(payload.error || 'Threat search failed (HTTP ' + response.status + '). Please try again.', 'error');
          return;
        }

        const results = Array.isArray(payload.results) ? payload.results : [];
        if (!results.length) {
          setIntelStatus('No sources found for “' + query + '”. Try a broader or differently worded search.', 'empty');
          return;
        }

        intelResults.replaceChildren(...results.map(renderIntelResult));
        setIntelStatus(results.length + (results.length === 1 ? ' source' : ' sources') + ' found for “' + (payload.query || query) + '”.', 'info');
      } catch (err) {
        setIntelStatus('Could not reach the search service. Make sure the site is running through its server (npm start) and try again.', 'error');
      } finally {
        intelSubmit.disabled = false;
      }
    }

    intelForm.addEventListener('submit', (e) => {
      e.preventDefault();
      runIntelSearch(intelQuery.value);
    });

    // Newsletter
    const nl = document.getElementById('newsletter');
    nl.addEventListener('submit', (e) => {
      e.preventDefault();
      const email = nl.email.value.trim();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { nl.email.focus(); nl.email.classList.add('border-rose-500'); return; }
      nl.email.classList.remove('border-rose-500');
      document.getElementById('newsletterMsg').classList.remove('hidden');
      nl.reset();
    });
  