(() => {
  "use strict";

  // ============================== Utilities ==============================
  const $  = (sel, el=document) => el.querySelector(sel);
  const $$ = (sel, el=document) => Array.from(el.querySelectorAll(sel));

  const isHTTPS = location.protocol === "https:";

  const Cookies = {
    set(n, v, d=365, samesite='Lax'){
      let str = `${n}=${encodeURIComponent(v)}; Max-Age=${d*86400}; Path=/; SameSite=${samesite}`;
      if (isHTTPS) str += '; Secure';
      document.cookie = str;
    },
    get(n){
      const r = document.cookie.split('; ').find(r => r.startsWith(n+'='));
      return r ? decodeURIComponent(r.split('=')[1]) : undefined;
    },
    del(n){ document.cookie = `${n}=; Max-Age=0; Path=/; SameSite=Lax${isHTTPS?'; Secure':''}`; }
  };

  const Sec = {
    csrf(){
      const m = document.querySelector('meta[name="csrf-token"]');
      return m?.content;
    },
    headers(h={}){
      const out = { 'X-Requested-With':'fetch', ...h };
      const t = Sec.csrf(); if (t) out['X-CSRF-Token'] = t;
      return out;
    },
    // simple email hash (privacy friendly identifiers for analytics)
    async sha256(text){
      const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text||''));
      return [...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,'0')).join('');
    },
    // Robust beacon with fetch fallback (keepalive for unload)
    beacon(url, data){
      try {
        const blob = new Blob([JSON.stringify(data)], { type: 'application/json' });
        if (navigator.sendBeacon && navigator.sendBeacon(url, blob)) return true;
      } catch {}
      fetch(url, {
        method:'POST', credentials:'include', keepalive:true,
        headers:{ 'Content-Type':'application/json', ...Sec.headers() },
        body: JSON.stringify(data)
      }).catch(()=>{});
      return false;
    }
  };

  const consented = () => Cookies.get('roboai_cookie_consent') === 'accepted';

  // ============================== Header / Theme / Mobile Nav ==============================
  const header       = $('.site-header');
  const themeToggle  = $('#themeToggle');
  const mobileToggle = $('#navToggle');
  const mobileNav    = $('#mobileNav');

  const setHeaderScroll = () => header?.classList.toggle('is-scrolled', window.scrollY > 8);
  addEventListener('scroll', setHeaderScroll, { passive:true }); setHeaderScroll();

  const themeOrder = ['light','dark','system'];
  function applyTheme(v){
    try {
      if (v === 'system') {
        v = (window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light';
        document.documentElement.setAttribute('data-theme', v);
        // Live-update when OS theme changes and user pref is 'system'
        const mq = matchMedia('(prefers-color-scheme: dark)');
        if (!applyTheme._bound) {
          mq.addEventListener('change', () => {
            const pref = Cookies.get('roboai_theme');
            if (pref === 'system') {
              document.documentElement.setAttribute('data-theme', mq.matches ? 'dark':'light');
            }
          });
          applyTheme._bound = true;
        }
        return;
      }
      document.documentElement.setAttribute('data-theme', v);
    } catch(e) {}
  }
  function toggleTheme(){
    const cur = Cookies.get('roboai_theme') || 'light';
    const next = themeOrder[(themeOrder.indexOf(cur)+1) % themeOrder.length];
    // theme preference is a functional cookie (strictly necessary)
    Cookies.set('roboai_theme', next, 365);
    applyTheme(next);
    themeToggle?.setAttribute('aria-pressed', String(next==='dark'));
  }
  applyTheme( Cookies.get('roboai_theme') || 'system' );
  themeToggle?.addEventListener('click', toggleTheme);

  mobileToggle?.addEventListener('click', () => {
    const open = mobileNav?.hasAttribute('hidden') ? true : false;
    if (!mobileNav) return;
    if (open) mobileNav.removeAttribute('hidden'); else mobileNav.setAttribute('hidden','');
    mobileToggle.setAttribute('aria-expanded', String(open));
  });

  // ============================== Security: Frame-busting (best handled via CSP, but client hint) ==============================
  try { if (self !== top) top.location = self.location; } catch {}

  // ============================== Login / Logout with Session Tracking ==============================
  const loginBtn     = $('#loginBtn');
  const loginDialog  = $('#loginDialog');
  const loginForm    = $('#loginForm');
  const loginError   = $('#loginError');
  const loginClose   = $('#loginClose');
  const userBadge    = $('#userBadge');
  const rememberChk  = $('#remember');

  function nameFromEmail(email){ return (email||'').split('@')[0].replace(/[._-]/g, ' ').replace(/\\b\\w/g, s => s.toUpperCase()); }

  // Anti-abuse: throttle & lockout for login
  const SEC_KEY = 'roboai_login_sec';
  const secState = JSON.parse(localStorage.getItem(SEC_KEY) || '{"attempts":0,"lockUntil":0}');
  function saveSec(){ localStorage.setItem(SEC_KEY, JSON.stringify(secState)); }
  function locked() { return Date.now() < (secState.lockUntil||0); }
  function onFail(){
    secState.attempts = (secState.attempts||0) + 1;
    // exponential backoff: 1s,2s,4s,8s... up to 60s; after 5 fails, 10min lock
    const backoff = Math.min(60000, 1000 * Math.pow(2, Math.min(10, secState.attempts-1)));
    if (secState.attempts >= 5) secState.lockUntil = Date.now() + 10*60*1000; // 10 minutes
    else secState.lockUntil = Date.now() + backoff;
    saveSec();
  }
  function onSuccess(){ secState.attempts = 0; secState.lockUntil = 0; saveSec(); }

  // Session object (login time, id). Logged for DB analytics
  const SESS_KEY = 'roboai_session';
  function getSession(){ try { return JSON.parse(localStorage.getItem(SESS_KEY)||'null'); } catch { return null; } }
  function setSession(s){ localStorage.setItem(SESS_KEY, JSON.stringify(s)); }
  function clearSession(){ localStorage.removeItem(SESS_KEY); }

  // Restore display name if user chose remember
  const savedName = Cookies.get('roboai_user');
  if (savedName) switchToLogout(savedName);

  // Track form open time (basic bot-honeypot: min dwell time)
  let formOpenedAt = 0;
  loginBtn?.addEventListener('click', () => {
    if (loginBtn.id === 'logoutBtn'){
      performLogout('manual');
      return;
    }
    if (window.HTMLDialogElement && loginDialog?.showModal) { loginDialog.showModal(); formOpenedAt = performance.now(); }
    else location.href = '/login';
  });
  loginClose?.addEventListener('click', () => loginDialog?.close());

  async function performLogout(reason='logout'){
    // compute session duration & send to DB via beacon
    const sess = getSession();
    const logoutAt = Date.now();
    const loginAt  = sess?.loginAt || logoutAt;
    const durationMs = Math.max(0, logoutAt - loginAt);
    const payload = { event:'logout', reason, sessionId: sess?.id, loginAt, logoutAt, durationMs };
    Sec.beacon('/api/analytics/session', payload);
    // clear local state
    localStorage.removeItem('roboai_token'); Cookies.del('roboai_user'); clearSession();
    showUserBadge(null); location.reload();
  }

  loginForm?.addEventListener('submit', async (e) => {
    e.preventDefault(); if (loginError) loginError.textContent = '';

    if (locked()){
      const ms = Math.max(0, (secState.lockUntil||0) - Date.now());
      loginError && (loginError.textContent = `잠시 후 다시 시도하세요. 대기: ${Math.ceil(ms/1000)}초`);
      return;
    }

    const earliest = formOpenedAt + 800; // basic dwell-time protection
    if (performance.now() < earliest){
      await new Promise(r => setTimeout(r, Math.ceil(earliest - performance.now())));
    }

    // sanitize & validate
    const email = ( $('#email')?.value || '' ).trim();
    const pass  = ( $('#password')?.value || '' );
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)){
      loginError && (loginError.textContent = '이메일 형식이 올바르지 않습니다.'); return;
    }
    if (pass.length < 8){
      loginError && (loginError.textContent = '비밀번호는 최소 8자 이상이어야 합니다.'); return;
    }

    try {
      const r = await fetch('/api/auth/login', {
        method:'POST', credentials:'include',
        headers:{ 'Content-Type':'application/json', ...Sec.headers() },
        body: JSON.stringify({ email, password: pass })
      });
      if (r.ok){
        const { token, displayName, sessionId } = await r.json();
        localStorage.setItem('roboai_token', token);
        const display = displayName || nameFromEmail(email);
        if (rememberChk?.checked && consented()) Cookies.set('roboai_user', display, 365); // prefer consent
        loginDialog?.close(); switchToLogout(display); onSuccess();
        // create session entry for DB analytics
        const sid = sessionId || (crypto.randomUUID?.() || String(Math.random()).slice(2));
        const sess = { id: sid, loginAt: Date.now() };
        setSession(sess);
        // send login event
        const emailHash = await Sec.sha256(email.toLowerCase());
        Sec.beacon('/api/analytics/session', { event:'login', sessionId:sess.id, loginAt:sess.loginAt, emailHash });
        return;
      } else if (r.status === 429){
        loginError && (loginError.textContent = '요청이 너무 많습니다. 잠시 후 다시 시도하세요.');
      } else if (r.status === 401){
        onFail(); loginError && (loginError.textContent = '이메일 또는 비밀번호가 올바르지 않습니다.');
      } else {
        onFail(); loginError && (loginError.textContent = `로그인 실패: ${r.status}`);
      }
    } catch (err){
      // Offline fallback (demo account)
      if (email === 'demo@ai.dev' && pass === 'demo1234!'){
        localStorage.setItem('roboai_token', 'demo.'+Date.now());
        const display = nameFromEmail(email);
        if (rememberChk?.checked && consented()) Cookies.set('roboai_user', display, 365);
        loginDialog?.close(); switchToLogout(display); onSuccess();
        const sid = crypto.randomUUID?.() || String(Math.random()).slice(2);
        const sess = { id: sid, loginAt: Date.now() };
        setSession(sess);
        Sec.beacon('/api/analytics/session', { event:'login', sessionId:sess.id, loginAt:sess.loginAt, emailHash:'demo' });
        return;
      }
      onFail();
      loginError && (loginError.textContent = '네트워크 오류 또는 서버와의 통신 실패.');
    }
  });

  function switchToLogout(display){
    const btn = $('#loginBtn'); if (!btn) return;
    btn.textContent = '로그아웃'; btn.id = 'logoutBtn';
    showUserBadge(display);
    $('#logoutBtn')?.addEventListener('click', () => performLogout('manual'), { once:true });
  }
  function showUserBadge(name){
    if (!userBadge) return;
    if (name){ userBadge.textContent = `👤 ${name}`; userBadge.hidden = false; }
    else { userBadge.hidden = true; userBadge.textContent = ''; }
  }

  // Flush session on tab close
  addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden'){
      const sess = getSession();
      if (sess){
        const now = Date.now();
        Sec.beacon('/api/analytics/session', { event:'ping', sessionId:sess.id, elapsedMs: now - sess.loginAt });
      }
    }
  });

  // ============================== Prompt (rate-limited, secure) ==============================
  const providerSelect  = $('#providerSelect');
  const providerStatus  = $('#providerStatus');
  const promptInput     = $('#promptInput');
  const promptSend      = $('#promptSend');
  const promptOutput    = $('#promptOutput');
  const clearOutput     = $('#clearOutput');

  const autoResize = (ta) => { ta.style.height = 'auto'; ta.style.height = Math.min(240, ta.scrollHeight) + 'px'; };
  promptInput?.addEventListener('input', () => autoResize(promptInput));

  $$('.suggest').forEach(btn => btn.addEventListener('click', () => {
    promptInput.value = btn.dataset.example || ''; autoResize(promptInput); sendPrompt();
  }));

  promptInput?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey){ e.preventDefault(); sendPrompt(); }
  });

  promptSend?.addEventListener('click', sendPrompt);
  clearOutput?.addEventListener('click', () => { if (promptOutput) promptOutput.textContent = ''; });

  function typedEffect(target, text, speed=14){
    return new Promise((resolve) => {
      if (!target) return resolve();
      target.textContent = ''; let i = 0;
      const id = setInterval(() => {
        target.textContent += text[i++] || '';
        if (i >= text.length){ clearInterval(id); resolve(); }
      }, speed);
    });
  }

  function demoReply(q){
    const l = (q||'').trim().toLowerCase();
    if (!l) return '질문을 입력해주세요.';
    if (l.includes('mysql')) return 'MySQL 슬로우 쿼리 튜닝 체크리스트:\\n1) EXPLAIN 실행계획 확인\\n2) WHERE 컬럼 인덱싱\\n3) LIMIT + 정렬키 최적화\\n4) N+1 조인 제거\\n5) 커버링 인덱스';
    if (l.includes('면접')) return '주니어 백엔드 면접 10문:\\n- HTTP 상태코드\\n- 트랜잭션 격리수준\\n- B+Tree 인덱스…';
    if (l.includes('여행') || l.includes('제주')) return '3일 제주 코스(요약): Day1 남부 / Day2 동부 / Day3 한라산.';
    return `요청 정리:\\n- 주제: ${q}\\n- 핵심: 포인트 3~5개로 구조화\\n- 필요 시 코드/SQL 예시 포함`;
  }

  const auth = () => {
    const t = localStorage.getItem('roboai_token'); return t ? { Authorization: 'Bearer '+t } : {};
  };
  let inflight;

  // Rate limit: 10 requests / minute
  let promptTimes = [];
  function canSendNow(){
    const now = Date.now();
    promptTimes = promptTimes.filter(t => now - t < 60000);
    if (promptTimes.length >= 10) return false;
    promptTimes.push(now); return true;
  }

  async function sendPrompt(){
    const q = promptInput?.value.trim(); if (!q) return;

    if (!canSendNow()){
      providerStatus && (providerStatus.textContent = '요청 과다: 1분 후 재시도');
      return;
    }

    const mode = providerSelect?.value || 'demo';
    if (providerStatus) providerStatus.textContent = (mode==='demo' ? '로컬 데모' : '백엔드 호출 중…');

    if (mode === 'demo'){
      const ans = demoReply(q); await typedEffect(promptOutput, ans);
      if (providerStatus) providerStatus.textContent = '완료'; return;
    }

    try {
      if (inflight) inflight.abort();
      inflight = new AbortController();
      const r = await fetch('/api/free-gpt', {
        method:'POST', credentials:'include',
        headers:{ 'Content-Type':'application/json', ...Sec.headers(), ...auth() },
        body: JSON.stringify({ query:q }),
        signal: inflight.signal
      });
      if (!r.ok) throw new Error('응답 오류 '+r.status);
      const t = await r.text();
      await typedEffect(promptOutput, t);
      if (providerStatus) providerStatus.textContent = '완료';
    } catch (e){
      if (providerStatus) providerStatus.textContent = '실패(데모 폴백 사용)';
      const ans = demoReply(q); await typedEffect(promptOutput, ans);
    } finally {
      inflight = null;
    }
  }

  // Hero prompt → main prompt
  const heroForm  = $('#heroPrompt');
  const heroInput = $('#heroPromptInput');
  heroForm?.addEventListener('submit', (e) => {
    e.preventDefault();
    const q = heroInput?.value.trim(); if (!q) return;
    const ta = $('#promptInput'); ta.value = q; ta.dispatchEvent(new Event('input'));
    const sel = $('#providerSelect'); if (sel) sel.value = 'demo';
    document.getElementById('prompt').scrollIntoView({ behavior:'smooth', block:'start' });
    setTimeout(() => document.getElementById('promptSend')?.click(), 200);
  });

  // ============================== Modern UX: View Transitions / IO ==============================
  if ('startViewTransition' in document){
    $$('a[href^="#"]').forEach(a => {
      a.addEventListener('click', (e) => {
        const id = a.getAttribute('href'); const t = id && $(id);
        if (!t) return; e.preventDefault();
        document.startViewTransition(() => { t.scrollIntoView({ behavior:'smooth', block:'start' }); });
      });
    });
  }

  const io = ('IntersectionObserver' in window)
    ? new IntersectionObserver((entries)=>{ entries.forEach(e => { if (e.isIntersecting) e.target.classList.add('is-visible'); }); }, { threshold:.15 })
    : null;
  io && $$('.card,.price-card,.section__title').forEach(el => io.observe(el));

  // ============================== Global Cursor Reactions (all items) ==============================
  // 1) CSS variables for light direction
  addEventListener('pointermove', (e) => {
    const x = e.clientX / innerWidth, y = e.clientY / innerHeight;
    document.documentElement.style.setProperty('--mx', x.toFixed(4));
    document.documentElement.style.setProperty('--my', y.toFixed(4));
  }, { passive:true });

  // 2) Pressable hover-highlights
  function attachPressable(el){
    const update = (ev) => {
      const r  = el.getBoundingClientRect();
      const rx = ((ev.clientX - r.left) / r.width) * 100;
      const ry = ((ev.clientY - r.top) / r.height) * 100;
      el.style.setProperty('--rx', rx + '%'); el.style.setProperty('--ry', ry + '%');
    };
    el.addEventListener('pointerenter', (e) => { el.classList.add('is-hover'); update(e); });
    el.addEventListener('pointermove', update);
    el.addEventListener('pointerleave', () => { el.classList.remove('is-hover'); el.style.removeProperty('--rx'); el.style.removeProperty('--ry'); });
    el.addEventListener('pointerdown', () => el.classList.add('is-pressed'));
    addEventListener('pointerup',   () => el.classList.remove('is-pressed'));
  }
  $$('.pressable,.btn,.card,.price-card,.nav__link,.nav-mobile__link,.scrolly__thumb').forEach(attachPressable);

  // 3) 3D tilt (GPU)
  const prefersReduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (!prefersReduced){
    const maxAngle = 8, maxShift = 8;
    $$('.tilt,.card,.price-card').forEach(el => {
      let raf = 0;
      const depth = Number(el.getAttribute('data-tilt-depth') || 8);
      const onMove = (ev) => {
        cancelAnimationFrame(raf);
        raf = requestAnimationFrame(() => {
          const r = el.getBoundingClientRect();
          const x = (ev.clientX - r.left) / r.width;
          const y = (ev.clientY - r.top) / r.height;
          const ty = (x - .5) * (maxAngle * depth / 10);
          const tx = -(y - .5) * (maxAngle * depth / 10);
          const px = (x - .5) * (maxShift * depth / 10);
          const py = (y - .5) * (maxShift * depth / 10);
          el.style.setProperty('--ty', ty + 'deg');
          el.style.setProperty('--tx', tx + 'deg');
          el.style.setProperty('--px', px + 'px');
          el.style.setProperty('--py', py + 'px');
        });
      };
      el.addEventListener('pointermove', onMove);
      el.addEventListener('pointerleave', () => { el.style.removeProperty('--ty'); el.style.removeProperty('--tx'); el.style.removeProperty('--px'); el.style.removeProperty('--py'); });
    });
  }

  // 4) Magnetic micro-interactions (buttons/cards)
  const MAGNET_RANGE    = 140;
  const MAGNET_STRENGTH = .15;
  const magnets = $$('.btn,.card,.price-card');
  addEventListener('pointermove', (e) => {
    if (prefersReduced) return;
    magnets.forEach(el => {
      const r  = el.getBoundingClientRect();
      const cx = r.left + r.width/2, cy = r.top + r.height/2;
      const dx = e.clientX - cx,      dy = e.clientY - cy;
      const dist = Math.hypot(dx,dy);
      if (dist < MAGNET_RANGE){
        const nx = dx/dist, ny = dy/dist;
        const tx = nx*(MAGNET_RANGE - dist)*MAGNET_STRENGTH;
        const ty = ny*(MAGNET_RANGE - dist)*MAGNET_STRENGTH;
        el.animate([{ transform:`translate(${tx}px, ${ty}px)` }], { duration:120, fill:'forwards', easing:'ease-out' });
      } else {
        el.animate([{ transform:'translate(0,0)' }], { duration:180, fill:'forwards', easing:'ease-out' });
      }
    });
  }, { passive:true });

  // 5) Cursor particles (Canvas, light performance)
  const reduceMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const canvas = $('#cursorFX');
  if (canvas && !reduceMotion){
    const ctx = canvas.getContext('2d', { alpha: true });
    const DPR = Math.max(1, Math.min(2, devicePixelRatio || 1));
    let w = 0, h = 0;
    function resize(){
      w = canvas.clientWidth = innerWidth;
      h = canvas.clientHeight = innerHeight;
      canvas.width  = Math.floor(w * DPR);
      canvas.height = Math.floor(h * DPR);
      ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    }
    addEventListener('resize', resize, { passive: true }); resize();

    const pool = [];
    const make = (x, y) => ({ x, y, vx:(Math.random()-.5)*1.2, vy:(Math.random()-.5)*1.2, life:1 });
    let last = 0;

    addEventListener('pointermove', (e) => {
      const now = performance.now();
      if (now - last < 12) return; last = now;
      const r = canvas.getBoundingClientRect();
      const x = e.clientX - r.left, y = e.clientY - r.top;
      for (let i=0;i<4;i++) pool.push(make(x,y));
    }, { passive: true });

    function tick(){
      ctx.clearRect(0,0,w,h);
      ctx.globalCompositeOperation = 'lighter';
      for (let i = pool.length - 1; i >= 0; i--){
        const p = pool[i];
        p.x += p.vx; p.y += p.vy; p.life -= .02;
        if (p.life <= 0){ pool.splice(i,1); continue; }
        const rad = 2 + (1-p.life)*2;
        const g = ctx.createRadialGradient(p.x,p.y,0,p.x,p.y,rad*2);
        g.addColorStop(0,'rgba(6,182,212,0.35)');
        g.addColorStop(1,'rgba(6,182,212,0)');
        ctx.fillStyle = g;
        ctx.beginPath(); ctx.arc(p.x,p.y,rad,0,Math.PI*2); ctx.fill();
      }
      requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  // Scroll behavior for right rail on mobile
  const scrolly     = $('#scrolly');
  const scrollyRail = $('#scrollyRail');
  if (scrolly && scrollyRail){
    scrolly.addEventListener('wheel', (e) => {
      if (innerWidth >= 1200) return;
      const atTop    = scrollyRail.scrollTop <= 0;
      const atBottom = Math.ceil(scrollyRail.scrollTop + scrollyRail.clientHeight) >= scrollyRail.scrollHeight;
      const goingDown = e.deltaY > 0;
      const canDown = !atBottom && goingDown;
      const canUp   = !atTop && !goingDown;
      if (canDown || canUp){ scrollyRail.scrollTop += e.deltaY; e.preventDefault(); }
    }, { passive:false });
  }

  // ============================== Cookies & Consent ==============================
  const cookieBanner = $('#cookieBanner');
  const cookieAccept = $('#cookieAccept');
  const cookieReject = $('#cookieReject');
  const consent = Cookies.get('roboai_cookie_consent');
  if (!consent && cookieBanner) cookieBanner.hidden = false;
  cookieAccept?.addEventListener('click', () => { Cookies.set('roboai_cookie_consent', 'accepted', 180); cookieBanner.hidden = true; });
  cookieReject?.addEventListener('click', () => { Cookies.set('roboai_cookie_consent', 'rejected', 180); cookieBanner.hidden = true; });

  // Security Policy monitoring (optional telemetry)
  addEventListener('securitypolicyviolation', (e) => {
    Sec.beacon('/api/security/csp-violation', {
      blockedURI: e.blockedURI, violatedDirective: e.violatedDirective, lineNumber: e.lineNumber, columnNumber: e.columnNumber
    });
  });

  // Footer year
  const year = $('#year'); if (year) year.textContent = new Date().getFullYear();
})();