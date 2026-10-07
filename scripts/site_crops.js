// Real crops of the running console for the public sub-pages (frontend/media/real). Each crop is a
// region of one real panel, at 2x. Needs the stack running, puppeteer-core, and a console JWT.
// usage: ST_TOKEN_FILE=<file with a JWT> node scripts/site_crops.js <outdir> [name...]
const puppeteer = require('puppeteer-core'); const fs = require('fs');
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const TOKEN = fs.readFileSync(process.env.ST_TOKEN_FILE || __dirname + '/../token.txt', 'utf8').trim();
// find: JS returning the element to crop from; rect: [dx, dy, w, h] from that element's top-left (CSS px); prep: optional async JS run first
const head = (text) => `[...document.querySelectorAll('h1,h2,h3,h4,.card-title,.hd .t')].find(e => e.textContent.trim().toLowerCase().startsWith(${JSON.stringify(text.toLowerCase())}))`;
// climb from an element to the first ancestor at least this big (a heading to its card, a card to its board)
const up = (expr, minW, minH) => `(() => { let e = ${expr}; while (e && e.parentElement && (e.offsetWidth < ${minW} || e.offsetHeight < ${minH})) e = e.parentElement; return e; })()`;
const CROPS = {
  honeypots: { page: 'nodes.html', find: up(head('Sensors'), 600, 250), rect: [0, 0, 620, 340] },
  telemetry: { page: 'events.html', find: `document.querySelector('#hn-feed').closest('.hn-panel')`, rect: [0, 0, 620, 340] },
  geo: { page: 'geo.html', find: up(head('Top source locations'), 500, 250), rect: [0, 0, 620, 340], wait: 5000 },
  classify: { page: 'logs.html', find: `document.querySelector('#lg-kpis')`, rect: [0, 0, 500, 340] },
  rules: { page: 'validation.html', find: up(`[...document.querySelectorAll('.main-content *')].find(e => e.childElementCount === 0 && e.textContent.trim() === 'credential-attack')`, 900, 300), rect: [0, 0, 620, 340] },
  matrix: { page: 'mitre.html', find: up(`document.querySelector('.technique-card.active')`, 900, 250), rect: [0, 0, 620, 340] },
  malware: { page: 'malware.html', find: up(head('Threat family distribution'), 280, 250), rect: [0, 0, 620, 340], wait: 3500 },
  url: { page: 'urlscan.html', prep: `(async()=>{ document.querySelector('#urlInput').value='https://example.com'; document.querySelector('#scanBtn').click(); for(let i=0;i<200;i++){ await new Promise(r=>setTimeout(r,200)); if(!document.querySelector('#scanBtn').disabled) break; } })()`, find: up(head('Threat assessment'), 400, 330), rect: [0, 0, 620, 340], wait: 1200 },
  lab: { page: 'vm_lab.html', find: up(head('Kali Linux lab'), 520, 300), rect: [0, 0, 620, 262] },
  delivery: { page: 'credential_mgmt.html', find: up(head('Credential issuance form'), 600, 250), rect: [0, 0, 620, 340] },
  behaviour: { page: 'behavior.html', find: up(head('Behavioral relationship graph'), 500, 250), rect: [0, 0, 620, 340], wait: 3500 },
  actor: { page: 'behavior.html', find: up(head('Dominant threat actor'), 250, 200), rect: [0, 0, 620, 340], wait: 3500 },
  heatmap: { page: 'behavior.html', find: up(head('MITRE ATT&CK tactics heatmap'), 600, 150), rect: [0, 0, 620, 340], wait: 3500 },
  caseHero: { page: 'incidents.html', find: `document.querySelector('#inc-detail .hero')`, rect: [0, 0, 620, 340] },
  replay: { page: 'incidents.html', prep: `(async()=>{ document.querySelector('#act-replay').click(); await new Promise(r=>setTimeout(r,2600)); document.querySelector('#rp-play').click(); })()`, find: `document.querySelector('#rp')`, rect: [0, 0, 620, 340] },
  selfhosted: { page: 'nodes.html', find: `document.querySelector('.kpis, .kpi-strip, .hn-stats')`, rect: [0, 0, 620, 340] },
};
(async () => {
  const [out, ...only] = process.argv.slice(2); fs.mkdirSync(out, { recursive: true });
  const b = await puppeteer.launch({ executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', headless: true, args: ['--hide-scrollbars'] });
  for (const [name, c] of Object.entries(CROPS)) {
    if (only.length && !only.includes(name)) continue;
    const p = await b.newPage(); await p.setViewport({ width: 1440, height: 1000, deviceScaleFactor: 2 });
    await p.emulateMediaFeatures([{ name: 'prefers-color-scheme', value: 'light' }, { name: 'prefers-reduced-motion', value: 'reduce' }]);
    await p.evaluateOnNewDocument((tok) => { try { localStorage.setItem('st-theme', 'light'); localStorage.setItem('access_token', tok); localStorage.setItem('authToken', tok); } catch (e) {} }, TOKEN);
    try {
      await p.goto('http://127.0.0.1:5500/' + c.page, { waitUntil: 'networkidle2', timeout: 60000 }); await sleep(c.wait || 2500);
      if (c.prep) { await p.evaluate(c.prep); await sleep(c.wait || 800); }
      const r = await p.evaluate((find) => { const el = eval(find); el.scrollIntoView({ block: 'start' }); const m = document.querySelector('.main-content'); if (m) m.scrollTop -= 70; const r = el.getBoundingClientRect(); return { x: r.left, y: r.top, w: r.width, h: r.height }; }, c.find);
      await sleep(500);
      const r2 = await p.evaluate((find) => { const r = eval(find).getBoundingClientRect(); return { x: r.left, y: r.top, w: r.width, h: r.height }; }, c.find);
      const [dx, dy, w, h] = c.rect;
      await p.screenshot({ path: `${out}/${name}.png`, clip: { x: r2.x + dx, y: r2.y + dy, width: Math.min(w, r2.w - dx), height: h } });
      console.log(name.padEnd(11), 'element', Math.round(r2.w) + 'x' + Math.round(r2.h), '-> crop', Math.min(w, Math.round(r2.w - dx)) + 'x' + Math.min(h, Math.round(r2.h - dy)));
    } catch (e) { console.log(name.padEnd(11), 'FAILED', e.message.slice(0, 140)); }
    await p.close();
  }
  await b.close();
})();
