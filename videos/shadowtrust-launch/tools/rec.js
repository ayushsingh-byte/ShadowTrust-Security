// Screen recorder for the launch video: drives the real console in headless Chrome and records it.
// Frames come from the DevTools screencast (about 60 fps, CSS-pixel size), with a drawn cursor so
// clicks can be followed. Nothing on the page is altered except that cursor overlay.
const puppeteer = require('puppeteer-core');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const W = 1440, H = 810;
const TOKEN = fs.readFileSync(path.join(__dirname, '..', 'token.txt'), 'utf8').trim();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const OPEN = []; // every browser opened, so a failed scene can still be cleaned up
const closeAll = async () => { while (OPEN.length) await OPEN.pop().close().catch(() => {}); };
const ease = (k) => (k < 0.5 ? 4 * k * k * k : 1 - Math.pow(-2 * k + 2, 3) / 2);

async function open(pagePath, { cursor = true, dark = false } = {}) {
    const browser = await puppeteer.launch({
        executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        headless: true,
        args: ['--hide-scrollbars', `--window-size=${W},${H}`],
    });
    OPEN.push(browser);
    const page = await browser.newPage();
    await page.setViewport({ width: W, height: H, deviceScaleFactor: 1 });
    await page.emulateMediaFeatures([{ name: 'prefers-color-scheme', value: dark ? 'dark' : 'light' }]);
    await page.evaluateOnNewDocument((tok, dark) => {
        localStorage.setItem('st-theme', dark ? 'dark' : 'light');
        localStorage.setItem('access_token', tok);
        localStorage.setItem('authToken', tok);
    }, TOKEN, dark);
    const errors = [];
    page.on('pageerror', (e) => errors.push(e.message.slice(0, 140)));
    await page.goto('http://127.0.0.1:5500/' + pagePath, { waitUntil: 'networkidle2', timeout: 60000 }).catch((e) => errors.push('GOTO ' + e.message));

    const s = { browser, page, errors, x: W * 0.7, y: H * 0.45, marks: [], frames: [], dir: null, cdp: null };

    if (cursor) {
        await page.evaluate((x, y) => {
            const c = document.createElement('div');
            c.id = '__rec_cursor';
            c.style.cssText = 'position:fixed;left:0;top:0;width:24px;height:24px;z-index:2147483647;pointer-events:none;will-change:transform;transform:translate(' + x + 'px,' + y + 'px)';
            c.innerHTML = '<svg viewBox="0 0 24 24" width="24" height="24"><path d="M4.5 2.5 19 11.2l-6.4 1.5-2.9 6.3Z" fill="#061B31" stroke="#fff" stroke-width="1.6" stroke-linejoin="round"/></svg>';
            document.documentElement.appendChild(c);
            const st = document.createElement('style');
            st.textContent = '@keyframes __rec_ring{from{transform:translate(-50%,-50%) scale(.3);opacity:.55}to{transform:translate(-50%,-50%) scale(1.5);opacity:0}}';
            document.documentElement.appendChild(st);
            document.addEventListener('mousemove', (e) => { c.style.transform = 'translate(' + e.clientX + 'px,' + e.clientY + 'px)'; }, true);
            document.addEventListener('mousedown', (e) => {
                const r = document.createElement('div');
                r.style.cssText = 'position:fixed;left:' + e.clientX + 'px;top:' + e.clientY + 'px;width:44px;height:44px;border-radius:50%;border:3px solid #533AFD;z-index:2147483646;pointer-events:none;animation:__rec_ring .5s ease-out forwards';
                document.documentElement.appendChild(r);
                setTimeout(() => r.remove(), 600);
            }, true);
        }, s.x, s.y);
        await page.mouse.move(s.x, s.y);
    }

    s.sleep = sleep;
    s.mark = (label) => { const t = s.frames.length ? Date.now() / 1000 - s.frames[0].t : 0; s.marks.push([+t.toFixed(2), label]); };

    s.moveTo = async (x, y, ms = 700) => {
        const x0 = s.x, y0 = s.y, steps = Math.max(2, Math.round(ms / 16));
        for (let i = 1; i <= steps; i++) {
            const k = ease(i / steps);
            await page.mouse.move(x0 + (x - x0) * k, y0 + (y - y0) * k);
            await sleep(12);
        }
        s.x = x; s.y = y;
    };
    s.centre = (sel, index = 0) => page.evaluate((sel, index) => {
        const el = document.querySelectorAll(sel)[index];
        if (!el) return null;
        const r = el.getBoundingClientRect();
        return { x: r.left + r.width / 2, y: r.top + r.height / 2, w: r.width, h: r.height };
    }, sel, index);
    s.moveToEl = async (sel, ms = 700, index = 0, dx = 0, dy = 0) => {
        const c = await s.centre(sel, index);
        if (!c) throw new Error('no element ' + sel);
        await s.moveTo(c.x + dx, c.y + dy, ms);
        return c;
    };
    s.click = async (sel, ms = 700, index = 0) => {
        await s.moveToEl(sel, ms, index);
        await sleep(140);
        await page.mouse.down(); await sleep(70); await page.mouse.up();
    };
    s.drag = async (x1, y1, x2, y2, ms = 1400) => {
        await s.moveTo(x1, y1, 500);
        await page.mouse.down();
        await s.moveTo(x2, y2, ms);
        await page.mouse.up();
    };
    s.type = async (text, delay = 70) => { await page.keyboard.type(text, { delay }); };
    s.key = (k) => page.keyboard.press(k);
    // smooth scroll of the console's own scroller (the console scrolls inside .main-content)
    s.scroll = (dy, ms = 900, sel = '.main-content') => page.evaluate((dy, ms, sel) => new Promise((res) => {
        const el = document.querySelector(sel) || document.scrollingElement;
        const y0 = el.scrollTop, t0 = performance.now();
        (function step(now) {
            const k = Math.min(1, (now - t0) / ms);
            const e = k < 0.5 ? 4 * k * k * k : 1 - Math.pow(-2 * k + 2, 3) / 2;
            el.scrollTop = y0 + dy * e;
            if (k < 1) requestAnimationFrame(step); else res();
        })(t0);
    }), dy, ms, sel);
    s.scrollTo = (top, sel = '.main-content') => page.evaluate((top, sel) => { (document.querySelector(sel) || document.scrollingElement).scrollTop = top; }, top, sel);
    // fire one of the product's own honeypot triggers (real traffic at the lab's sensors)
    s.fire = (id) => fetch('http://127.0.0.1:8000/api/v1/admin/diagnostics/trigger/' + id, { method: 'POST', headers: { Authorization: 'Bearer ' + TOKEN } })
        .then((r) => r.status).catch((e) => 'ERR ' + e.message);
    s.waitFor = async (fn, timeout = 30000, arg) => {
        const t0 = Date.now();
        while (Date.now() - t0 < timeout) { if (await page.evaluate(fn, arg).catch(() => false)) return true; await sleep(150); }
        return false;
    };

    s.start = async (dir) => {
        dir = path.resolve(dir); // the frame list needs absolute paths
        s.dir = dir; fs.rmSync(dir, { recursive: true, force: true }); fs.mkdirSync(dir, { recursive: true });
        s.cdp = await page.createCDPSession();
        s.cdp.on('Page.screencastFrame', (f) => {
            const file = path.join(dir, 'f' + String(s.frames.length).padStart(6, '0') + '.jpg');
            fs.writeFileSync(file, Buffer.from(f.data, 'base64'));
            s.frames.push({ file, t: f.metadata.timestamp });
            s.cdp.send('Page.screencastFrameAck', { sessionId: f.sessionId }).catch(() => {});
        });
        await s.cdp.send('Page.startScreencast', { format: 'jpeg', quality: 96, everyNthFrame: 1 });
        await sleep(120);
    };

    // stop and encode to a constant 30 fps master at the capture size
    s.stop = async (outMp4) => {
        outMp4 = path.resolve(outMp4);
        await sleep(150);
        await s.cdp.send('Page.stopScreencast').catch(() => {});
        await sleep(200);
        const fr = s.frames;
        if (fr.length < 2) throw new Error('no frames recorded');
        const lines = ['ffconcat version 1.0'];
        for (let i = 0; i < fr.length; i++) {
            const d = i < fr.length - 1 ? Math.max(0.001, fr[i + 1].t - fr[i].t) : 0.4;
            lines.push("file '" + fr[i].file + "'", 'duration ' + d.toFixed(4));
        }
        lines.push("file '" + fr[fr.length - 1].file + "'");
        const list = path.join(s.dir, 'list.txt'); fs.writeFileSync(list, lines.join('\n'));
        execFileSync('ffmpeg', ['-v', 'error', '-y', '-f', 'concat', '-safe', '0', '-i', list, '-vf', 'fps=30', '-c:v', 'libx264', '-preset', 'medium', '-crf', '12', '-pix_fmt', 'yuv420p', outMp4]);
        const span = fr[fr.length - 1].t - fr[0].t;
        fs.writeFileSync(outMp4.replace(/\.mp4$/, '.json'), JSON.stringify({ frames: fr.length, seconds: +span.toFixed(2), fps: +(fr.length / span).toFixed(1), marks: s.marks, errors }, null, 1));
        for (const f of fr) fs.rmSync(f.file, { force: true });
        fs.rmSync(list, { force: true });
        console.log(path.basename(outMp4), fr.length, 'frames', span.toFixed(1) + 's', (fr.length / span).toFixed(0) + 'fps', 'marks', JSON.stringify(s.marks), errors.length ? 'ERRORS ' + errors.join(' | ') : '');
    };
    s.close = () => browser.close();
    return s;
}

module.exports = { open, sleep, closeAll, W, H };
