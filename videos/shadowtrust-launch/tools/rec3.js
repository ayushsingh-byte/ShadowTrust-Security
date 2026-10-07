// Screen recorder with a camera, for the third cut of the launch video.
// It drives the real console in headless Chrome and records it. The camera is a CSS transform
// on the page body, animated in the page itself, so a close-up is re-drawn sharp by the browser
// instead of being an enlarged picture. The page runs at 2x pixel density so charts, the globe
// and PDF pages stay sharp when zoomed. Every keystroke time is logged for the typing sound.
// Added to the page while recording: the camera transform, a drawn cursor, a click ring. Nothing else.
const puppeteer = require('puppeteer-core');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const W = 1664, H = 936; // the size of the window the recording is shown in, so no scaling is needed later
const TOKEN = fs.readFileSync(process.env.ST_TOKEN_FILE || path.join(__dirname, 'token.txt'), 'utf8').trim();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const ease = (k) => (k < 0.5 ? 4 * k * k * k : 1 - Math.pow(-2 * k + 2, 3) / 2);
const OPEN = [];
const closeAll = async () => { while (OPEN.length) await OPEN.pop().close().catch(() => {}); };

async function open(pagePath, { cursor = true, dark = false } = {}) {
    const browser = await puppeteer.launch({
        executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        headless: true,
        args: ['--hide-scrollbars', `--window-size=${W},${H}`],
    });
    OPEN.push(browser);
    const page = await browser.newPage();
    await page.setViewport({ width: W, height: H, deviceScaleFactor: 2 });
    await page.emulateMediaFeatures([{ name: 'prefers-color-scheme', value: dark ? 'dark' : 'light' }]);
    await page.evaluateOnNewDocument((tok, dark) => {
        try {
            localStorage.setItem('st-theme', dark ? 'dark' : 'light');
            localStorage.setItem('access_token', tok);
            localStorage.setItem('authToken', tok);
        } catch (e) { /* sandboxed preview frames have no storage */ }
    }, TOKEN, dark);
    const errors = [];
    page.on('pageerror', (e) => errors.push(e.message.slice(0, 140)));
    await page.goto('http://127.0.0.1:5500/' + pagePath, { waitUntil: 'networkidle2', timeout: 60000 }).catch((e) => errors.push('GOTO ' + e.message));

    const s = { browser, page, errors, x: W * 0.7, y: H * 0.45, marks: [], keys: [], frames: [], dir: null, cdp: null };

    // camera and cursor live in the page
    await page.evaluate((W, H, x, y, withCursor) => {
        const body = document.body;
        document.documentElement.style.overflow = 'hidden';
        body.style.transformOrigin = '0 0';
        const cam = window.__cam = { x: W / 2, y: H / 2, s: 1, tx: 0, ty: 0 };
        const apply = () => {
            let tx = W / 2 - cam.x * cam.s, ty = H / 2 - cam.y * cam.s;
            tx = Math.min(0, Math.max(W - W * cam.s, tx)); // never show beyond the page edge
            ty = Math.min(0, Math.max(H - H * cam.s, ty));
            cam.tx = tx; cam.ty = ty;
            body.style.transform = cam.s === 1 ? 'none' : 'translate(' + tx.toFixed(2) + 'px,' + ty.toFixed(2) + 'px) scale(' + cam.s.toFixed(4) + ')';
            if (window.__placeCursor) window.__placeCursor();
        };
        const ease = (k) => (k < 0.5 ? 4 * k * k * k : 1 - Math.pow(-2 * k + 2, 3) / 2);
        // move the camera so the layout point (x, y) is centred at zoom s; zoom is interpolated geometrically
        window.__camTo = (x, y, s, ms) => new Promise((res) => {
            const a = { x: cam.x, y: cam.y, s: cam.s }, t0 = performance.now();
            (function step(now) {
                const k = Math.min(1, (now - t0) / ms), e = ease(k);
                cam.s = a.s * Math.pow(s / a.s, e);
                cam.x = a.x + (x - a.x) * e; cam.y = a.y + (y - a.y) * e;
                apply();
                if (k < 1) requestAnimationFrame(step); else res();
            })(t0);
        });
        // where an element sits in layout space (before the camera transform)
        window.__layoutCentre = (el) => { const r = el.getBoundingClientRect(); return { x: (r.left + r.width / 2 - cam.tx) / cam.s, y: (r.top + r.height / 2 - cam.ty) / cam.s, w: r.width / cam.s, h: r.height / cam.s }; };
        if (!withCursor) return;
        const c = document.createElement('div');
        c.id = '__rec_cursor';
        c.style.cssText = 'position:fixed;left:0;top:0;width:24px;height:24px;z-index:2147483647;pointer-events:none';
        c.innerHTML = '<svg viewBox="0 0 24 24" width="24" height="24"><path d="M4.5 2.5 19 11.2l-6.4 1.5-2.9 6.3Z" fill="#061B31" stroke="#fff" stroke-width="1.6" stroke-linejoin="round"/></svg>';
        body.appendChild(c);
        const st = document.createElement('style');
        st.textContent = '@keyframes __rec_ring{from{transform:translate(-50%,-50%) scale(.3);opacity:.55}to{transform:translate(-50%,-50%) scale(1.5);opacity:0}}';
        document.head.appendChild(st);
        const m = { x: x, y: y }; // last mouse position in screen pixels
        window.__placeCursor = () => { c.style.transform = 'translate(' + ((m.x - cam.tx) / cam.s) + 'px,' + ((m.y - cam.ty) / cam.s) + 'px)'; };
        document.addEventListener('mousemove', (e) => { m.x = e.clientX; m.y = e.clientY; window.__placeCursor(); }, true);
        document.addEventListener('mousedown', (e) => {
            const r = document.createElement('div');
            r.style.cssText = 'position:fixed;left:' + ((e.clientX - cam.tx) / cam.s) + 'px;top:' + ((e.clientY - cam.ty) / cam.s) + 'px;width:44px;height:44px;border-radius:50%;border:3px solid #533AFD;z-index:2147483646;pointer-events:none;animation:__rec_ring .5s ease-out forwards';
            body.appendChild(r);
            setTimeout(() => r.remove(), 600);
        }, true);
        window.__placeCursor();
    }, W, H, s.x, s.y, cursor);
    if (cursor) await page.mouse.move(s.x, s.y);

    const now = () => (s.frames.length ? Date.now() / 1000 - s.frames[0].t : 0);
    s.sleep = sleep;
    s.mark = (label) => s.marks.push([+now().toFixed(2), label]);

    // ---- camera
    s.cam = (x, y, zoom, ms = 900) => page.evaluate((x, y, z, ms) => window.__camTo(x, y, z, ms), x, y, zoom, ms);
    s.wide = (ms = 900) => s.cam(W / 2, H / 2, 1, ms);
    s.layout = (sel, index = 0) => page.evaluate((sel, index) => { const el = document.querySelectorAll(sel)[index]; return el ? window.__layoutCentre(el) : null; }, sel, index);
    // centre the camera on an element; fit = how much of the frame the element may fill (caps the zoom)
    s.camEl = async (sel, zoom, ms = 900, { index = 0, dx = 0, dy = 0, fit = 0.9 } = {}) => {
        const c = await s.layout(sel, index);
        if (!c) throw new Error('camera: no element ' + sel);
        // fit: 0 means take the zoom as given (for tall elements such as tables)
        const z = fit ? Math.max(1, Math.min(zoom, (fit * W) / c.w, (fit * H) / c.h)) : zoom;
        await s.cam(c.x + dx, c.y + dy, z, ms);
        return z;
    };

    // frame the top of a tall element (a table, a tab body): centred on it sideways, with its top edge
    // `inset` screen pixels below the top of the frame at this zoom
    // left: also line the element's left edge up `left` screen pixels from the frame's left edge
    s.camTop = async (sel, zoom, ms = 900, { index = 0, inset = 80, left = null } = {}) => {
        const c = await s.layout(sel, index);
        if (!c) throw new Error('camera: no element ' + sel);
        const x = left === null ? c.x : c.x - c.w / 2 + (W / zoom) / 2 - left / zoom;
        await s.cam(x, c.y - c.h / 2 + (H / zoom) / 2 - inset / zoom, zoom, ms);
    };

    // ---- pointer (screen pixels). Targets are re-read on every step, so the pointer follows an
    // element while the camera is still moving.
    s.centre = (sel, index = 0) => page.evaluate((sel, index) => {
        const el = document.querySelectorAll(sel)[index];
        if (!el) return null;
        const r = el.getBoundingClientRect();
        return { x: r.left + r.width / 2, y: r.top + r.height / 2, w: r.width, h: r.height };
    }, sel, index);
    s.moveTo = async (x, y, ms = 700) => {
        const x0 = s.x, y0 = s.y, steps = Math.max(2, Math.round(ms / 16));
        for (let i = 1; i <= steps; i++) { const k = ease(i / steps); await page.mouse.move(x0 + (x - x0) * k, y0 + (y - y0) * k); await sleep(11); }
        s.x = x; s.y = y;
    };
    s.moveToEl = async (sel, ms = 700, { index = 0, dx = 0, dy = 0 } = {}) => {
        const x0 = s.x, y0 = s.y, t0 = Date.now();
        let c = null;
        for (;;) {
            const k = Math.min(1, (Date.now() - t0) / ms);
            c = await s.centre(sel, index);
            if (!c) throw new Error('pointer: no element ' + sel);
            const e = ease(k);
            s.x = x0 + (c.x + dx - x0) * e; s.y = y0 + (c.y + dy - y0) * e;
            await page.mouse.move(s.x, s.y);
            if (k >= 1) break;
            await sleep(9);
        }
        return c;
    };
    s.press = async () => { await sleep(130); await page.mouse.down(); await sleep(70); await page.mouse.up(); };
    s.click = async (sel, ms = 700, opts) => { await s.moveToEl(sel, ms, opts); await s.press(); };
    // camera and pointer travel to the same element together
    s.go = async (sel, zoom, ms = 900, opts = {}) => { await Promise.all([s.camEl(sel, zoom, ms, opts), s.moveToEl(sel, ms + 120, opts)]); };
    s.drag = async (x1, y1, x2, y2, ms = 1400) => { await s.moveTo(x1, y1, 500); await page.mouse.down(); await s.moveTo(x2, y2, ms); await page.mouse.up(); };

    // ---- keyboard: one key at a time with an uneven, human rhythm; every key time is logged
    s.type = async (text, delay = 80) => {
        for (let i = 0; i < text.length; i++) {
            await page.keyboard.type(text[i]);
            s.keys.push(+now().toFixed(3));
            const wobble = 0.72 + 0.56 * ((i * 0.618034) % 1); // deterministic, 0.72 to 1.28
            await sleep(delay * wobble * (text[i] === ' ' ? 1.5 : 1));
        }
    };
    s.enter = async () => { await page.keyboard.press('Enter'); s.keys.push(+now().toFixed(3)); };

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
    // fire one of the product's own honeypot triggers (real traffic at the lab's sensors)
    s.fire = (id) => fetch('http://127.0.0.1:8000/api/v1/admin/diagnostics/trigger/' + id, { method: 'POST', headers: { Authorization: 'Bearer ' + TOKEN } })
        .then((r) => r.status).catch((e) => 'ERR ' + e.message);
    s.waitFor = async (fn, timeout = 30000, arg) => {
        const t0 = Date.now();
        while (Date.now() - t0 < timeout) { if (await page.evaluate(fn, arg).catch(() => false)) return true; await sleep(120); }
        return false;
    };

    s.start = async (dir) => {
        dir = path.resolve(dir);
        s.dir = dir; fs.rmSync(dir, { recursive: true, force: true }); fs.mkdirSync(dir, { recursive: true });
        s.cdp = await page.createCDPSession();
        s.cdp.on('Page.screencastFrame', (f) => {
            const file = path.join(dir, 'f' + String(s.frames.length).padStart(6, '0') + '.jpg');
            fs.writeFileSync(file, Buffer.from(f.data, 'base64'));
            s.frames.push({ file, t: f.metadata.timestamp });
            s.cdp.send('Page.screencastFrameAck', { sessionId: f.sessionId }).catch(() => {});
        });
        await s.cdp.send('Page.startScreencast', { format: 'jpeg', quality: 97, everyNthFrame: 1 });
        await sleep(150);
    };

    // stop and encode a constant 30 fps master at the capture size
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
        execFileSync('ffmpeg', ['-v', 'error', '-y', '-f', 'concat', '-safe', '0', '-i', list, '-vf', 'fps=30', '-c:v', 'libx264', '-preset', 'medium', '-crf', '11', '-pix_fmt', 'yuv420p', outMp4]);
        const span = fr[fr.length - 1].t - fr[0].t;
        const size = execFileSync('ffprobe', ['-v', 'error', '-select_streams', 'v:0', '-show_entries', 'stream=width,height', '-of', 'csv=p=0', outMp4]).toString().trim();
        fs.writeFileSync(outMp4.replace(/\.mp4$/, '.json'), JSON.stringify({ frames: fr.length, seconds: +span.toFixed(2), fps: +(fr.length / span).toFixed(1), size, marks: s.marks, keys: s.keys, errors }, null, 1));
        for (const f of fr) fs.rmSync(f.file, { force: true });
        fs.rmSync(list, { force: true });
        console.log(path.basename(outMp4), size, fr.length, 'frames', span.toFixed(1) + 's', (fr.length / span).toFixed(0) + 'fps', 'keys', s.keys.length, 'marks', JSON.stringify(s.marks), errors.length ? 'ERRORS ' + errors.join(' | ') : '');
    };
    return s;
}

module.exports = { open, sleep, closeAll, W, H };
