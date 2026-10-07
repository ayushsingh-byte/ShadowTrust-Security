/* Explainer figures for the public sub-pages (features, architecture, use cases, docs).
   Each block initialises only when its markup is on the page. Requires js/site.js first.
   Without Motion or with reduced motion, figures render in a readable static state. */
(function () {
    'use strict';

    var S = window.STSite || {};
    var M = S.M;
    var EASE = S.EASE || [0.16, 1, 0.3, 1];
    var animated = !!S.canAnimate;
    var sleep = function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };
    var esc = function (s) {
        return String(s).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    };

    /* ------------------------------------------------------------------
       Features: scroll-pinned malware pipeline
       ------------------------------------------------------------------ */
    function initPipeline() {
        var pipe = document.querySelector('[data-pipe]');
        if (!pipe) return;
        var stations = pipe.querySelectorAll('[data-station]');
        var token = pipe.querySelector('[data-pipe-token]');
        var rail = pipe.querySelector('[data-pipe-rail]');
        var title = pipe.querySelector('[data-readout-title]');
        var text = pipe.querySelector('[data-readout-text]');
        var code = pipe.querySelector('[data-readout-code]');
        var readout = pipe.querySelector('.readout');

        var STEPS = [
            {
                t: 'Capture',
                p: 'Dionaea keeps whatever is uploaded to it. Cowrie records every wget or curl URL as a file_download event, tied to the session that ran it.',
                c: [['eventid', 'cowrie.session.file_download'], ['url', 'http://45.9.148.99/bins/mirai.arm7', 's'], ['session', '93ff915d8dee'], ['sensor', 'cowrie, ssh 2222']],
            },
            {
                t: 'Hash',
                p: 'Each stored file is hashed the moment it lands, so a sample seen twice is recognised and linked instead of analysed again.',
                c: [['md5', '32 hex characters'], ['sha1', '40 hex characters'], ['sha256', '64 hex characters, used as the sample ID', 's'], ['seen', 'first and last sighting, per sensor']],
            },
            {
                t: 'Static analysis',
                p: 'Headers are parsed for architecture, imports and exports. High section entropy flags packing. Printable strings are pulled out to find URLs, addresses and shell commands.',
                c: [['format', 'PE, ELF, Mach-O, PDF, DOCX, scripts'], ['sections', 'entropy per section, packer hints'], ['imports', 'grouped by suspicious API family', 's'], ['strings', 'URLs, IPs, commands']],
            },
            {
                t: 'Signatures',
                p: 'ClamAV scans with its signature database. YARA runs the starter ruleset that ships with the platform, and any rules you add next to it.',
                c: [['clamav', 'clamd on the internal network'], ['yara', 'backend/yara_rules/shadowtrust_starter.yar', 's'], ['virustotal', 'only when VIRUSTOTAL_API_KEY is set']],
            },
            {
                t: 'Detonation',
                p: 'If CAPE_URL points at a CAPE sandbox, the sample is submitted for behavioral analysis. If it does not, the report says dynamic analysis was not run. Nothing is made up.',
                c: [['CAPE_URL set', 'behavior, network, dropped files', 's'], ['CAPE_URL unset', 'available: false'], ['verdict', 'carried by static, YARA, ClamAV']],
            },
            {
                t: 'Secrets and verdict',
                p: 'Scripts and configs are searched for credentials and API keys. Hashes, findings and the verdict are saved and linked back to the attacker session and any open incident.',
                c: [['finds', 'cloud keys, tokens, passwords in configs'], ['links', 'sample, session, incident', 's'], ['shown in', 'Binary analysis and PDF reports']],
            },
        ];

        var current = -1;
        function show(i, instant) {
            if (i === current) return;
            current = i;
            stations.forEach(function (st, k) {
                st.classList.toggle('on', k <= i);
                st.classList.toggle('cur', k === i);
            });
            var step = STEPS[i];
            var fill = function () {
                title.textContent = step.t;
                text.textContent = step.p;
                code.innerHTML = step.c.map(function (kv) {
                    var pad = kv[0] + '              '.slice(kv[0].length);
                    return '<span class="k">' + esc(pad) + '</span><span class="' + (kv[2] || 'v') + '">' + esc(kv[1]) + '</span>';
                }).join('\n');
            };
            if (!animated || instant) { fill(); return; }
            M.animate(readout, { opacity: [1, 0], y: [0, -6] }, { duration: 0.16 }).then(function () {
                fill();
                M.animate(readout, { opacity: [0, 1], y: [8, 0] }, { duration: 0.35, ease: EASE });
            });
        }

        // Clicking a station scrolls to its point in the pinned section.
        stations.forEach(function (st, k) {
            st.style.cursor = 'pointer';
            st.addEventListener('click', function () {
                var top = pipe.getBoundingClientRect().top + window.scrollY;
                var span = pipe.offsetHeight - window.innerHeight;
                window.scrollTo({ top: top + span * (k / (STEPS.length - 1)) + 2, behavior: animated ? 'smooth' : 'auto' });
                if (!animated) show(k, true);
            });
        });

        show(0, true);
        if (!animated || !M.scroll) {
            stations.forEach(function (st) { st.classList.add('on'); });
            return;
        }

        // Dot centres relative to the track's padding box, where the rail and token sit.
        var track = token.parentElement;
        var xs;
        function measure() {
            var base = track.getBoundingClientRect();
            var y = 0;
            xs = Array.prototype.map.call(stations, function (st) {
                var d = st.querySelector('.dot').getBoundingClientRect();
                y = d.top + d.height / 2 - base.top - track.clientTop;
                return d.left + d.width / 2 - base.left - track.clientLeft;
            });
            var railBox = rail.parentElement;
            railBox.style.left = xs[0] + 'px';
            railBox.style.right = 'auto';
            railBox.style.width = (xs[xs.length - 1] - xs[0]) + 'px';
            railBox.style.top = (y - railBox.offsetHeight / 2) + 'px';
            token.style.top = (y - token.offsetHeight / 2) + 'px';
        }
        measure();
        window.addEventListener('resize', measure);

        M.scroll(function (p) {
            var pos = Math.max(0, Math.min(1, p)) * (STEPS.length - 1);
            var k = Math.min(STEPS.length - 2, Math.floor(pos));
            var x = xs[k] + (xs[k + 1] - xs[k]) * (pos - k);
            token.style.transform = 'translateX(' + x + 'px)';
            rail.style.transform = 'scaleX(' + ((x - xs[0]) / ((xs[xs.length - 1] - xs[0]) || 1)) + ')';
            show(Math.min(STEPS.length - 1, Math.floor(pos + 0.3)));
        }, { target: pipe, offset: ['start start', 'end end'] });
    }

    /* ------------------------------------------------------------------
       Architecture: one event travels the stack, hop by hop
       ------------------------------------------------------------------ */
    function initJourney() {
        var fig = document.querySelector('[data-journey]');
        if (!fig) return;
        var NS = 'http://www.w3.org/2000/svg';
        var layer = fig.querySelector('[data-journey-layer]');
        var hops = fig.querySelectorAll('[data-hops] .hop');
        var nodes = {};
        fig.querySelectorAll('[data-hop-node]').forEach(function (n) { nodes[n.getAttribute('data-hop-node')] = n; });
        var SEGMENTS = [
            'M94 214 C 140 170, 150 115, 192 115',
            'M192 115 L 392 115 C 430 115, 430 222, 470 222',
            'M470 222 L 610 222 C 645 222, 645 109, 682 109',
            'M682 109 L 888 109 C 940 109, 950 100, 990 100',
            'M1050 156 C 1050 196, 960 191, 888 191',
            'M888 191 C 930 191, 930 266, 990 266',
            'M1075 294 V 360',
        ];
        var HOP_FOR_NODE = [0, 1, 2, 3, 4, 5, 6, 6];

        function light(k) {
            Object.keys(nodes).forEach(function (key) { nodes[key].classList.toggle('lit', +key === k); });
            hops.forEach(function (h, i) { h.classList.toggle('on', i <= HOP_FOR_NODE[k]); });
        }

        if (!animated) {
            hops.forEach(function (h) { h.classList.add('on'); });
            return;
        }

        var running = false;
        var gen = 0;

        async function run() {
            var my = ++gen;
            while (running && my === gen) {
                layer.innerHTML = '';
                light(0);
                await sleep(900);
                for (var i = 0; i < SEGMENTS.length; i++) {
                    if (!running || my !== gen) return;
                    var path = document.createElementNS(NS, 'path');
                    path.setAttribute('d', SEGMENTS[i]);
                    path.setAttribute('class', 'journey-trail');
                    path.setAttribute('pathLength', '1');
                    path.style.strokeDasharray = '1';
                    path.style.strokeDashoffset = '1';
                    layer.appendChild(path);
                    var dot = document.createElementNS(NS, 'circle');
                    dot.setAttribute('r', '6');
                    dot.setAttribute('class', 'journey-dot');
                    layer.appendChild(dot);
                    var len = path.getTotalLength();
                    await M.animate(0, 1, {
                        duration: 0.5 + len / 900,
                        ease: [0.45, 0, 0.2, 1],
                        onUpdate: function (t) {
                            var pt = path.getPointAtLength(t * len);
                            dot.setAttribute('cx', pt.x);
                            dot.setAttribute('cy', pt.y);
                            path.style.strokeDashoffset = String(1 - t);
                        },
                    });
                    dot.remove();
                    light(i + 1);
                    await sleep(900);
                }
                await sleep(2200);
                if (!running || my !== gen) return;
                await M.animate(layer.childNodes, { opacity: 0 }, { duration: 0.6 });
            }
        }

        M.inView(fig, function () {
            running = true;
            run();
            return function () { running = false; gen++; };
        }, { amount: 0.4 });
    }

    /* ------------------------------------------------------------------
       Vertical timelines: steps fill in as they reach the middle of the screen
       ------------------------------------------------------------------ */
    function initTimelines() {
        document.querySelectorAll('[data-vtl]').forEach(function (list) {
            var items = list.querySelectorAll(':scope > li');
            var bar = list.parentElement.querySelector('[data-vtl-progress]');
            if (!animated) {
                items.forEach(function (li) { li.classList.add('on'); });
                return;
            }
            // The drawing beside the list (architecture) shows the step that was reached last.
            var split = list.closest('.split');
            var stage = split && split.querySelector('[data-vtl-stage]');
            var STAGE_ART = ['decoys', 'stream', 'classify', 'sessions', 'rules', 'malware', 'lab', 'report'];
            var shown = 0;
            function syncStage() {
                if (!stage || !window.STArt) return;
                var k = 0;
                items.forEach(function (li, i) { if (li.classList.contains('on')) k = i; });
                if (k === shown || !STAGE_ART[k]) return;
                shown = k;
                var art = stage.querySelector('.art');
                window.STArt.mount(art, STAGE_ART[k]);
                art.classList.remove('swap');
                void art.offsetWidth; // restart the swap animation
                art.classList.add('swap');
                stage.querySelector('[data-vtl-stage-title]').textContent = items[k].querySelector('h3').textContent;
                stage.querySelector('[data-vtl-stage-step]').textContent = 'Step ' + (k + 1) + ' of ' + items.length;
            }
            items.forEach(function (li) {
                M.inView(li, function () {
                    li.classList.add('on');
                    syncStage();
                    return function (info) {
                        if (info && info.boundingClientRect && info.boundingClientRect.top > 0) li.classList.remove('on');
                        syncStage();
                    };
                }, { margin: '0px 0px -45% 0px' });
            });
            if (bar && M.scroll) {
                M.scroll(M.animate(bar, { scaleY: [0, 1] }, { ease: 'linear' }), {
                    target: list,
                    offset: ['start 55%', 'end 55%'],
                });
            }
        });
    }

    /* ------------------------------------------------------------------
       Use cases: each team's route through the console
       ------------------------------------------------------------------ */
    function initScenarios() {
        var root = document.querySelector('[data-scen]');
        if (!root) return;
        var tabs = root.querySelectorAll('[data-tab]');
        var ind = root.querySelector('[data-scen-ind]');
        var path = root.querySelector('[data-scen-path]');
        var line = root.querySelector('[data-scen-line]');
        var title = root.querySelector('[data-scen-title]');
        var text = root.querySelector('[data-scen-text]');
        var TEAMS = [
            { t: 'Watch, triage, close.', p: 'A SOC analyst starts from what changed, drills into the events behind it, works the case and hands off a report.', s: [
                ['08:30', 'Overview', 'Counts, map and the newest events since yesterday.'],
                ['08:40', 'Event log', 'Filter to the source that tripped a lure overnight.'],
                ['09:10', 'Investigations', 'Open the incident, read the timeline, add notes.'],
                ['11:00', 'Reports', 'Export the incident report as a PDF with hashes.']] },
            { t: 'Collect, open, compare.', p: 'A researcher pulls what attackers dropped, takes it apart in isolation, and writes up what it does.', s: [
                ['day 1', 'Binary analysis', 'Hashes, strings, ClamAV and YARA on the new samples.'],
                ['day 1', 'APK inspector', 'MobSF report on an Android dropper from the same campaign.'],
                ['day 2', 'Virtual lab', 'Kali in the browser to poke at the C2 safely.'],
                ['day 3', 'Reports', 'Malware report with every sample and verdict.']] },
            { t: 'Show, then let them try.', p: 'A teacher demonstrates a live kill chain, then turns students loose on their own accounts.', s: [
                ['week 1', 'Analysis lab', 'Run commands in the sandbox and watch detection react.'],
                ['week 1', 'MITRE ATT&CK', 'Map what just happened to techniques and tactics.'],
                ['week 2', 'Detection validation', 'Replay attacks and check which rules fire.'],
                ['week 3', 'Investigations', 'Students work a real case end to end.']] },
            { t: 'Aggregate, enrich, publish.', p: 'An intelligence team turns raw sightings into indicators other tools can consume.', s: [
                ['daily', 'Geo intelligence', 'Where the week\'s traffic came from, by country and ASN.'],
                ['daily', 'Credential vault', 'Which username and password pairs are trending.'],
                ['weekly', 'Behavior profiling', 'Cluster attackers by behavior, export STIX 2.1.'],
                ['weekly', 'Splunk blue team', 'Forward the enriched events to Splunk.']] },
            { t: 'Deploy, monitor, evidence.', p: 'A defence team runs decoys on a closed network and needs proof for auditors as much as alerts.', s: [
                ['setup', 'Honeypot nodes', 'Confirm every sensor is up and reporting.'],
                ['ongoing', 'Logs', 'Categorised raw logs, searchable and kept in-house.'],
                ['quarterly', 'GRC and SOC 2', 'Readiness by criterion with collected evidence.'],
                ['quarterly', 'Reports', 'Executive summary and compliance report.']] },
            { t: 'Context, right now.', p: 'During an active incident, responders need to know who, how and what was taken, fast.', s: [
                ['T+0', 'Investigations', 'The incident with its ordered timeline.'],
                ['T+5 min', 'Behavior profiling', 'Has this actor been seen before, and doing what?'],
                ['T+10 min', 'URL scanner', 'Check the download URLs from the session safely.'],
                ['T+15 min', 'Credential vault', 'Which credentials worked, so they can be rotated.']] },
        ];
        var active = -1;

        // The indicator is a pill that sits behind the selected tab, on whichever row it wrapped to.
        function moveInd(tab, instant) {
            var box = tab.parentElement;
            var x = tab.offsetLeft - box.clientLeft;
            var y = tab.offsetTop - box.clientTop;
            ind.style.height = tab.offsetHeight + 'px';
            if (!animated || instant) {
                ind.style.transform = 'translate(' + x + 'px, ' + y + 'px)';
                ind.style.width = tab.offsetWidth + 'px';
                return;
            }
            M.animate(ind, { x: x, y: y, width: tab.offsetWidth + 'px' }, { type: 'spring', stiffness: 380, damping: 34 });
        }

        function select(i, instant) {
            if (i === active) return;
            active = i;
            tabs.forEach(function (t, k) {
                t.setAttribute('aria-selected', String(k === i));
                t.tabIndex = k === i ? 0 : -1;
            });
            moveInd(tabs[i], instant);
            var team = TEAMS[i];
            title.textContent = team.t;
            text.textContent = team.p;
            path.querySelectorAll('.scen-stop').forEach(function (n) { n.remove(); });
            var stops = team.s.map(function (st) {
                var d = document.createElement('div');
                d.className = 'scen-stop';
                d.innerHTML = '<span class="pin"></span><span class="when">' + esc(st[0]) + '</span><span class="pg">' + esc(st[1]) + '</span><p>' + esc(st[2]) + '</p>';
                path.appendChild(d);
                return d;
            });
            if (!animated || instant) return;
            M.animate(line, { scaleX: [0, 1] }, { duration: 1.1, ease: [0.65, 0, 0.35, 1] });
            M.animate([title, text], { opacity: [0, 1], y: [10, 0] }, { duration: 0.5, delay: M.stagger(0.06), ease: EASE });
            M.animate(stops, { opacity: [0, 1], y: [14, 0] }, { duration: 0.55, delay: M.stagger(0.22, { startDelay: 0.05 }), ease: EASE });
            M.animate(stops.map(function (s) { return s.querySelector('.pin'); }), { scale: [0, 1] }, { type: 'spring', stiffness: 420, damping: 18, delay: M.stagger(0.22, { startDelay: 0.05 }) });
        }

        tabs.forEach(function (t, k) {
            t.addEventListener('click', function () { select(k); });
            t.addEventListener('keydown', function (e) {
                if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
                var n = (k + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length;
                tabs[n].focus();
                select(n);
            });
        });
        window.addEventListener('resize', function () { moveInd(tabs[active], true); });

        select(0, true);
        if (animated) {
            M.inView(root, function () { active = -1; select(0); }, { amount: 0.4 });
        }
    }

    /* ------------------------------------------------------------------
       Docs: setup.sh replay, section filter, scroll spy, copy buttons
       ------------------------------------------------------------------ */
    function initDocs() {
        var term = document.querySelector('[data-setup-body]');
        if (term) {
            var LINES = [
                ['p', '$ ', 'st', './setup.sh'],
                ['st', '[1/6] Checking prerequisites...'],
                ['ok', '  ✓ ', '', 'Docker'],
                ['ok', '  ✓ ', '', 'Compose (docker compose)'],
                ['st', '[2/6] Detecting platform...'],
                ['ok', '  ✓ ', '', 'Platform : macOS'],
                ['st', '[3/6] Setting up environment files...'],
                ['ok', '  ✓ ', '', 'Created .env'],
                ['st', '[4/6] Initialising data directories...'],
                ['ok', '  ✓ ', '', 'MobSF data directory ready'],
                ['st', '[5/6] Building images and starting containers...'],
                ['st', '[6/6] Verifying services...'],
                ['c', '    Console   →  ', 'u', 'http://localhost:5500'],
                ['c', '    API docs  →  ', 'u', 'http://localhost:8000/docs'],
            ];
            var render = function (l) {
                var d = document.createElement('div');
                d.className = 'l';
                d.innerHTML = '<span class="' + l[0] + '">' + esc(l[1]) + '</span>' + (l[3] ? '<span class="' + l[2] + '">' + esc(l[3]) + '</span>' : '');
                term.appendChild(d);
                return d;
            };
            if (!animated) {
                LINES.forEach(render);
            } else {
                (async function () {
                    await sleep(900);
                    for (var i = 0; i < LINES.length; i++) {
                        var d = render(LINES[i]);
                        M.animate(d, { opacity: [0, 1], x: [-6, 0] }, { duration: 0.3 });
                        await sleep(LINES[i][0] === 'st' ? 520 : 240);
                    }
                })();
            }
        }

        // Copy buttons on code blocks.
        document.querySelectorAll('[data-copy-code]').forEach(function (btn) {
            btn.addEventListener('click', function () {
                var code = btn.closest('.code').querySelector('code').innerText;
                if (!navigator.clipboard) return;
                navigator.clipboard.writeText(code).then(function () {
                    btn.textContent = 'Copied';
                    setTimeout(function () { btn.textContent = 'Copy'; }, 1400);
                });
            });
        });

        var nav = document.querySelector('[data-docs-nav]');
        if (!nav) return;
        var links = nav.querySelectorAll('a[href^="#"]');
        var sections = document.querySelectorAll('[data-doc]');

        // Scroll spy: mark the section crossing the upper third of the viewport.
        if ('IntersectionObserver' in window) {
            var io = new IntersectionObserver(function (entries) {
                entries.forEach(function (en) {
                    if (!en.isIntersecting) return;
                    links.forEach(function (a) { a.classList.toggle('on', a.getAttribute('href') === '#' + en.target.id); });
                });
            }, { rootMargin: '-25% 0px -70% 0px' });
            sections.forEach(function (sec) { io.observe(sec); });
        }

        // Filter: hide nav entries and dim sections that do not mention the query.
        var input = nav.querySelector('[data-docs-search]');
        var empty = nav.querySelector('[data-docs-empty]');
        input.addEventListener('input', function () {
            var q = input.value.trim().toLowerCase();
            var hits = 0;
            sections.forEach(function (sec) {
                var match = !q || sec.textContent.toLowerCase().indexOf(q) !== -1;
                sec.classList.toggle('dim', !match);
                var link = nav.querySelector('a[href="#' + sec.id + '"]');
                if (link) link.parentElement.classList.toggle('hidden', !match);
                if (match) hits++;
            });
            empty.style.display = hits ? 'none' : 'block';
        });
        input.addEventListener('keydown', function (e) {
            if (e.key !== 'Enter') return;
            var first = Array.prototype.find.call(sections, function (sec) { return !sec.classList.contains('dim'); });
            if (first) first.scrollIntoView({ behavior: animated ? 'smooth' : 'auto', block: 'start' });
        });
    }

    window.STExplain = { sleep: sleep, esc: esc };
    initDocs();
    initScenarios();
    initPipeline();
    initJourney();
    initTimelines();
})();
