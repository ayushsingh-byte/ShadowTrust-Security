/* Shared motion for console pages. Loaded by sidebar.js, so every app page gets it.
   - Figures count up when their value first arrives or changes.
   - Sections below the fold rise in as they scroll into view.
   - Tables and lists stagger their rows the first time they fill.
   Everything is skipped under prefers-reduced-motion. */
(function () {
    'use strict';

    /* ---------- sparklines ---------- */
    // STSpark(host, values, label) draws a small trend line in the corner of a KPI card.
    // It is only for real series: with fewer than two numbers it draws nothing.
    var SVGNS = 'http://www.w3.org/2000/svg';
    var sparkSeq = 0;
    window.STSpark = function (host, values, label) {
        if (!host) return;
        var vals = (values || []).map(Number).filter(isFinite);
        var svg = host.querySelector('.st-spark');
        if (vals.length < 2) { if (svg) svg.remove(); return; }
        var W = 58, H = 22, pad = 3;
        var min = Math.min.apply(null, vals), span = (Math.max.apply(null, vals) - min) || 1;
        var pts = vals.map(function (v, i) {
            return [pad + (W - pad * 2) * i / (vals.length - 1), H - pad - (H - pad * 2) * (v - min) / span];
        });
        var d = pts.map(function (p, i) { return (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1); }).join(' ');
        var end = pts[pts.length - 1];
        if (!svg) {
            var id = 'stSpark' + (++sparkSeq);
            svg = document.createElementNS(SVGNS, 'svg');
            svg.setAttribute('class', 'st-spark');
            svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
            svg.setAttribute('role', 'img');
            svg.innerHTML = '<title></title><defs><linearGradient id="' + id + '" x1="0" y1="0" x2="0" y2="1">'
                + '<stop offset="0" style="stop-color:var(--st-accent);stop-opacity:.3"/>'
                + '<stop offset="1" style="stop-color:var(--st-accent);stop-opacity:0"/></linearGradient></defs>'
                + '<path class="area" fill="url(#' + id + ')"/><path class="line" pathLength="1"/><circle class="end" r="2.4"/>';
            host.appendChild(svg);
        }
        svg.setAttribute('aria-label', label || 'Trend');
        svg.querySelector('title').textContent = label || '';
        svg.querySelector('.line').setAttribute('d', d);
        svg.querySelector('.area').setAttribute('d', d + ' L' + end[0].toFixed(1) + ' ' + H + ' L' + pts[0][0].toFixed(1) + ' ' + H + ' Z');
        svg.querySelector('.end').setAttribute('cx', end[0].toFixed(1));
        svg.querySelector('.end').setAttribute('cy', end[1].toFixed(1));
    };

    /* ---------- empty and loading messages ---------- */
    // A cell or list item that only says "No ... yet" gets the empty-state drawing; one that
    // only says "Loading ..." becomes a shimmer bar. Pages keep writing plain text.
    var EMPTY = /^(no |nothing |waiting for )/i;
    var LOADING = /^loading/i;
    function dress(root) {
        if (!root.querySelectorAll) return;
        root.querySelectorAll('td[colspan], li, .text-muted').forEach(function (el) {
            if (el.children.length || el.classList.contains('st-empty-msg') || el.classList.contains('st-loading-td')) return;
            var text = (el.textContent || '').trim();
            if (!text || text.length > 90) return;
            var cell = el.tagName === 'TD';
            var row = el.parentElement;
            // only a placeholder that stands in for the whole table or list, never a note inside a data row
            var alone = row && row.children.length === 1 && el.tagName !== 'SPAN'
                && (!cell || (row.parentElement && row.parentElement.children.length === 1));
            if (!alone) return;
            if (LOADING.test(text)) { if (cell) el.classList.add('st-loading-td'); return; }
            if (EMPTY.test(text) && el.offsetWidth > 220) el.classList.add('st-empty-msg');
        });
    }
    var shell = document.querySelector('.main-content');
    if (shell) {
        dress(shell);
        var queued = false;
        new MutationObserver(function () {
            if (queued) return;
            queued = true;
            requestAnimationFrame(function () { queued = false; dress(shell); });
        }).observe(shell, { childList: true, subtree: true, attributes: true, attributeFilter: ['class', 'style', 'hidden'] });
    }

    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    var main = document.querySelector('.main-content');
    if (!main) return;

    /* ---------- count-up ---------- */
    var FIGURES = '.kpi-value, .metric-value, .hn-stat .value, .stat-num, .lg-kpi .v, .sp-kpi .v, .dv-kpi-val, .tile .v, [data-countup]';
    var NUM = /-?\d[\d,]*(\.\d+)?/;
    var animating = new WeakSet();
    var lastValue = new WeakMap();
    var ours = new WeakMap();      // the text this script last wrote into an element
    var handsOff = new WeakSet();  // elements the page animates itself

    function parse(text) {
        var all = text.match(/-?\d[\d,]*(\.\d+)?/g);
        if (!all || all.length !== 1) return null; // "4 / 4" or plain words: leave alone
        var m = NUM.exec(text);
        var raw = m[0];
        var value = parseFloat(raw.replace(/,/g, ''));
        if (!isFinite(value)) return null;
        return {
            value: value,
            pre: text.slice(0, m.index),
            post: text.slice(m.index + raw.length),
            decimals: (raw.split('.')[1] || '').length,
            grouped: raw.indexOf(',') !== -1,
        };
    }

    function format(v, spec) {
        var s = spec.decimals ? v.toFixed(spec.decimals) : String(Math.round(v));
        if (spec.grouped) {
            var parts = s.split('.');
            parts[0] = parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, ',');
            s = parts.join('.');
        }
        return spec.pre + s + spec.post;
    }

    function write(el, text) {
        ours.set(el, text);
        el.textContent = text;
    }

    function countUp(el) {
        if (animating.has(el) || handsOff.has(el) || el.children.length) return;
        var text = el.textContent;
        var spec = parse(text);
        if (!spec) return;
        var from = lastValue.has(el) ? lastValue.get(el) : 0;
        lastValue.set(el, spec.value);
        if (from === spec.value || Math.abs(spec.value) < 2) return;
        animating.add(el);
        var start = performance.now();
        var dur = 900;
        (function tick(now) {
            if (handsOff.has(el)) { animating.delete(el); return; } // the page took over
            var k = Math.min(1, (now - start) / dur);
            var e = 1 - Math.pow(1 - k, 4);
            if (k < 1) { write(el, format(from + (spec.value - from) * e, spec)); requestAnimationFrame(tick); }
            else { write(el, text); animating.delete(el); }
        })(start);
    }

    var figureObserver = new MutationObserver(function (records) {
        records.forEach(function (r) {
            var el = r.target.nodeType === 1 ? r.target : r.target.parentElement;
            if (!el || !el.matches || !el.matches(FIGURES) || handsOff.has(el)) return;
            if (animating.has(el)) {
                // A write that is not ours while we animate means the page runs its own counter.
                if (el.textContent !== ours.get(el)) handsOff.add(el);
                return;
            }
            if (el.textContent === ours.get(el)) return;
            countUp(el);
        });
    });

    function watchFigures(root) {
        root.querySelectorAll(FIGURES).forEach(function (el) {
            if (el.dataset.stWatched) return;
            el.dataset.stWatched = '1';
            figureObserver.observe(el, { childList: true, characterData: true, subtree: true });
            var spec = parse(el.textContent);
            if (spec && spec.value !== 0) countUp(el);
        });
    }

    /* ---------- reveal on scroll ---------- */
    var io = 'IntersectionObserver' in window ? new IntersectionObserver(function (entries) {
        entries.forEach(function (en) {
            if (!en.isIntersecting) return;
            en.target.classList.add('in');
            io.unobserve(en.target);
        });
    }, { root: main, rootMargin: '0px 0px -8% 0px' }) : null;

    function armReveals() {
        if (!io) return;
        var fold = main.getBoundingClientRect().bottom;
        main.querySelectorAll(':scope > *, :scope > .grid12 > *, :scope > .dashboard-grid > *').forEach(function (el) {
            if (el.dataset.stReveal) return;
            el.dataset.stReveal = '1';
            if (el.getBoundingClientRect().top < fold) return; // already on screen: page entrance handles it
            if (getComputedStyle(el).position === 'fixed') return;
            el.classList.add('st-reveal');
            io.observe(el);
        });
        // safety: nothing may stay hidden if the observer never fires
        setTimeout(function () {
            main.querySelectorAll('.st-reveal:not(.in)').forEach(function (el) {
                var r = el.getBoundingClientRect();
                if (r.top < fold) el.classList.add('in');
            });
        }, 1500);
    }

    /* ---------- first-fill row stagger ---------- */
    var rowObserver = new MutationObserver(function (records) {
        records.forEach(function (r) {
            var box = r.target;
            if (box.dataset.stRows === 'done' || !r.addedNodes.length) return;
            var rows = box.children;
            if (rows.length < 2) return; // placeholder row ("No data yet")
            box.dataset.stRows = 'done';
            for (var i = 0; i < rows.length && i < 14; i++) rows[i].style.setProperty('--ri', i);
            box.classList.add('st-rows-in');
            setTimeout(function () { box.classList.remove('st-rows-in'); }, 1200);
        });
    });

    function watchRows(root) {
        root.querySelectorAll('tbody, .rows-list, [data-rows]').forEach(function (box) {
            if (box.dataset.stRows) return;
            box.dataset.stRows = 'armed';
            rowObserver.observe(box, { childList: true });
        });
    }

    function scan() {
        watchFigures(main);
        watchRows(main);
        armReveals();
    }

    scan();
    // pages build parts of themselves after their first API call
    new MutationObserver(function () {
        clearTimeout(scan.t);
        scan.t = setTimeout(scan, 120);
    }).observe(main, { childList: true, subtree: true });
})();

/* Tabs: the line under the active tab slides to the next one, and the panel that was
   switched to arrives with one short move (css: .tab-ink, .tab-switched in dashboard.css). */
(function () {
    'use strict';

    var main = document.querySelector('.main-content');
    if (!main) return;
    var SEL = '.tab-nav, .tabs';
    var ACTIVE = '.tab-btn.active, .tab.on, button.on';
    var queued = 0;

    function place(bar) {
        if (!bar.offsetWidth) return; // not on screen yet: its own underline stays until it is
        var active = bar.querySelector(ACTIVE), ink = null;
        for (var i = 0; i < bar.children.length; i++) if (bar.children[i].className === 'tab-ink') ink = bar.children[i];
        var fresh = !ink;
        if (fresh) {
            ink = document.createElement('span');
            ink.className = 'tab-ink';
            ink.setAttribute('aria-hidden', 'true');
            if (getComputedStyle(bar).position === 'static') bar.style.position = 'relative';
            bar.appendChild(ink);
            bar.classList.add('has-ink');
        }
        if (!active) { ink.style.opacity = '0'; return; }
        if (fresh) ink.style.transition = 'none'; // the first placement does not slide in from the corner
        ink.style.opacity = '1';
        ink.style.width = active.offsetWidth + 'px';
        ink.style.transform = 'translateX(' + active.offsetLeft + 'px)';
        if (fresh) { void ink.offsetWidth; ink.style.transition = ''; }
    }
    function sync() { queued = 0; main.querySelectorAll(SEL).forEach(place); }
    function queue() { if (!queued) queued = requestAnimationFrame(sync); }

    main.addEventListener('click', function (e) {
        var bar = e.target.closest && e.target.closest(SEL);
        if (!bar || !e.target.closest('button, a')) return;
        bar.classList.remove('tab-switched');
        void bar.offsetWidth;
        bar.classList.add('tab-switched');
        // the page's own handler runs after this one and moves the active class
        requestAnimationFrame(queue);
    }, true);
    new MutationObserver(queue).observe(main, { childList: true, subtree: true });
    window.addEventListener('resize', queue);
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(queue);
    queue();
})();

