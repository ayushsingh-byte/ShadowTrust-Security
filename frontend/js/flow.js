/* Overview: the attack flow. Four columns of boxes (sources, sensors, techniques, cases) joined
   by lines whose thickness follows real counts from /dashboard/flow.
   Nothing here moves on its own: the lines draw once when the data first arrives, and a dot
   crosses a source-to-sensor line only when the live stream reports an event on it. */
(function () {
    'use strict';

    var NS = 'http://www.w3.org/2000/svg';
    var STATUS = ['NEW', 'TRIAGING', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE'];
    var BANDS = [['source_sensor', 0, 'events'], ['sensor_technique', 1, 'detections'], ['technique_case', 2, 'detections']];
    var reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    var fmt = function (n) { return Number(n || 0).toLocaleString(); };
    var esc = function (s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    };
    var nice = function (s) {
        s = String(s).replace(/[_-]+/g, ' ').toLowerCase();
        return s.charAt(0).toUpperCase() + s.slice(1);
    };

    function columns(data) {
        var cases = (data.cases || []).slice().sort(function (a, b) { return STATUS.indexOf(a.id) - STATUS.indexOf(b.id); });
        return [
            { title: 'Sources', unit: 'events', items: (data.sources || []).map(function (s) { return { id: s.id, label: s.id === 'others' ? String(s.label).replace(/ address(es)?$/, s.label.indexOf('1 other') === 0 ? '' : 's') : s.label, value: s.events, mono: s.id !== 'others' }; }) },
            { title: 'Sensors', unit: 'events', items: (data.sensors || []).map(function (s) { return { id: s.id, label: nice(s.id), value: s.events }; }) },
            { title: 'Techniques', unit: 'detections', items: (data.techniques || []).map(function (t) { return { id: t.id, label: t.id, sub: t.tactic, value: t.detections, mono: true }; }) },
            { title: 'Cases', unit: 'cases', items: cases.map(function (c) { return { id: c.id, label: nice(c.id), value: c.cases }; }) },
        ];
    }

    // one line per link, from the right edge of its first box to the left edge of its second
    function draw(host) {
        var svg = host.querySelector('.flow-links');
        var data = host._flow;
        if (!svg || !data) return;
        var box = host.getBoundingClientRect();
        var at = function (col, id) {
            var el = host.querySelector('.flow-node[data-col="' + col + '"][data-id="' + (window.CSS && CSS.escape ? CSS.escape(id) : id) + '"]');
            if (!el) return null;
            var r = el.getBoundingClientRect();
            return { left: r.left - box.left, right: r.right - box.left, y: r.top - box.top + r.height / 2 };
        };
        var first = !host._drawn;
        svg.setAttribute('viewBox', '0 0 ' + box.width + ' ' + box.height);
        svg.textContent = '';
        var n = 0;
        BANDS.forEach(function (band) {
            var links = (data.links && data.links[band[0]]) || [];
            var max = links.reduce(function (m, l) { return Math.max(m, l.value); }, 1);
            links.forEach(function (l) {
                var a = at(band[1], l.from), b = at(band[1] + 1, l.to);
                if (!a || !b) return;
                var dx = (b.left - a.right) * 0.5;
                var p = document.createElementNS(NS, 'path');
                p.setAttribute('d', 'M' + a.right.toFixed(1) + ' ' + a.y.toFixed(1) + 'C' + (a.right + dx).toFixed(1) + ' ' + a.y.toFixed(1) + ' ' + (b.left - dx).toFixed(1) + ' ' + b.y.toFixed(1) + ' ' + b.left.toFixed(1) + ' ' + b.y.toFixed(1));
                p.setAttribute('class', 'b' + band[1]);
                p.setAttribute('data-from', l.from);
                p.setAttribute('data-to', l.to);
                p.setAttribute('data-band', band[1]);
                // square root, so a line a hundred times busier is ten times thicker and thin ones stay visible
                p.setAttribute('stroke-width', (1.5 + 12.5 * Math.sqrt(l.value / max)).toFixed(2));
                var t = document.createElementNS(NS, 'title');
                t.textContent = l.from + ' to ' + nice(l.to) + ': ' + fmt(l.value) + ' ' + band[2];
                p.appendChild(t);
                if (first && !reduce) {
                    p.setAttribute('pathLength', '1');
                    p.style.setProperty('--n', n++);
                    p.classList.add('draw');
                }
                svg.appendChild(p);
            });
        });
        host._drawn = true;
    }

    function render(host, data) {
        if (!host || !data) return;
        var key = JSON.stringify([data.sources, data.sensors, data.techniques, data.cases, data.links]);
        if (host._key === key) return; // nothing changed since the last answer
        host._key = key;
        host._flow = data;
        var cols = columns(data);
        if (!cols[0].items.length) {
            host.innerHTML = '<p class="flow-empty">No traffic recorded yet. The diagram fills in once a sensor logs its first event.</p>';
            host._drawn = false;
            return;
        }
        host.innerHTML = '<svg class="flow-links" aria-hidden="true"></svg>'
            + cols.map(function (c) { return '<div class="flow-h">' + c.title + '<span>' + c.unit + '</span></div>'; }).join('')
            + cols.map(function (c, i) {
                return '<div class="flow-col">' + c.items.map(function (it) {
                    return '<div class="flow-node" data-col="' + i + '" data-id="' + esc(it.id) + '">'
                        + '<span class="fl-l' + (it.mono ? ' mono' : '') + '">' + esc(it.label) + (it.sub ? '<small>' + esc(it.sub) + '</small>' : '') + '</span>'
                        + '<b>' + fmt(it.value) + '</b></div>';
                }).join('') + '</div>';
            }).join('');
        host.setAttribute('aria-label', 'Attack flow: ' + cols.map(function (c) { return c.items.length + ' ' + c.title.toLowerCase(); }).join(', ') + '.');
        draw(host);

        if (!host._wired) {
            host._wired = true;
            if (window.ResizeObserver) new ResizeObserver(function () { draw(host); }).observe(host);
            // hovering a box traces the lines that touch it
            host.addEventListener('mouseover', function (e) {
                var node = e.target.closest && e.target.closest('.flow-node');
                if (!node) return;
                var col = +node.getAttribute('data-col'), id = node.getAttribute('data-id');
                host.classList.add('focus');
                host.querySelectorAll('.hot').forEach(function (x) { x.classList.remove('hot'); });
                node.classList.add('hot');
                host.querySelectorAll('.flow-links path').forEach(function (p) {
                    var band = +p.getAttribute('data-band');
                    var hit = (band === col && p.getAttribute('data-from') === id) || (band === col - 1 && p.getAttribute('data-to') === id);
                    if (!hit) return;
                    p.classList.add('hot');
                    var other = band === col ? [col + 1, p.getAttribute('data-to')] : [col - 1, p.getAttribute('data-from')];
                    host.querySelectorAll('.flow-node[data-col="' + other[0] + '"]').forEach(function (m) {
                        if (m.getAttribute('data-id') === other[1]) m.classList.add('hot');
                    });
                });
            });
            host.addEventListener('mouseleave', function () {
                host.classList.remove('focus');
                host.querySelectorAll('.hot').forEach(function (x) { x.classList.remove('hot'); });
            });
        }
    }

    // A live event: a dot crosses the line from its source (or "others") to its sensor.
    function pulse(host, sourceIp, sensor) {
        if (!host || reduce || document.hidden || !host._drawn) return;
        var paths = host.querySelectorAll('.flow-links path[data-band="0"]');
        var exact = null, rest = null;
        paths.forEach(function (p) {
            if (p.getAttribute('data-to') !== sensor) return;
            if (p.getAttribute('data-from') === sourceIp) exact = p;
            if (p.getAttribute('data-from') === 'others') rest = p;
        });
        var path = exact || rest;
        if (!path) return;
        var now = performance.now();
        if (path._last && now - path._last < 220) return; // a burst shows as a stream of dots, not a smear
        path._last = now;
        var dot = document.createElementNS(NS, 'circle');
        dot.setAttribute('r', '3.5');
        dot.setAttribute('class', 'flow-dot');
        path.parentNode.appendChild(dot);
        var len = path.getTotalLength(), t0 = now, DUR = 900;
        (function step(t) {
            var k = Math.min(1, (t - t0) / DUR);
            var e = k < 0.5 ? 2 * k * k : 1 - Math.pow(-2 * k + 2, 2) / 2;
            var pt = path.getPointAtLength(len * e);
            dot.setAttribute('cx', pt.x);
            dot.setAttribute('cy', pt.y);
            dot.style.opacity = k < 0.85 ? 1 : (1 - k) / 0.15;
            if (k < 1 && dot.isConnected) requestAnimationFrame(step); else dot.remove();
        })(now);
        // the box it lands on answers
        var node = null;
        host.querySelectorAll('.flow-node[data-col="1"]').forEach(function (m) { if (m.getAttribute('data-id') === sensor) node = m; });
        if (node) {
            node.classList.remove('ping');
            void node.offsetWidth;
            node.classList.add('ping');
        }
    }

    window.STFlow = { render: render, pulse: pulse };
})();
