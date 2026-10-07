/* The silk ribbon and the small canvas helpers behind it. Shared by the public site, the
   sign-in pages and the console, so the same piece of graphic runs through all of them.
   Any <canvas data-ribbon> present when this file loads is drawn; variants:
     data-ribbon            the landing hero
     data-ribbon="corner"   kept to the right, clear of a heading (sub-pages, sign-in)
     data-ribbon="console"  the console's top right corner
   With reduced motion the ribbon is painted once and left still. */
(function () {
    'use strict';

    var REDUCED = !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
    var mix = function (a, b, t) { return a + (b - a) * t; };
    var mixc = function (a, b, t) { return [mix(a[0], b[0], t), mix(a[1], b[1], t), mix(a[2], b[2], t)]; };
    var clamp01 = function (v) { return v < 0 ? 0 : v > 1 ? 1 : v; };
    var easeOut = function (v) { return 1 - Math.pow(1 - clamp01(v), 3); };
    var rgba = function (c, a) {
        return 'rgba(' + Math.round(c[0]) + ',' + Math.round(c[1]) + ',' + Math.round(c[2]) + ',' + (a == null ? 1 : a).toFixed(3) + ')';
    };
    // Seeded generator, so the drawings look the same on every load.
    function seeded(seed) {
        return function () {
            seed = (seed + 0x6D2B79F5) | 0;
            var t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
            t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
            return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
        };
    }
    // Keep a canvas at device resolution and call draw(ctx, w, h, seconds) for each frame
    // while it is on screen. With reduced motion it is painted once, at rest (seconds = 0).
    function stage(cv, draw, maxDpr, gap) {
        var ctx = cv.getContext('2d');
        var w = 0, h = 0, raf = 0, last = 0;
        function paint(now) {
            if (!w || !h) return;
            ctx.clearRect(0, 0, w, h);
            draw(ctx, w, h, REDUCED ? 0 : now / 1000);
        }
        function tick(now) {
            raf = requestAnimationFrame(tick);
            if (now - last < (gap || 30)) return;
            last = now;
            paint(now);
        }
        function fit() {
            var dpr = Math.min(window.devicePixelRatio || 1, maxDpr || 2);
            w = cv.clientWidth;
            h = cv.clientHeight;
            cv.width = Math.round(w * dpr);
            cv.height = Math.round(h * dpr);
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
            paint(performance.now());
        }
        if ('ResizeObserver' in window) new ResizeObserver(fit).observe(cv);
        else { fit(); window.addEventListener('resize', fit); }
        if (!REDUCED && 'IntersectionObserver' in window) {
            new IntersectionObserver(function (entries) {
                cancelAnimationFrame(raf);
                if (entries[entries.length - 1].isIntersecting) raf = requestAnimationFrame(tick);
            }).observe(cv);
        }
        return { paint: function () { paint(performance.now()); } };
    }

    window.STCanvas = {
        reduced: REDUCED, mix: mix, mixc: mixc, clamp01: clamp01, easeOut: easeOut,
        rgba: rgba, seeded: seeded, stage: stage,
    };

    /* ------------------------------------------------------------------
       Hero ribbon: sheets of fabric, each a family of cubic curves between an "a" edge
       and a "b" edge. Coordinates are fractions of the canvas; colours run along the
       length of each edge and blend across the sheet.
       ------------------------------------------------------------------ */
    function ribbon(cv) {
        if (!cv || !cv.getContext || cv.stRibbon) return;
        cv.stRibbon = true;
        var SKY = [176, 205, 255], VIOLET = [124, 104, 255], PINK = [244, 75, 204], ROSE = [255, 128, 168],
            ORANGE = [255, 104, 24], AMBER = [255, 172, 36], PEACH = [255, 196, 150], WHITE = [255, 255, 255];
        var SHEETS = [
            { // pale blue into violet and pink, passing behind the heading
                a: [0.335, -0.03, 0.55, 0.30, 0.79, 0.62, 0.925, 1.03],
                b: [0.62, -0.03, 0.76, 0.27, 0.91, 0.56, 1.00, 1.03],
                ca: [SKY, VIOLET, PINK, VIOLET], cb: [SKY, PINK, ROSE, PINK],
                alpha: [0, 0.78], n: 34, amp: 0.011, speed: 0.050, phase: 0.0,
            },
            { // rose and peach down the right edge
                a: [0.70, -0.03, 0.86, 0.24, 0.875, 0.58, 0.94, 1.03],
                b: [1.10, -0.03, 1.05, 0.30, 1.12, 0.66, 1.06, 1.03],
                ca: [AMBER, ROSE, PINK, VIOLET], cb: [ROSE, PEACH, ROSE, PINK],
                alpha: [0.92, 0.92], n: 30, amp: 0.012, speed: 0.041, phase: 1.7,
            },
            { // orange blade on top, narrowing to a point
                a: [0.545, -0.03, 0.70, 0.22, 0.85, 0.46, 0.934, 0.71],
                b: [0.83, -0.03, 0.87, 0.22, 0.91, 0.47, 0.936, 0.71],
                ca: [AMBER, ORANGE, ORANGE, PINK], cb: [AMBER, AMBER, ORANGE, ROSE],
                alpha: [0.94, 0.94], n: 28, amp: 0.009, speed: 0.058, phase: 3.1,
            },
        ];
        var rnd = seeded(11);
        SHEETS.forEach(function (s) {
            s.streak = [];
            for (var i = 0; i <= s.n; i++) s.streak.push(rnd());
        });
        var A = new Array(8), B = new Array(8);

        // The cloth leans a little towards the pointer (not in the console corner).
        var lean = cv.getAttribute('data-ribbon') === 'console' || REDUCED ? 0 : 0.055;
        var px = 0, py = 0, tx = 0, ty = 0;
        if (lean && window.matchMedia('(hover: hover) and (pointer: fine)').matches) {
            window.addEventListener('pointermove', function (e) {
                tx = e.clientX / window.innerWidth - 0.5;
                ty = e.clientY / window.innerHeight - 0.5;
            }, { passive: true });
        }

        function curve(s, u, t, w, h, out) {
            var kind = cv.getAttribute('data-ribbon');
            var narrow = kind !== 'console' && w < 720, corner = kind === 'corner';
            for (var k = 0; k < 8; k += 2) {
                var x = mix(s.a[k], s.b[k], u), y = mix(s.a[k + 1], s.b[k + 1], u);
                if (k === 2 || k === 4) { // the inner control points drift, so the cloth breathes
                    var ph = t * s.speed * 6.2832 + s.phase + u * 2.4 + k;
                    x += Math.sin(ph) * s.amp + px * lean * (0.4 + u * 0.6);
                    y += Math.cos(ph * 0.8) * s.amp * 0.7 + py * lean * 0.7;
                }
                if (narrow) { x = 0.34 + 0.84 * x; y *= 0.52; } // phones: keep it in the top corner
                else if (corner) x = 0.4 + 0.62 * x;           // sub-pages: clear of the heading
                out[k] = x * w;
                out[k + 1] = y * h;
            }
        }

        stage(cv, function (ctx, w, h, t) {
            px += (tx - px) * 0.07;
            py += (ty - py) * 0.07;
            SHEETS.forEach(function (s) {
                var last = s.ca.length - 1, i, k;
                for (i = 0; i < s.n; i++) {
                    var um = (i + 0.5) / s.n;
                    curve(s, i / s.n, t, w, h, A);
                    curve(s, (i + 1.08) / s.n, t, w, h, B);
                    // a slow highlight wanders across the sheet, like light on silk
                    var sheen = 0.5 + 0.5 * Math.sin(um * 8.5 + s.phase + t * 0.22);
                    var al = mix(s.alpha[0], s.alpha[1], um * um * (3 - 2 * um));
                    var g = ctx.createLinearGradient(A[0], A[1], A[6], A[7]);
                    for (k = 0; k <= last; k++) {
                        g.addColorStop(k / last, rgba(mixc(mixc(s.ca[k], s.cb[k], um), WHITE, sheen * 0.26), al));
                    }
                    ctx.fillStyle = g;
                    ctx.beginPath();
                    ctx.moveTo(A[0], A[1]);
                    ctx.bezierCurveTo(A[2], A[3], A[4], A[5], A[6], A[7]);
                    ctx.lineTo(B[6], B[7]);
                    ctx.bezierCurveTo(B[4], B[5], B[2], B[3], B[0], B[1]);
                    ctx.closePath();
                    ctx.fill();
                }
                // fine streaks along the weave
                for (i = 1; i < s.n; i++) {
                    var u = i / s.n;
                    var a2 = mix(s.alpha[0], s.alpha[1], u) * (0.05 + 0.3 * s.streak[i]);
                    if (a2 < 0.02) continue;
                    curve(s, u, t, w, h, A);
                    ctx.strokeStyle = rgba(WHITE, a2);
                    ctx.lineWidth = 0.5 + s.streak[s.n - i] * 1.1;
                    ctx.beginPath();
                    ctx.moveTo(A[0], A[1]);
                    ctx.bezierCurveTo(A[2], A[3], A[4], A[5], A[6], A[7]);
                    ctx.stroke();
                }
            });
        }, 1.5, cv.getAttribute('data-ribbon') === 'console' ? 66 : 30); // the console corner idles at 15 fps
    }

    window.STCanvas.ribbon = ribbon;
    document.querySelectorAll('canvas[data-ribbon]').forEach(ribbon);
})();
