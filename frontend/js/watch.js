/* The watching eye on the sign-in pages. The iris follows the pointer, the eye blinks now
   and then, and it closes while a password field has focus (and peeks if the password is shown).
   Reduced motion: the eye stays open and still. */
(function () {
    'use strict';

    var svg = document.querySelector('[data-watch]');
    if (!svg) return;
    var lens = svg.querySelector('[data-lens]');
    var clip = svg.querySelector('[data-lens-clip]');
    var iris = svg.querySelector('[data-iris]');
    var lashes = svg.querySelector('[data-lashes]');
    var reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // Lens: the upper lid's control points travel from 12 (open) down to 150 (shut).
    function lensPath(t) {
        var y = 12 + (150 - 12) * t;
        return 'M14 85 C 70 ' + y + ', 210 ' + y + ', 266 85 C 210 158, 70 158, 14 85 Z';
    }

    var lid = 0;
    function setLid(t) {
        lid = t;
        var d = lensPath(t);
        lens.setAttribute('d', d);
        clip.setAttribute('d', d);
        lashes.style.opacity = String(Math.max(0, (t - 0.7) / 0.3));
    }
    setLid(0);

    // Sign-in success: the eye blinks, the ribbon's colours wipe across the page and the
    // console opens behind them. With reduced motion the console simply opens.
    window.STEnter = function (url) {
        if (reduce) { location.href = url; return; }
        lidTo(1, 110);
        setTimeout(function () { lidTo(0, 150); }, 150);
        var sweep = document.createElement('div');
        sweep.className = 'auth-sweep';
        sweep.setAttribute('aria-hidden', 'true');
        sweep.innerHTML = '<svg viewBox="0 0 28 28" fill="none"><path d="M2.5 14c3-5.3 7-8 11.5-8s8.5 2.7 11.5 8c-3 5.3-7 8-11.5 8S5.5 19.3 2.5 14Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><circle cx="14" cy="14" r="4.2" fill="currentColor"/></svg>';
        setTimeout(function () { document.body.appendChild(sweep); }, 280);
        setTimeout(function () { location.href = url; }, 1020);
    };

    if (reduce) return;

    var target = 0;
    var tween = null;
    function lidTo(t, ms) {
        target = t;
        if (tween) cancelAnimationFrame(tween);
        var from = lid;
        var start = performance.now();
        var step = function (now) {
            var k = Math.min(1, (now - start) / ms);
            var e = k < 0.5 ? 2 * k * k : 1 - Math.pow(-2 * k + 2, 2) / 2;
            setLid(from + (t - from) * e);
            if (k < 1) tween = requestAnimationFrame(step);
        };
        tween = requestAnimationFrame(step);
    }

    // Password fields: close while typing, peek when the text is revealed.
    function passwordState() {
        var el = document.activeElement;
        if (!el || el.tagName !== 'INPUT') return 0;
        if (el.type === 'password') return 1;
        if (el.dataset.wasPassword === '1') return 0.55;
        return 0;
    }
    document.querySelectorAll('input[type="password"]').forEach(function (inp) {
        inp.dataset.wasPassword = '1';
    });
    function sync() { lidTo(passwordState(), 260); }
    document.addEventListener('focusin', sync);
    document.addEventListener('focusout', function () { setTimeout(sync, 0); });
    document.addEventListener('click', function (e) {
        if (e.target.closest('.eye-btn')) setTimeout(function () {
            var btn = e.target.closest('.eye-btn');
            var inp = btn && btn.parentElement.querySelector('input');
            if (inp) inp.focus();
            sync();
        }, 0);
    });

    // Blink every few seconds when the eye is open.
    (function blink() {
        setTimeout(function () {
            if (target === 0 && !document.hidden) {
                lidTo(1, 90);
                setTimeout(function () { if (target === 1 && passwordState() === 0) lidTo(0, 140); }, 110);
            }
            blink();
        }, 3200 + Math.random() * 4200);
    })();

    // Iris follows the pointer with a little lag.
    var tx = 0, ty = 0, cx = 0, cy = 0;
    window.addEventListener('pointermove', function (e) {
        var r = svg.getBoundingClientRect();
        var ex = r.left + r.width / 2;
        var ey = r.top + r.height / 2;
        var dx = e.clientX - ex;
        var dy = e.clientY - ey;
        var dist = Math.hypot(dx, dy) || 1;
        var reach = Math.min(1, dist / 380);
        tx = (dx / dist) * 46 * reach;
        ty = (dy / dist) * 26 * reach;
    }, { passive: true });
    (function loop() {
        cx += (tx - cx) * 0.12;
        cy += (ty - cy) * 0.12;
        iris.setAttribute('transform', 'translate(' + cx.toFixed(2) + ' ' + cy.toFixed(2) + ')');
        requestAnimationFrame(loop);
    })();
})();
