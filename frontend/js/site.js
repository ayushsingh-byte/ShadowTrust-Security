/* Shared behavior for the public site pages: nav state, mobile menu, copy buttons, the
   hero ribbon canvas, and Motion-driven reveals (headline words and lines, [data-reveal],
   staggered groups, counters, the reading progress bar, the tilting product frame and
   the cards that lean towards the pointer).
   Everything degrades to a static page when Motion is missing or reduced motion is on. */
(function () {
    'use strict';

    var M = window.Motion;
    var reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    var canAnimate = !!M && !reduce;
    var EASE = [0.16, 1, 0.3, 1];

    window.STSite = { M: M, canAnimate: canAnimate, EASE: EASE };

    // Canvas helpers and the hero ribbon live in js/ribbon.js (loaded first).
    window.STSite.canvas = window.STCanvas;

    // Nav border once the page scrolls.
    var nav = document.querySelector('[data-nav]');
    if (nav) {
        var onScroll = function () { nav.classList.toggle('scrolled', window.scrollY > 8); };
        onScroll();
        window.addEventListener('scroll', onScroll, { passive: true });

        var burger = nav.querySelector('[data-burger]');
        if (burger) {
            burger.addEventListener('click', function () {
                var open = !nav.classList.contains('open');
                nav.classList.toggle('open', open);
                burger.setAttribute('aria-expanded', String(open));
            });
        }
    }

    // Copy-to-clipboard buttons.
    document.querySelectorAll('[data-copy]').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var text = btn.getAttribute('data-copy');
            var done = function () {
                var prev = btn.textContent;
                btn.textContent = 'Copied';
                setTimeout(function () { btn.textContent = prev; }, 1400);
            };
            if (navigator.clipboard) navigator.clipboard.writeText(text).then(done, function () {});
        });
    });

    // Short recordings inside tiles play only while they are on screen.
    var loops = document.querySelectorAll('video[data-loop]');
    if (loops.length && !reduce && 'IntersectionObserver' in window) {
        var loopWatch = new IntersectionObserver(function (entries) {
            entries.forEach(function (en) {
                if (!en.isIntersecting) { en.target.pause(); return; }
                var playing = en.target.play();
                if (playing && playing.catch) playing.catch(function () {});
            });
        }, { threshold: 0.5 });
        loops.forEach(function (v) { loopWatch.observe(v); });
    }

    // The eye in the header looks towards the pointer and blinks now and then.
    var eye = document.querySelector('.site-nav .brand svg');
    if (eye && !reduce && window.matchMedia('(hover: hover) and (pointer: fine)').matches) {
        var pupil = eye.querySelector('circle');
        var looking = 0, at = null;
        var look = function () {
            looking = 0;
            var r = eye.getBoundingClientRect();
            var dx = at.clientX - (r.left + r.width / 2), dy = at.clientY - (r.top + r.height / 2);
            var d = Math.sqrt(dx * dx + dy * dy) || 1;
            var reach = Math.min(1, d / 260); // nearby pointers move it less
            // the opening is wider than it is tall, so it travels further sideways (viewBox units)
            pupil.style.transform = 'translate(' + (dx / d * 3 * reach).toFixed(2) + 'px,' + (dy / d * 1.5 * reach).toFixed(2) + 'px)';
        };
        window.addEventListener('pointermove', function (e) {
            at = e;
            if (!looking) looking = requestAnimationFrame(look);
        }, { passive: true });
        var GAPS = [4200, 6100, 2900, 7400, 5200, 3600]; // uneven, so it does not read as a timer
        var blinks = 0;
        var blink = function () {
            if (!document.hidden) {
                eye.classList.add('blink');
                setTimeout(function () { eye.classList.remove('blink'); }, 120);
            }
            setTimeout(blink, GAPS[blinks++ % GAPS.length]);
        };
        setTimeout(blink, 2600);
    }

    // Cards lean towards the pointer and carry a soft light under it (css: .bento .card).
    // Uses the `rotate` property, so it never fights the reveal's transform.
    if (!reduce && window.matchMedia('(hover: hover) and (pointer: fine)').matches) {
        document.querySelectorAll('.bento .card').forEach(function (card) {
            var frame = 0, last = null;
            function apply() {
                frame = 0;
                var r = card.getBoundingClientRect();
                var nx = (last.clientX - r.left) / r.width - 0.5, ny = (last.clientY - r.top) / r.height - 0.5;
                // wide cards turn less, so their far edge never swings out
                var most = 2.4 * Math.min(1, 460 / Math.max(r.width, r.height));
                var angle = Math.min(1, Math.sqrt(nx * nx + ny * ny) * 2) * most;
                card.style.rotate = (-ny).toFixed(3) + ' ' + nx.toFixed(3) + ' 0 ' + angle.toFixed(2) + 'deg';
                card.style.setProperty('--gx', ((nx + 0.5) * 100).toFixed(1) + '%');
                card.style.setProperty('--gy', ((ny + 0.5) * 100).toFixed(1) + '%');
            }
            card.addEventListener('pointermove', function (e) {
                last = e;
                if (!frame) frame = requestAnimationFrame(apply);
            });
            card.addEventListener('pointerleave', function () {
                cancelAnimationFrame(frame);
                frame = 0;
                card.style.rotate = '';
            });
        });
    }

    if (!canAnimate) {
        document.documentElement.classList.remove('motion-ready');
        return;
    }

    // Reading progress along the top edge.
    if (M.scroll) {
        var bar = document.createElement('div');
        bar.className = 'scroll-progress';
        bar.setAttribute('aria-hidden', 'true');
        document.body.appendChild(bar);
        M.scroll(M.animate(bar, { scaleX: [0, 1] }, { ease: 'linear' }));
    }

    // Home headline: each word rises out of its own mask.
    var words = document.querySelectorAll('[data-words] .w > span');
    if (words.length) {
        M.animate(words, { y: ['112%', '0%'] }, { duration: 0.95, delay: M.stagger(0.07, { startDelay: 0.1 }), ease: EASE });
    }

    // Sub-page headline: each line slides up out of its own mask.
    document.querySelectorAll('[data-split] .line > span').forEach(function (el, i) {
        M.animate(el, { y: ['112%', '0%'] }, { duration: 1.05, delay: 0.1 + i * 0.12, ease: EASE });
    });

    var heroFades = document.querySelectorAll('[data-hero-fade]');
    if (heroFades.length) {
        M.animate(heroFades, { opacity: [0, 1], y: [18, 0] }, {
            duration: 0.85,
            delay: M.stagger(0.09, { startDelay: words.length ? 0.4 : 0.3 }),
            ease: EASE,
        });
    }

    // Product frame: starts leaning back and flattens as it scrolls into view.
    // The parent is measured because the frame's own box changes with its transform.
    var frame = document.querySelector('[data-tilt]');
    if (frame) {
        var ticking = false;
        var tilt = function () {
            ticking = false;
            var top = frame.parentElement.getBoundingClientRect().top;
            var vh = window.innerHeight;
            var p = Math.max(0, Math.min(1, (vh * 0.92 - top) / (vh * 0.6)));
            frame.style.transform = 'rotateX(' + (8 * (1 - p)).toFixed(2) + 'deg) scale(' + (0.95 + 0.05 * p).toFixed(4) + ')';
        };
        tilt();
        window.addEventListener('scroll', function () {
            if (!ticking) { ticking = true; requestAnimationFrame(tilt); }
        }, { passive: true });
        window.addEventListener('resize', tilt);
    }

    // Generic reveal on scroll.
    M.inView('[data-reveal]', function (el) {
        M.animate(el, { opacity: [0, 1], y: [22, 0] }, { duration: 0.85, ease: EASE });
    }, { amount: 0.25 });

    // Staggered children: lists, cards and columns marked with these attributes.
    ['[data-index] > li', '[data-cols] > .col', '[data-numbers] > .num', '[data-stagger] > *'].forEach(function (sel) {
        var groups = new Map();
        document.querySelectorAll(sel).forEach(function (el) {
            el.style.opacity = '0';
            var list = groups.get(el.parentElement) || [];
            list.push(el);
            groups.set(el.parentElement, list);
        });
        groups.forEach(function (items, parent) {
            M.inView(parent, function () {
                M.animate(items, { opacity: [0, 1], y: [20, 0], scale: [0.985, 1] }, { duration: 0.7, delay: M.stagger(0.055), ease: EASE });
            }, { amount: 0.08 });
        });
    });

    // Line glyphs draw themselves stroke by stroke.
    M.inView('svg[data-draw-in]', function (svg) {
        var shapes = svg.querySelectorAll('path, circle, rect, line, polyline, ellipse');
        var strokes = [];
        var fills = [];
        shapes.forEach(function (el) {
            if (el.getAttribute('stroke') === 'none') { fills.push(el); return; }
            el.setAttribute('pathLength', '1');
            el.style.strokeDasharray = '1';
            el.style.strokeDashoffset = '1';
            strokes.push(el);
        });
        fills.forEach(function (el) { el.style.opacity = '0'; });
        svg.style.opacity = '1';
        M.animate(strokes, { strokeDashoffset: [1, 0] }, { duration: 0.9, delay: M.stagger(0.08), ease: [0.65, 0, 0.35, 1] });
        if (fills.length) M.animate(fills, { opacity: [0, 1], scale: [0.4, 1] }, { duration: 0.5, delay: 0.5 + strokes.length * 0.08 });
    }, { amount: 0.6 });

    // Counters: count up from zero once visible.
    M.inView('[data-count]', function (el) {
        var target = parseFloat(el.getAttribute('data-count')) || 0;
        M.animate(0, target, {
            duration: 1.4,
            ease: [0.22, 1, 0.36, 1],
            onUpdate: function (v) { el.textContent = Math.round(v).toLocaleString(); },
        });
    }, { amount: 0.6 });
})();
