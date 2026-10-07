/* Theme bootstrap: applies the saved light/dark choice before first paint (light unless
   dark was chosen), exposes window.stTheme, and lets Chart.js use the CSS color tokens
   (canvas cannot read var()). */
(function () {
    var KEY = 'st-theme';
    var root = document.documentElement;

    // Light is the default; dark applies only once someone has chosen it.
    var saved = null;
    try { saved = localStorage.getItem(KEY); } catch (e) { /* storage blocked: stay light */ }
    root.setAttribute('data-theme', saved === 'dark' ? 'dark' : 'light');

    var media = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;

    function isDark() {
        var t = root.getAttribute('data-theme');
        return t ? t === 'dark' : !!(media && media.matches);
    }

    // Browsers report color-mix() results as "color(srgb r g b / a)", which canvas libraries can't parse.
    function toRgba(c) {
        var m = /^color\(srgb\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)(?:\s*\/\s*([\d.]+)(%?))?\s*\)$/.exec(c);
        if (!m) return c;
        var a = m[4] === undefined ? 1 : parseFloat(m[4]) / (m[5] ? 100 : 1);
        return 'rgba(' + Math.round(m[1] * 255) + ', ' + Math.round(m[2] * 255) + ', ' + Math.round(m[3] * 255) + ', ' + a + ')';
    }

    var probe = null;
    function resolve(value) {
        if (typeof value !== 'string' || (value.indexOf('var(') === -1 && value.indexOf('color-mix(') === -1)) return value;
        if (!probe) {
            probe = document.createElement('span');
            probe.style.display = 'none';
            (document.body || root).appendChild(probe);
        }
        probe.style.color = '';
        probe.style.color = value;
        return toRgba(getComputedStyle(probe).color || value);
    }

    function cssVar(name) {
        return getComputedStyle(root).getPropertyValue(name).trim();
    }

    function needsResolve(v) {
        return typeof v === 'string' && (v.indexOf('var(') !== -1 || v.indexOf('color-mix(') !== -1);
    }

    // Record every token string in a chart config so a theme switch can re-resolve it.
    function collect(obj, store, depth) {
        if (!obj || typeof obj !== 'object' || depth > 8) return;
        if (typeof Node !== 'undefined' && obj instanceof Node) return;
        var keys = Array.isArray(obj) ? obj.map(function (_, i) { return i; }) : Object.keys(obj);
        for (var i = 0; i < keys.length; i++) {
            var k = keys[i];
            var v = obj[k];
            if (typeof k === 'string' && (((k === 'data' || k === 'labels') && Array.isArray(v)) || k.charAt(0) === '_' || k.charAt(0) === '$')) continue;
            if (needsResolve(v)) {
                store.push({ o: obj, k: k, src: v });
                obj[k] = resolve(v);
            } else if (v && typeof v === 'object') {
                collect(v, store, depth + 1);
            }
        }
    }

    var reduceMotion = !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);

    // "rgb(r, g, b)" or "#rrggbb" with a new alpha.
    function withAlpha(color, a) {
        var m = /^rgba?\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)/.exec(color);
        if (m) return 'rgba(' + m[1] + ', ' + m[2] + ', ' + m[3] + ', ' + a + ')';
        m = /^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(color);
        if (m) return 'rgba(' + parseInt(m[1], 16) + ', ' + parseInt(m[2], 16) + ', ' + parseInt(m[3], 16) + ', ' + a + ')';
        return color;
    }

    // Area under a line: the line's own colour, fading out towards the axis.
    function softFill(context) {
        var chart = context.chart;
        var area = chart.chartArea;
        var line = context.dataset && context.dataset.borderColor;
        if (!area || typeof line !== 'string') return 'rgba(0, 0, 0, 0)';
        var g = chart.ctx.createLinearGradient(0, area.top, 0, area.bottom);
        g.addColorStop(0, withAlpha(line, 0.24));
        g.addColorStop(1, withAlpha(line, 0));
        return g;
    }

    function prepareChart(chart) {
        var store = chart.$stColors || (chart.$stColors = []);
        if (!chart.config) return;
        // Lines that did not choose a fill get the soft area. Done before the colours are
        // collected, so the point colour follows the theme like the line does.
        var type = chart.config.type;
        ((chart.config.data && chart.config.data.datasets) || []).forEach(function (ds) {
            if ((ds.type || type) !== 'line' || ds.$stFill || ds.fill !== undefined) return;
            ds.$stFill = true;
            if (ds.pointBackgroundColor === undefined) ds.pointBackgroundColor = ds.borderColor;
            ds.fill = 'origin';
            ds.backgroundColor = softFill;
        });
        collect(chart.config.data, store, 0);
        collect(chart.config.options, store, 0);
    }

    function hasData(chart) {
        return ((chart.config.data && chart.config.data.datasets) || []).some(function (ds) {
            return (ds.data || []).some(function (v) { return v && (typeof v !== 'object' || v.y); });
        });
    }

    var chartPlugin = {
        id: 'stThemeColors',
        beforeInit: prepareChart,
        beforeUpdate: prepareChart,
        // Line charts draw themselves in from the left, once, when their data first arrives.
        beforeDatasetsDraw: function (chart) {
            if (reduceMotion || chart.config.type !== 'line') return;
            var st = chart.$stReveal;
            if (!st) {
                if (!hasData(chart) || !chart.chartArea) return;
                st = chart.$stReveal = { start: performance.now(), done: false, clipped: false };
                var loop = function () {
                    if (st.done || !chart.ctx || !chart.canvas || !chart.canvas.isConnected) return;
                    chart.draw();
                    requestAnimationFrame(loop);
                };
                requestAnimationFrame(loop);
            }
            if (st.done) return;
            var p = Math.min(1, (performance.now() - st.start) / 1200);
            if (p >= 1) { st.done = true; return; }
            var a = chart.chartArea;
            var eased = 1 - Math.pow(1 - p, 3);
            chart.ctx.save();
            chart.ctx.beginPath();
            chart.ctx.rect(a.left - 6, a.top - 10, (a.width + 12) * eased, a.height + 20);
            chart.ctx.clip();
            st.clipped = true;
        },
        afterDatasetsDraw: function (chart) {
            var st = chart.$stReveal;
            if (st && st.clipped) { chart.ctx.restore(); st.clipped = false; }
        }
    };

    function setupChart() {
        var C = window.Chart;
        if (!C || !C.defaults) return;
        if (!chartPlugin.registered && typeof C.register === 'function') {
            C.register(chartPlugin);
            chartPlugin.registered = true;
        }
        var line = resolve('var(--st-border)');
        C.defaults.color = resolve('var(--st-text-muted)');
        C.defaults.borderColor = line;
        if (C.defaults.font) C.defaults.font.family = "'Inter', system-ui, sans-serif";
        if (C.defaults.scale && C.defaults.scale.grid) C.defaults.scale.grid.color = line;

        var legend = C.defaults.plugins && C.defaults.plugins.legend;
        if (legend && legend.labels) {
            legend.labels.color = resolve('var(--st-text-secondary)');
            legend.labels.usePointStyle = true;
            legend.labels.boxWidth = 8;
            legend.labels.boxHeight = 8;
        }

        // Tooltips read as the white cards from the landing page; bars get a soft corner.
        var tip = C.defaults.plugins && C.defaults.plugins.tooltip;
        if (tip) {
            tip.backgroundColor = resolve('var(--st-surface)');
            tip.titleColor = resolve('var(--st-text)');
            tip.bodyColor = resolve('var(--st-text-muted)');
            tip.borderColor = resolve('var(--st-border-strong)');
            tip.borderWidth = 1;
            tip.padding = 12;
            tip.cornerRadius = 6;
            tip.boxPadding = 6;
            tip.usePointStyle = true;
            tip.caretSize = 5;
            tip.titleFont = { family: "'Inter', system-ui, sans-serif", weight: '500', size: 13 };
            tip.bodyFont = { family: "'Inter', system-ui, sans-serif", size: 12.5 };
        }
        if (C.defaults.elements && C.defaults.elements.bar) C.defaults.elements.bar.borderRadius = 3;
        if (C.defaults.elements && C.defaults.elements.line) C.defaults.elements.line.borderCapStyle = 'round';

        // Charts draw themselves in once; later updates stay quick.
        if (C.defaults.animation && !reduceMotion) {
            C.defaults.animation.duration = 900;
            C.defaults.animation.easing = 'easeOutQuart';
        }

        var radial = C.defaults.scales && C.defaults.scales.radialLinear;
        if (radial) {
            if (radial.ticks) {
                radial.ticks.backdropColor = 'transparent';
                radial.ticks.color = resolve('var(--st-text-muted)');
            }
            if (radial.grid) radial.grid.color = line;
            if (radial.angleLines) radial.angleLines.color = line;
            if (radial.pointLabels) radial.pointLabels.color = resolve('var(--st-text-secondary)');
        }
    }

    function refreshCharts() {
        setupChart();
        var C = window.Chart;
        if (!C || !C.instances) return;
        Object.keys(C.instances).forEach(function (id) {
            var chart = C.instances[id];
            if (!chart) return;
            if (!chart.$stColors) prepareChart(chart);
            chart.$stColors.forEach(function (entry) { entry.o[entry.k] = resolve(entry.src); });
            chart.update('none');
        });
    }

    function refresh() {
        refreshCharts();
        var detail = { dark: isDark() };
        try {
            document.dispatchEvent(new CustomEvent('st-themechange', { detail: detail }));
        } catch (e) { /* very old browsers: no CustomEvent constructor */ }
        document.querySelectorAll('[data-theme-toggle]').forEach(function (btn) {
            btn.setAttribute('aria-pressed', detail.dark ? 'true' : 'false');
            btn.setAttribute('title', detail.dark ? 'Switch to light theme' : 'Switch to dark theme');
        });
    }

    function set(theme) {
        root.setAttribute('data-theme', theme);
        try { localStorage.setItem(KEY, theme); } catch (e) { /* ignore */ }
        refresh();
    }

    if (media) {
        var onChange = function () { if (!root.getAttribute('data-theme')) refresh(); };
        if (media.addEventListener) media.addEventListener('change', onChange);
        else if (media.addListener) media.addListener(onChange);
    }

    setupChart();
    document.addEventListener('DOMContentLoaded', refresh);

    // Loading state: figures shimmer (css/dashboard.css) from the first paint until their
    // real value is written, or four seconds pass. html.st-loading covers the time before
    // the document is parsed; after that each figure is tracked on its own. Text written
    // before the page's first data answer is taken to be a placeholder.
    var FIGURES = '.kpi-value, .metric-value, .kpi .kv, .hn-stat .value, .lg-kpi .v, .sp-kpi .v, .dv-kpi-val, .stat-num, .tile .v, .glow-card .gv, .micro-metric .value';
    root.classList.add('st-loading');
    document.addEventListener('DOMContentLoaded', function () {
        var main = document.querySelector('.main-content');
        var pending = main ? Array.prototype.slice.call(main.querySelectorAll(FIGURES)) : [];
        var clear = function (el) { el.classList.remove('st-fig-loading'); };
        pending.forEach(function (el) { el.classList.add('st-fig-loading'); });
        root.classList.remove('st-loading');
        if (!main) return;
        if (typeof MutationObserver === 'undefined') { pending.forEach(clear); return; }

        var dataSeen = false;
        var touched = [];
        var watch = new MutationObserver(function (records) {
            records.forEach(function (r) {
                // A strip the page builds itself before any data has arrived holds placeholders too.
                if (!dataSeen) {
                    Array.prototype.forEach.call(r.addedNodes || [], function (n) {
                        if (n.nodeType !== 1) return;
                        var figs = n.matches(FIGURES) ? [n] : n.querySelectorAll(FIGURES);
                        Array.prototype.forEach.call(figs, function (f) {
                            if (f.classList.contains('st-fig-loading')) return;
                            f.classList.add('st-fig-loading');
                            pending.push(f);
                            touched.push(f);
                        });
                    });
                }
                var node = r.target.nodeType === 1 ? r.target : r.target.parentElement;
                var fig = node && node.closest ? node.closest('.st-fig-loading') : null;
                if (!fig) return;
                if (dataSeen) clear(fig);
                else if (touched.indexOf(fig) === -1) touched.push(fig);
            });
        });
        watch.observe(main, { childList: true, characterData: true, subtree: true });

        // The first data answer: not the shell's own sign-in check, not the live stream.
        var onData = function () {
            dataSeen = true;
            touched.forEach(clear);
            touched = [];
        };
        try {
            var seen = new PerformanceObserver(function (list) {
                var hit = list.getEntries().some(function (e) {
                    return e.name.indexOf('/api/v1/') !== -1 && !/\/users\/me(\?|$)/.test(e.name) && e.name.indexOf('/live/stream') === -1;
                });
                if (!hit) return;
                seen.disconnect();
                setTimeout(onData, 60); // values written just ahead of this notice count too
            });
            seen.observe({ type: 'resource', buffered: true });
        } catch (e) { onData(); }

        setTimeout(function () {
            watch.disconnect();
            pending.forEach(clear);
        }, 4000);
    });

    window.stTheme = {
        isDark: isDark,
        set: set,
        toggle: function () { set(isDark() ? 'light' : 'dark'); },
        resolve: resolve,
        cssVar: cssVar,
        refresh: refresh
    };
})();
