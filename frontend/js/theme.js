/* Theme bootstrap: applies the saved light/dark choice before first paint, exposes
   window.stTheme, and lets Chart.js use the CSS color tokens (canvas cannot read var()). */
(function () {
    var KEY = 'st-theme';
    var root = document.documentElement;

    try {
        var saved = localStorage.getItem(KEY);
        if (saved === 'light' || saved === 'dark') root.setAttribute('data-theme', saved);
    } catch (e) { /* storage blocked: follow the OS setting */ }

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

    function prepareChart(chart) {
        var store = chart.$stColors || (chart.$stColors = []);
        if (!chart.config) return;
        collect(chart.config.data, store, 0);
        collect(chart.config.options, store, 0);
    }

    var chartPlugin = {
        id: 'stThemeColors',
        beforeInit: prepareChart,
        beforeUpdate: prepareChart
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
        if (C.defaults.font) C.defaults.font.family = "'Public Sans', system-ui, sans-serif";
        if (C.defaults.scale && C.defaults.scale.grid) C.defaults.scale.grid.color = line;

        var legend = C.defaults.plugins && C.defaults.plugins.legend;
        if (legend && legend.labels) legend.labels.color = resolve('var(--st-text-secondary)');

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

    window.stTheme = {
        isDark: isDark,
        set: set,
        toggle: function () { set(isDark() ? 'light' : 'dark'); },
        resolve: resolve,
        cssVar: cssVar,
        refresh: refresh
    };
})();
