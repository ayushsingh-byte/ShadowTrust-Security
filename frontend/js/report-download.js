/**
 * Shared report generation + download helper.
 * Every "generate report / export" button on the dashboard routes through here so
 * reports are produced by the backend PDF engine, recorded in the Reports page,
 * and downloaded with the server-assigned filename.
 */
(function () {
    function apiBase() {
        const local = ['127.0.0.1', 'localhost', '0.0.0.0'].includes(location.hostname)
            || location.protocol === 'file:';
        return local ? 'http://127.0.0.1:8000/api/v1' : '/api/v1';
    }

    function token() {
        return localStorage.getItem('access_token') || localStorage.getItem('authToken') || '';
    }

    function toast(msg, kind) {
        let el = document.getElementById('__report_toast');
        if (!el) {
            el = document.createElement('div');
            el.id = '__report_toast';
            el.style.cssText = 'position:fixed;bottom:22px;right:22px;z-index:99999;max-width:360px;'
                + 'padding:12px 16px;border-radius:6px;font:13px/1.4 monospace;white-space:pre-wrap;'
                + 'box-shadow:0 8px 24px rgba(0,0,0,.4);transition:opacity .3s';
            document.body.appendChild(el);
        }
        const colors = {
            ok: 'background:var(--st-surface-hover);border:1px solid var(--st-success);color:var(--st-success)',
            err: 'background:var(--st-surface);border:1px solid var(--st-danger);color:var(--st-danger)',
            info: 'background:var(--st-surface-hover);border:1px solid var(--st-info);color:var(--st-info)',
        };
        el.style.cssText += ';' + (colors[kind] || colors.info);
        el.textContent = msg;
        el.style.opacity = '1';
        clearTimeout(el._t);
        el._t = setTimeout(() => { el.style.opacity = '0'; }, kind === 'err' ? 8000 : 4500);
    }

    async function generateAndDownload(reportType, params, opts) {
        opts = opts || {};
        const base = apiBase();
        const btn = opts.button;
        const label = btn ? btn.innerHTML : null;
        if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generating…'; }
        toast('Generating ' + (opts.title || reportType) + ' report…', 'info');
        try {
            const r = await fetch(`${base}/reports/${reportType}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token()}` },
                body: JSON.stringify({ params: params || {} }),
            });
            const d = await r.json();
            if (!r.ok) throw new Error(d.detail || ('HTTP ' + r.status));

            const dl = await fetch(`${base}/reports/${d.id}/download`, {
                headers: { 'Authorization': `Bearer ${token()}` },
            });
            if (!dl.ok) throw new Error('download failed (HTTP ' + dl.status + ')');
            const blob = await dl.blob();
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = d.filename;
            document.body.appendChild(a); a.click(); a.remove();
            URL.revokeObjectURL(a.href);
            toast('✓ ' + d.filename + '\nSHA-256 ' + (d.sha256 || '').slice(0, 24) + '…', 'ok');
            return d;
        } catch (e) {
            toast('Report failed: ' + e.message, 'err');
            throw e;
        } finally {
            if (btn) { btn.disabled = false; if (label) btn.innerHTML = label; }
        }
    }

    function downloadBlob(filename, text, mime) {
        const a = document.createElement('a');
        a.href = URL.createObjectURL(new Blob([text], { type: mime || 'text/plain' }));
        a.download = filename;
        document.body.appendChild(a); a.click(); a.remove();
        URL.revokeObjectURL(a.href);
    }

    window.STReports = { generateAndDownload, downloadBlob, toast, apiBase, token };
})();
