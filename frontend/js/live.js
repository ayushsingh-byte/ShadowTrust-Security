/* One authenticated Server-Sent Events connection per page, shared by every widget.
   Channels: "event" (normalized honeypot events), "detection" (detection-engine cycles
   that produced detections or incidents), "metrics" (sensor container resource samples). */
(function () {
    if (window.STLive) return;

    const isLocalDev = ['127.0.0.1', 'localhost', '0.0.0.0'].includes(window.location.hostname)
        || window.location.protocol === 'file:';
    const API_BASE = isLocalDev ? 'http://127.0.0.1:8000/api/v1' : '/api/v1';
    const CHANNELS = ['event', 'detection', 'metrics'];
    const MAX_BACKOFF_MS = 15000;

    const listeners = {};
    let source = null;
    let status = 'idle';
    let backoff = 1000;
    let retryTimer = null;
    let connecting = false;

    const token = () => localStorage.getItem('access_token') || localStorage.getItem('authToken');

    function setStatus(next) {
        if (status === next) return;
        status = next;
        document.dispatchEvent(new CustomEvent('st-live-status', { detail: { status } }));
    }

    function emit(channel, payload) {
        (listeners[channel] || []).slice().forEach((fn) => {
            try { fn(payload); } catch (err) { console.error('[live]', channel, err); }
        });
    }

    function parse(msg) {
        try { return JSON.parse(msg.data); } catch (_) { return null; }
    }

    function scheduleReconnect() {
        clearTimeout(retryTimer);
        setStatus('reconnecting');
        retryTimer = setTimeout(connect, backoff);
        backoff = Math.min(backoff * 2, MAX_BACKOFF_MS);
    }

    async function connect() {
        if (connecting || (source && source.readyState !== EventSource.CLOSED)) return;
        const bearer = token();
        if (!bearer) { setStatus('signed-out'); return; }

        connecting = true;
        if (status === 'idle') setStatus('connecting');
        let ticket;
        try {
            const res = await fetch(`${API_BASE}/live/stream-ticket`, {
                method: 'POST',
                headers: { Authorization: `Bearer ${bearer}` },
                cache: 'no-store',
            });
            if (res.status === 401) { setStatus('signed-out'); return; }
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            ticket = (await res.json()).ticket;
        } catch (_) {
            scheduleReconnect();
            return;
        } finally {
            connecting = false;
        }

        // Tickets are single-use, so reconnects fetch a fresh one here instead of relying
        // on EventSource's built-in retry, which would replay the spent ticket.
        source = new EventSource(`${API_BASE}/live/stream?ticket=${encodeURIComponent(ticket)}`);
        source.addEventListener('ready', (msg) => {
            backoff = 1000;
            setStatus('live');
            emit('ready', parse(msg));
        });
        source.addEventListener('heartbeat', () => setStatus('live'));
        CHANNELS.forEach((channel) => source.addEventListener(channel, (msg) => {
            const payload = parse(msg);
            if (payload) emit(channel, payload);
        }));
        source.onerror = () => {
            source.close();
            scheduleReconnect();
        };
    }

    window.STLive = {
        apiBase: API_BASE,
        get status() { return status; },
        connect,
        on(channel, fn) {
            (listeners[channel] = listeners[channel] || []).push(fn);
            connect();
            return () => { listeners[channel] = (listeners[channel] || []).filter((f) => f !== fn); };
        },
        debounce(fn, wait) {
            let timer = null;
            return (...args) => {
                clearTimeout(timer);
                timer = setTimeout(() => fn(...args), wait);
            };
        },
    };
})();
