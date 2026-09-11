/**
 * Event Log — the local telemetry pipeline dashboard (SSE + polling).
 *
 * Data flow this page renders:
 *   sensor -> telemetry/raw/<sensor>/*.json -> collector -> normalizer
 *          -> normalized_events (SQLite) -> /api/v1/live/* -> this page
 *
 * Two update paths, deliberately both present:
 *   - SSE (/live/stream) pushes each new event the instant the collector
 *     writes it, and drives the live feed + sensor "last event" ticking.
 *   - Polling (/live/overview, /live/attackers, /live/sensors) every few
 *     seconds keeps the aggregate counters and attacker table correct even
 *     if a browser tab missed events while backgrounded, or connected after
 *     the events it would have needed to recompute a count already happened.
 * SSE is the "make it feel live" layer; polling is the "make it right" layer.
 */

(function () {
    const isLocalDev = window.location.hostname === '127.0.0.1' ||
        window.location.hostname === 'localhost' ||
        window.location.hostname === '0.0.0.0' ||
        window.location.protocol === 'file:';
    // In local dev the page is often opened straight off disk or via a bare
    // static server, so talk to the backend container's published port
    // directly. Once nginx is fronting both (the normal docker compose path)
    // relative /api/v1 goes through the same-origin proxy in nginx.conf.
    const API_BASE = isLocalDev ? 'http://127.0.0.1:8000/api/v1' : '/api/v1';

    const POLL_INTERVAL_MS = 30000;  // fallback only; pushed events trigger refreshes
    const MAX_FEED_ROWS = 200;

    const $ = (sel) => document.querySelector(sel);

    const el = {
        conn: $('#hn-conn'),
        connLabel: $('#hn-conn-label'),
        statTotal: $('#stat-total'),
        statSessions: $('#stat-sessions'),
        statIps: $('#stat-ips'),
        statCommands: $('#stat-commands'),
        statAttacks: $('#stat-attacks'),
        statSensors: $('#stat-sensors'),
        feed: $('#hn-feed'),
        sensors: $('#hn-sensors'),
        attackers: $('#hn-attackers tbody'),
        attackerCount: $('#hn-attacker-count'),
        events: $('#hn-events tbody'),
        eventCount: $('#hn-event-count'),
        timeline: $('#hn-timeline'),
        timelineTitle: $('#hn-timeline-title'),
        filterSensor: $('#filter-sensor'),
        filterSeverity: $('#filter-severity'),
        filterIp: $('#filter-ip'),
        filterApply: $('#filter-apply'),
        filterClear: $('#filter-clear'),
    };

    let selectedIp = null;

    // ── helpers ──────────────────────────────────────────────────────────────

    function fmtTime(iso) {
        if (!iso) return '--:--:--';
        const d = new Date(iso.endsWith('Z') || iso.includes('+') ? iso : iso + 'Z');
        if (isNaN(d.getTime())) return iso;
        return d.toLocaleTimeString('en-US', { hour12: false });
    }

    function fmtRelative(iso) {
        if (!iso) return 'never';
        const d = new Date(iso.endsWith('Z') || iso.includes('+') ? iso : iso + 'Z');
        const s = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000));
        if (s < 60) return `${s}s ago`;
        if (s < 3600) return `${Math.floor(s / 60)}m ago`;
        if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
        return `${Math.floor(s / 86400)}d ago`;
    }

    function esc(s) {
        if (s === null || s === undefined) return '';
        return String(s).replace(/[&<>"']/g, (c) => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
        }[c]));
    }

    function describeEvent(ev) {
        // One human line per sensor-event-type. Falls back to the raw type
        // for anything not called out explicitly, so a new Cowrie event kind
        // still shows *something* instead of a blank cell.
        const type = ev.sensor_event_type || '';
        if (type.includes('login')) {
            const result = ev.authentication_result === 'SUCCESS' ? 'succeeded' : 'failed';
            return `login ${result} <span class="ip">user=${esc(ev.username || '?')}</span>`;
        }
        if (type.includes('command')) {
            return `<span class="cmd">$ ${esc(ev.command || '')}</span>`;
        }
        if (type.includes('connect')) {
            return `connection opened, dst port ${esc(ev.destination_port ?? '?')}`;
        }
        if (type.includes('closed') || type.includes('disconnect')) {
            return 'session closed';
        }
        return esc(type || 'event');
    }

    function severityBadge(sev) {
        const s = sev || 'INFO';
        return `<span class="hn-sev hn-sev-${esc(s)}">${esc(s)}</span>`;
    }

    async function getJSON(path) {
        const token = localStorage.getItem('access_token') || localStorage.getItem('authToken');
        const res = await fetch(`${API_BASE}${path}`, {
            cache: 'no-store',
            headers: token ? { Authorization: `Bearer ${token}` } : {},
        });
        if (res.status === 401) {
            window.location.href = 'login.html';
            throw new Error('Session expired');
        }
        if (!res.ok) throw new Error(`${path} -> HTTP ${res.status}`);
        return res.json();
    }

    // ── rendering ────────────────────────────────────────────────────────────

    function prependFeedRow(ev, isNew) {
        if (el.feed.querySelector('.hn-empty')) el.feed.innerHTML = '';

        const row = document.createElement('div');
        row.className = 'hn-feed-row' + (isNew ? ' hn-new' : '');
        row.innerHTML = `
            <span class="ts">${fmtTime(ev.timestamp)}</span>
            <span class="sensor">${esc(ev.sensor)}</span>
            ${severityBadge(ev.severity)}
            <span class="detail"><span class="ip">${esc(ev.source_ip || '?')}</span> — ${describeEvent(ev)}</span>
        `;
        el.feed.insertBefore(row, el.feed.firstChild);

        while (el.feed.children.length > MAX_FEED_ROWS) {
            el.feed.removeChild(el.feed.lastChild);
        }
    }

    function renderOverview(o) {
        el.statTotal.textContent = o.total_events.toLocaleString();
        el.statSessions.textContent = o.active_sessions.toLocaleString();
        el.statIps.textContent = o.unique_source_ips.toLocaleString();
        el.statCommands.textContent = o.commands_executed.toLocaleString();
        const attacks = (o.severity_breakdown?.HIGH || 0) + (o.severity_breakdown?.CRITICAL || 0);
        el.statAttacks.textContent = attacks.toLocaleString();
        el.statAttacks.parentElement.classList.toggle('crit', attacks > 0);
        el.statSensors.textContent = `${o.sensors_online}/${o.sensors_known}`;
        el.statSensors.parentElement.classList.toggle('warn', o.sensors_online < o.sensors_known);
    }

    function renderSensors(sensors) {
        el.sensors.innerHTML = sensors.map((s) => `
            <div class="hn-sensor-row">
                <div>
                    <div class="hn-sensor-name">${esc(s.sensor)}</div>
                    <div class="hn-sensor-meta">${s.event_count.toLocaleString()} events · ${s.unique_source_ips} src IP${s.unique_source_ips === 1 ? '' : 's'}</div>
                </div>
                <div style="text-align:right">
                    <div class="hn-badge hn-badge-${esc(s.status)}">${esc(s.status)}</div>
                    <div class="hn-sensor-meta">${fmtRelative(s.last_event)}</div>
                </div>
            </div>
        `).join('') || '<div class="hn-empty">No sensor data yet</div>';
    }

    function renderAttackers(attackers) {
        el.attackerCount.textContent = attackers.length;
        el.attackers.innerHTML = attackers.map((a) => `
            <tr data-ip="${esc(a.source_ip)}" class="${a.source_ip === selectedIp ? 'hn-selected' : ''}">
                <td>${esc(a.source_ip)}</td>
                <td>${severityBadge(a.severity)}</td>
                <td>${a.event_count}</td>
                <td><div class="hn-tags">${a.sensors.map(s => `<span class="hn-tag">${esc(s)}</span>`).join('')}</div></td>
                <td><div class="hn-tags">${a.ports_targeted.slice(0, 6).map(p => `<span class="hn-tag">${esc(p)}</span>`).join('')}</div></td>
                <td><div class="hn-tags">${a.usernames_attempted.slice(0, 6).map(u => `<span class="hn-tag">${esc(u)}</span>`).join('')}</div></td>
                <td>${a.successful_logins > 0 ? `<span style="color:var(--accent-critical)">${a.successful_logins}</span>` : '0'}</td>
                <td>${fmtRelative(a.last_seen)}</td>
            </tr>
        `).join('') || `<tr><td colspan="8" class="hn-empty">No attacker activity recorded yet</td></tr>`;

        el.attackers.querySelectorAll('tr[data-ip]').forEach((tr) => {
            tr.addEventListener('click', () => selectAttacker(tr.dataset.ip));
        });
    }

    function renderEvents(events) {
        el.eventCount.textContent = events.length;
        el.events.innerHTML = events.map((ev) => `
            <tr>
                <td class="ts">${fmtTime(ev.timestamp)}</td>
                <td>${esc(ev.sensor)}</td>
                <td>${esc(ev.sensor_event_type)}</td>
                <td>${esc(ev.source_ip || '')}</td>
                <td>${esc(ev.username || '')}</td>
                <td>${esc(ev.command || '')}</td>
                <td>${severityBadge(ev.severity)}</td>
            </tr>
        `).join('') || `<tr><td colspan="7" class="hn-empty">No events match these filters</td></tr>`;
    }

    function renderTimeline(profile) {
        if (!profile.found) {
            el.timelineTitle.textContent = 'Select an attacker to see their timeline';
            el.timeline.innerHTML = '<div class="hn-empty">No data</div>';
            return;
        }
        el.timelineTitle.textContent = `${profile.source_ip} — ${profile.event_count} event(s), first seen ${fmtRelative(profile.first_seen)}`;
        el.timeline.innerHTML = profile.timeline.map((ev) => `
            <div class="hn-timeline-item">
                <span class="ts">${fmtTime(ev.timestamp)}</span>
                <span>${esc(ev.sensor)} · ${describeEvent(ev)}</span>
            </div>
        `).join('');
    }

    async function selectAttacker(ip) {
        selectedIp = ip;
        el.attackers.querySelectorAll('tr[data-ip]').forEach((tr) => {
            tr.classList.toggle('hn-selected', tr.dataset.ip === ip);
        });
        try {
            const profile = await getJSON(`/live/attackers/${encodeURIComponent(ip)}`);
            renderTimeline(profile);
        } catch (e) {
            console.error('[honeynet] attacker detail failed', e);
        }
    }

    // ── polling ──────────────────────────────────────────────────────────────

    function currentFilters() {
        const params = new URLSearchParams();
        if (el.filterSensor.value) params.set('sensor', el.filterSensor.value);
        if (el.filterSeverity.value) params.set('severity', el.filterSeverity.value);
        if (el.filterIp.value.trim()) params.set('source_ip', el.filterIp.value.trim());
        params.set('limit', '100');
        return params.toString();
    }

    let feedSeeded = false;

    // The live feed fills from the SSE "event" channel, but that only carries NEW
    // telemetry. Seed it once from the most recent stored events so an idle honeypot
    // doesn't sit on "Waiting for telemetry"; a filter change forces a reseed.
    function seedFeed(events) {
        if (feedSeeded) return;
        el.feed.innerHTML = events && events.length
            ? '' : '<div class="hn-empty">No events recorded yet</div>';
        (events || []).slice(0, MAX_FEED_ROWS).reverse().forEach((ev) => prependFeedRow(ev, false));
        feedSeeded = true;
    }

    async function pollAll() {
        try {
            const [overview, sensors, attackers, events] = await Promise.all([
                getJSON('/live/overview'),
                getJSON('/live/sensors'),
                getJSON('/live/attackers'),
                getJSON(`/live/events?${currentFilters()}`),
            ]);
            renderOverview(overview);
            renderSensors(sensors);
            renderAttackers(attackers);
            renderEvents(events);
            seedFeed(events);
            if (selectedIp) selectAttacker(selectedIp);
        } catch (e) {
            console.error('[honeynet] poll failed', e);
        }
    }

    // ── live stream ──────────────────────────────────────────────────────────

    function setConn(state, label) {
        el.conn.className = `hn-conn ${state}`;
        el.connLabel.textContent = label;
    }

    function connectStream() {
        if (!window.STLive) {
            setConn('down', 'Live stream unavailable');
            return;
        }
        const labels = { idle: 'Connecting…', connecting: 'Connecting…', reconnecting: 'Reconnecting…', 'signed-out': 'Signed out' };
        const showStatus = (status) => {
            if (status === 'live') setConn('live', 'Live');
            else setConn(status === 'signed-out' ? 'down' : '', labels[status] || status);
        };
        showStatus(window.STLive.status);
        document.addEventListener('st-live-status', (e) => showStatus(e.detail.status));

        // Counters, sensors and attacker profiles re-query shortly after pushed events.
        const refreshAggregates = window.STLive.debounce(pollAll, 1500);
        window.STLive.on('event', (ev) => {
            prependFeedRow(ev, true);
            refreshAggregates();
            const published = Date.parse(ev.published_at || '');
            if (typeof ev.pipeline_latency_ms === 'number' && !Number.isNaN(published)) {
                const endToEnd = Math.max(0, Math.round(ev.pipeline_latency_ms + (Date.now() - published)));
                setConn('live', `Live · ${endToEnd} ms sensor→browser`);
            }
        });
    }

    // ── wiring ───────────────────────────────────────────────────────────────

    const reFilter = () => { feedSeeded = false; pollAll(); };
    el.filterApply.addEventListener('click', reFilter);
    el.filterClear.addEventListener('click', () => {
        el.filterSensor.value = '';
        el.filterSeverity.value = '';
        el.filterIp.value = '';
        reFilter();
    });
    el.filterIp.addEventListener('keydown', (e) => { if (e.key === 'Enter') reFilter(); });

    connectStream();
    pollAll();
    setInterval(pollAll, POLL_INTERVAL_MS);
})();
