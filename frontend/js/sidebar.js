/**
 * Shared sidebar for every app page. The base navigation renders immediately; GET /users/me
 * then decides whether the Administration group and [data-admin-only] controls appear.
 * Pages marked <html data-require-admin> stay hidden until an admin role is verified.
 */
document.addEventListener('DOMContentLoaded', function () {
    const root = document.documentElement;
    const sidebar = document.getElementById('sidebar');
    const ADMIN_ROLES = ['SUPER_ADMIN', 'ADMIN'];
    const COLLAPSE_KEY = 'st-sidebar-collapsed';
    const SCROLL_KEY = 'sidebarScrollPosition';

    const isLocalDev = ['127.0.0.1', 'localhost', '0.0.0.0'].includes(window.location.hostname)
        || window.location.protocol === 'file:';
    const API_BASE = isLocalDev ? 'http://127.0.0.1:8000/api/v1' : '/api/v1';
    const token = () => localStorage.getItem('access_token') || localStorage.getItem('authToken');

    let mePromise = null;
    function fetchMe() {
        if (!mePromise) {
            mePromise = (async () => {
                const bearer = token();
                if (!bearer) return null;
                try {
                    const res = await fetch(`${API_BASE}/users/me`, {
                        headers: { Authorization: `Bearer ${bearer}` },
                        cache: 'no-store',
                    });
                    return res.ok ? await res.json() : null;
                } catch (_) {
                    return null;
                }
            })();
        }
        return mePromise;
    }

    const isAdmin = (user) => !!user && ADMIN_ROLES.includes(user.role);
    window.stSession = { me: fetchMe, isAdmin };

    if (root.hasAttribute('data-require-admin')) {
        fetchMe().then((user) => {
            if (!user) { window.location.replace('admin_login.html'); return; }
            if (!isAdmin(user)) { window.location.replace('dashboard.html'); return; }
            root.setAttribute('data-admin-verified', '');
        });
    }

    let currentUser = null;

    fetchMe().then((user) => {
        currentUser = user;
        if (isAdmin(user)) {
            root.setAttribute('data-admin-session', '');
            localStorage.setItem('isAdmin', 'true');
            localStorage.setItem('userRole', user.role || '');
        } else {
            root.removeAttribute('data-admin-session');
            localStorage.removeItem('isAdmin');
        }
        if (sidebar) render();
    });

    if (!sidebar) return;

    const currentPage = (window.location.pathname.split('/').pop() || '').split('?')[0] || 'dashboard.html';
    const mobileQuery = window.matchMedia('(max-width: 900px)');

    const NAV_GROUPS = [
        {
            label: 'Command Center',
            items: [
                { href: 'dashboard.html', icon: 'fas fa-th-large', text: 'Tactical Overview' },
                { href: 'incidents.html', icon: 'fas fa-folder-open', text: 'Investigations' },
                { href: 'events.html', icon: 'fas fa-list-alt', text: 'Event Log' },
                { href: 'logs.html', icon: 'fas fa-layer-group', text: 'Logs' },
                { href: 'reports.html', icon: 'fas fa-file-pdf', text: 'Reports' },
            ],
        },
        {
            label: 'Grid Monitoring',
            items: [
                { href: 'nodes.html', icon: 'fas fa-server', text: 'Honeypot Nodes' },
                { href: 'splunk.html', icon: 'fas fa-shield-alt', text: 'Splunk Blue Team' },
                { href: 'geo.html', icon: 'fas fa-globe-americas', text: 'Geo Intelligence' },
            ],
        },
        {
            label: 'Intelligence',
            items: [
                { href: 'mitre.html', icon: 'fas fa-chess-board', text: 'MITRE Matrix' },
                { href: 'validation.html', icon: 'fas fa-vial', text: 'Detection Validation' },
                { href: 'graphs.html', icon: 'fas fa-chart-area', text: 'Attack Analytics' },
                { href: 'credentials.html', icon: 'fas fa-key', text: 'Credentials Vault' },
                { href: 'behavior.html', icon: 'fas fa-user-secret', text: 'Behavior Profiling' },
                { href: 'analysis_lab.html', icon: 'fas fa-terminal', text: 'Analysis Lab' },
            ],
        },
        {
            label: 'Governance',
            items: [
                { href: 'grc.html', icon: 'fas fa-clipboard-check', text: 'GRC & SOC 2' },
            ],
        },
        {
            label: 'Tools Suite',
            items: [
                { href: 'malware.html', icon: 'fas fa-biohazard', text: 'Binary Analysis' },
                { href: 'urlscan.html', icon: 'fas fa-search-location', text: 'URL Scanner' },
                { href: 'apk.html', icon: 'fas fa-mobile', text: 'APK Inspector' },
                { href: 'vm_lab.html', icon: 'fas fa-laptop-code', text: 'Virtual Lab' },
            ],
        },
        {
            label: 'Account',
            items: [
                { href: 'profile.html', icon: 'fas fa-user-circle', text: 'Officer Profile' },
            ],
        },
    ];

    const ADMIN_GROUP = {
        label: 'Administration',
        items: [
            { href: 'admin.html#section-overview', icon: 'fas fa-tachometer-alt', text: 'Global Overview' },
            { href: 'admin.html#section-users', icon: 'fas fa-users-cog', text: 'User Management' },
            { href: 'access_control.html', icon: 'fas fa-user-lock', text: 'Access Control Console' },
            { href: 'credential_mgmt.html', icon: 'fas fa-key', text: 'Credential Management' },
            { href: 'aws_connection.html', icon: 'fab fa-aws', text: 'AWS Connection' },
            { href: 'admin.html#section-nodes', icon: 'fas fa-network-wired', text: 'Node Control' },
            { href: 'admin.html#section-settings', icon: 'fas fa-cogs', text: 'System Settings' },
            { href: 'admin.html#section-debug', icon: 'fas fa-microchip', text: 'System Debug' },
        ],
    };

    const LIVE_LABELS = {
        idle: 'Connecting…',
        connecting: 'Connecting…',
        live: 'Live stream connected',
        reconnecting: 'Reconnecting…',
        'signed-out': 'Not signed in',
    };
    let liveStatus = token() ? 'connecting' : 'signed-out';

    const escapeHtml = (value) => String(value == null ? '' : value).replace(/[&<>"']/g, (ch) => (
        { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]
    ));

    function isActive(href) {
        const [page, hash] = href.split('#');
        if (page !== currentPage) return false;
        if (!hash) return true;
        return window.location.hash ? window.location.hash === `#${hash}` : hash === 'section-overview';
    }

    function navHtml() {
        const groups = isAdmin(currentUser) ? NAV_GROUPS.concat([ADMIN_GROUP]) : NAV_GROUPS;
        return groups.map((group) => {
            const items = group.items.map((item) => {
                const active = isActive(item.href);
                return `<a href="${item.href}" class="nav-item${active ? ' active' : ''}"${active ? ' aria-current="page"' : ''} title="${escapeHtml(item.text)}">`
                    + `<i class="${item.icon}"></i> <span class="nav-text">${escapeHtml(item.text)}</span></a>`;
            }).join('');
            return `<div class="nav-group"><div class="nav-group-label">${escapeHtml(group.label)}</div>${items}</div>`;
        }).join('');
    }

    function accountHtml() {
        if (!currentUser) {
            return `<div class="account-name">${token() ? 'Session not verified' : 'Not signed in'}</div>`;
        }
        const name = [currentUser.first_name, currentUser.last_name].filter(Boolean).join(' ')
            || currentUser.username || currentUser.email;
        const role = (currentUser.role || 'USER').replace(/_/g, ' ');
        return `<div class="account-name" title="${escapeHtml(currentUser.email)}">${escapeHtml(name)}</div>`
            + `<div class="account-role">${escapeHtml(role)}</div>`;
    }

    function render() {
        const scrollTop = sidebar.scrollTop;
        sidebar.innerHTML = `
            <div class="logo-area">
                <a class="logo-link" href="dashboard.html" title="Tactical Overview">
                    <div class="logo-icon"></div>
                    <div class="logo-text">
                        <div class="logo-title">SHADOW TRUST</div>
                        <div class="logo-sub">DEFENSE GRID // V2</div>
                    </div>
                </a>
                <button type="button" class="sidebar-collapse" data-sidebar-collapse>
                    <i class="fas fa-chevron-left toggle-btn"></i>
                </button>
            </div>
            <nav aria-label="Primary">${navHtml()}</nav>
            <button type="button" class="theme-toggle" data-theme-toggle>
                <span class="theme-when-light"><i class="fas fa-moon"></i><span class="theme-toggle-label">Dark theme</span></span>
                <span class="theme-when-dark"><i class="fas fa-sun"></i><span class="theme-toggle-label">Light theme</span></span>
            </button>
            <div class="build-info sidebar-account">
                ${accountHtml()}
                <div class="live-indicator" data-status="${liveStatus}">
                    <span class="live-dot"></span><span class="live-label">${LIVE_LABELS[liveStatus] || liveStatus}</span>
                </div>
            </div>
        `;
        sidebar.scrollTop = scrollTop;
        syncCollapseButton();
        const themeBtn = sidebar.querySelector('[data-theme-toggle]');
        if (themeBtn && window.stTheme) {
            themeBtn.setAttribute('aria-pressed', window.stTheme.isDark() ? 'true' : 'false');
        }
    }

    // ── collapse (desktop) ──────────────────────────────────────────────────
    const storedCollapsed = () => {
        try { return localStorage.getItem(COLLAPSE_KEY) === '1'; } catch (_) { return false; }
    };

    function syncCollapseButton() {
        const btn = sidebar.querySelector('[data-sidebar-collapse]');
        if (!btn) return;
        const collapsed = sidebar.classList.contains('collapsed');
        btn.setAttribute('aria-expanded', String(!collapsed));
        btn.setAttribute('aria-label', collapsed ? 'Expand sidebar' : 'Collapse sidebar');
        btn.title = collapsed ? 'Expand sidebar' : 'Collapse sidebar';
    }

    function applyCollapsed(collapsed, animate) {
        if (!animate) {
            sidebar.classList.add('no-transition');
            requestAnimationFrame(() => requestAnimationFrame(() => sidebar.classList.remove('no-transition')));
        }
        sidebar.classList.toggle('collapsed', collapsed && !mobileQuery.matches);
        syncCollapseButton();
    }

    // ── off-canvas (mobile) ─────────────────────────────────────────────────
    const mobileToggle = document.createElement('button');
    mobileToggle.type = 'button';
    mobileToggle.className = 'sidebar-mobile-toggle';
    mobileToggle.setAttribute('aria-label', 'Open navigation');
    mobileToggle.setAttribute('aria-expanded', 'false');
    mobileToggle.innerHTML = '<i class="fas fa-bars"></i>';
    const backdrop = document.createElement('div');
    backdrop.className = 'sidebar-backdrop';
    document.body.append(mobileToggle, backdrop);

    function setMobileOpen(open) {
        sidebar.classList.toggle('open', open);
        backdrop.classList.toggle('open', open);
        mobileToggle.setAttribute('aria-expanded', String(open));
    }

    mobileToggle.addEventListener('click', () => setMobileOpen(!sidebar.classList.contains('open')));
    backdrop.addEventListener('click', () => setMobileOpen(false));
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') setMobileOpen(false); });
    mobileQuery.addEventListener('change', () => {
        setMobileOpen(false);
        applyCollapsed(storedCollapsed(), false);
    });

    const saveScroll = () => {
        try { localStorage.setItem(SCROLL_KEY, String(sidebar.scrollTop)); } catch (_) { /* ignore */ }
    };

    sidebar.addEventListener('click', (e) => {
        if (e.target.closest('[data-sidebar-collapse]')) {
            const next = !sidebar.classList.contains('collapsed');
            try { localStorage.setItem(COLLAPSE_KEY, next ? '1' : '0'); } catch (_) { /* ignore */ }
            applyCollapsed(next, true);
            return;
        }
        if (e.target.closest('[data-theme-toggle]')) {
            if (window.stTheme) window.stTheme.toggle();
            return;
        }
        if (e.target.closest('a.nav-item')) {
            saveScroll();
            setMobileOpen(false);
        }
    });
    window.addEventListener('beforeunload', saveScroll);
    window.addEventListener('hashchange', render);

    // ── live stream status ──────────────────────────────────────────────────
    function setLiveStatus(status) {
        liveStatus = status;
        const indicator = sidebar.querySelector('.live-indicator');
        if (!indicator) return;
        indicator.dataset.status = status;
        indicator.querySelector('.live-label').textContent = LIVE_LABELS[status] || status;
    }

    document.addEventListener('st-live-status', (e) => setLiveStatus(e.detail.status));

    function startLive() {
        if (!token()) return;
        if (window.STLive) {
            setLiveStatus(window.STLive.status === 'idle' ? 'connecting' : window.STLive.status);
            window.STLive.connect();
            return;
        }
        const script = document.createElement('script');
        script.src = 'js/live.js';
        script.onload = () => window.STLive && window.STLive.connect();
        document.head.appendChild(script);
    }

    render();
    applyCollapsed(storedCollapsed(), false);
    try {
        const saved = localStorage.getItem(SCROLL_KEY);
        if (saved) sidebar.scrollTop = parseInt(saved, 10);
    } catch (_) { /* ignore */ }
    startLive();
});
