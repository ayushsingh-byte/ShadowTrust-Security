/**
 * Shared console shell for every app page: sidebar navigation, the top app bar
 * (breadcrumb, page search, live status, theme switch, account menu) and the command palette.
 * The base navigation renders immediately; GET /users/me then decides whether the
 * Administration group and [data-admin-only] controls appear.
 * Pages marked <html data-require-admin> stay hidden until an admin role is verified.
 */
document.addEventListener('DOMContentLoaded', function () {
    const root = document.documentElement;
    const sidebar = document.getElementById('sidebar');
    const ADMIN_ROLES = ['SUPER_ADMIN', 'ADMIN'];
    const COLLAPSE_KEY = 'st-sidebar-collapsed';
    const SCROLL_KEY = 'sidebarScrollPosition';
    const SESSION_KEYS = ['access_token', 'authToken', 'isAdmin', 'userRole', 'clearanceLevel', 'userEmail', 'userName', 'devSystemCode'];

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
        if (sidebar) { render(); renderAccount(); }
    });

    if (!sidebar) return;

    const currentPage = (window.location.pathname.split('/').pop() || '').split('?')[0] || 'dashboard.html';
    const mobileQuery = window.matchMedia('(max-width: 900px)');
    const main = document.querySelector('.main-content');

    const NAV_GROUPS = [
        {
            label: 'Operate',
            items: [
                { href: 'dashboard.html', icon: 'fas fa-th-large', text: 'Overview' },
                { href: 'incidents.html', icon: 'fas fa-folder-open', text: 'Investigations' },
                { href: 'events.html', icon: 'fas fa-list-alt', text: 'Event log' },
                { href: 'logs.html', icon: 'fas fa-layer-group', text: 'Logs' },
                { href: 'reports.html', icon: 'fas fa-file-pdf', text: 'Reports' },
            ],
        },
        {
            label: 'Sensors',
            items: [
                { href: 'nodes.html', icon: 'fas fa-server', text: 'Honeypot nodes' },
                { href: 'splunk.html', icon: 'fas fa-shield-alt', text: 'Splunk blue team' },
                { href: 'geo.html', icon: 'fas fa-globe-americas', text: 'Geo intelligence' },
            ],
        },
        {
            label: 'Intelligence',
            items: [
                { href: 'mitre.html', icon: 'fas fa-chess-board', text: 'MITRE ATT&CK' },
                { href: 'validation.html', icon: 'fas fa-vial', text: 'Detection validation' },
                { href: 'graphs.html', icon: 'fas fa-chart-area', text: 'Attack analytics' },
                { href: 'credentials.html', icon: 'fas fa-key', text: 'Credential vault' },
                { href: 'behavior.html', icon: 'fas fa-user-secret', text: 'Behavior profiling' },
                { href: 'analysis_lab.html', icon: 'fas fa-terminal', text: 'Analysis lab' },
            ],
        },
        {
            label: 'Governance',
            items: [
                { href: 'grc.html', icon: 'fas fa-clipboard-check', text: 'GRC & SOC 2' },
            ],
        },
        {
            label: 'Tools',
            items: [
                { href: 'malware.html', icon: 'fas fa-biohazard', text: 'Binary analysis' },
                { href: 'urlscan.html', icon: 'fas fa-search-location', text: 'URL scanner' },
                { href: 'apk.html', icon: 'fas fa-mobile', text: 'APK inspector' },
                { href: 'vm_lab.html', icon: 'fas fa-laptop-code', text: 'Virtual lab' },
            ],
        },
    ];

    const ADMIN_GROUP = {
        label: 'Administration',
        items: [
            { href: 'admin.html#section-overview', icon: 'fas fa-tachometer-alt', text: 'Global overview' },
            { href: 'admin.html#section-users', icon: 'fas fa-users-cog', text: 'Users' },
            { href: 'access_control.html', icon: 'fas fa-user-lock', text: 'Access control' },
            { href: 'credential_mgmt.html', icon: 'fas fa-key', text: 'Credential management' },
            { href: 'aws_connection.html', icon: 'fab fa-aws', text: 'AWS connection' },
            { href: 'admin.html#section-nodes', icon: 'fas fa-network-wired', text: 'Node control' },
            { href: 'admin.html#section-settings', icon: 'fas fa-cogs', text: 'System settings' },
            { href: 'admin.html#section-debug', icon: 'fas fa-microchip', text: 'System debug' },
        ],
    };

    // Pages that are reached from another page rather than the menu.
    const OFF_MENU = {
        'profile.html': ['Account', 'Profile'],
        'node_details.html': ['Sensors', 'Sensor investigation'],
        'debug.html': ['Administration', 'System diagnostics'],
    };

    // Brand mark: an eye on a tile (the decoy that watches back).
    const MARK_SVG = '<svg viewBox="0 0 28 28" fill="none"><path d="M2.5 14c3-5.3 7-8 11.5-8s8.5 2.7 11.5 8c-3 5.3-7 8-11.5 8S5.5 19.3 2.5 14Z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><circle cx="14" cy="14" r="4.2" fill="var(--st-brand)"/></svg>';

    // Console pages carry no favicon of their own; give them the brand mark on an ink tile.
    if (!document.querySelector('link[rel="icon"]')) {
        const icon = document.createElement('link');
        icon.rel = 'icon';
        icon.href = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 28 28'%3E%3Crect width='28' height='28' rx='6' fill='%23533afd'/%3E%3Cpath d='M4.5 14c2.5-4.3 5.7-6.4 9.5-6.4s7 2.1 9.5 6.4c-2.5 4.3-5.7 6.4-9.5 6.4S7 18.3 4.5 14Z' fill='none' stroke='%23fff' stroke-width='1.8' stroke-linejoin='round'/%3E%3Ccircle cx='14' cy='14' r='3.2' fill='%23fff'/%3E%3C/svg%3E";
        document.head.appendChild(icon);
    }

    const LIVE_LABELS = {
        idle: 'Connecting',
        connecting: 'Connecting',
        live: 'Live',
        reconnecting: 'Reconnecting',
        'signed-out': 'Not signed in',
    };
    let liveStatus = token() ? 'connecting' : 'signed-out';

    const escapeHtml = (value) => String(value == null ? '' : value).replace(/[&<>"']/g, (ch) => (
        { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]
    ));

    const allGroups = () => (isAdmin(currentUser) ? NAV_GROUPS.concat([ADMIN_GROUP]) : NAV_GROUPS);

    function isActive(href) {
        const [page, hash] = href.split('#');
        if (page !== currentPage) return false;
        if (!hash) return true;
        return window.location.hash ? window.location.hash === `#${hash}` : hash === 'section-overview';
    }

    function navHtml() {
        return allGroups().map((group) => {
            const items = group.items.map((item) => {
                const active = isActive(item.href);
                return `<a href="${item.href}" class="nav-item${active ? ' active' : ''}"${active ? ' aria-current="page"' : ''} title="${escapeHtml(item.text)}">`
                    + `<i class="${item.icon}"></i> <span class="nav-text">${escapeHtml(item.text)}</span></a>`;
            }).join('');
            return `<div class="nav-group"><div class="nav-group-label">${escapeHtml(group.label)}</div>${items}</div>`;
        }).join('');
    }

    // The pill behind the active item slides from where it sat on the previous page
    // (position kept in sessionStorage), so moving between pages reads as one motion.
    const INDICATOR_KEY = 'st-nav-pill';
    function placeIndicator(from) {
        const nav = sidebar.querySelector('nav');
        const active = nav && nav.querySelector('.nav-item.active');
        if (!nav || !active) return;
        const ind = document.createElement('span');
        ind.className = 'nav-indicator';
        nav.insertBefore(ind, nav.firstChild);
        const target = { top: active.offsetTop, h: active.offsetHeight };
        let start = from;
        if (!start) {
            try { start = JSON.parse(sessionStorage.getItem(INDICATOR_KEY)); } catch (_) { start = null; }
        }
        if (start && typeof start.top === 'number') {
            ind.style.transition = 'none';
            ind.style.top = `${start.top}px`;
            ind.style.height = `${start.h}px`;
            void ind.offsetHeight;
            ind.style.transition = '';
        }
        ind.style.top = `${target.top}px`;
        ind.style.height = `${target.h}px`;
        try { sessionStorage.setItem(INDICATOR_KEY, JSON.stringify(target)); } catch (_) { /* ignore */ }
    }

    function render() {
        const scrollTop = sidebar.scrollTop;
        const oldInd = sidebar.querySelector('.nav-indicator');
        const carry = oldInd ? { top: parseFloat(oldInd.style.top) || 0, h: parseFloat(oldInd.style.height) || 0 } : null;
        sidebar.innerHTML = `
            <div class="logo-area">
                <a class="logo-link" href="dashboard.html" title="Overview">
                    <span class="logo-icon" aria-hidden="true">${MARK_SVG}</span>
                    <div class="logo-text">
                        <div class="logo-title">ShadowTrust</div>
                        <div class="logo-sub">Security operations</div>
                    </div>
                </a>
            </div>
            <nav aria-label="Primary">${navHtml()}</nav>
            <div class="sidebar-foot">
                <button type="button" class="sidebar-collapse" data-sidebar-collapse>
                    <i class="fas fa-angles-left toggle-btn"></i><span class="sidebar-foot-text">Collapse</span>
                </button>
            </div>
        `;
        sidebar.scrollTop = scrollTop;
        placeIndicator(carry);
        syncCollapseButton();
    }

    // ── app bar ─────────────────────────────────────────────────────────────
    function crumbs() {
        for (const group of NAV_GROUPS.concat([ADMIN_GROUP])) {
            const hit = group.items.find((item) => isActive(item.href)) || group.items.find((item) => item.href.split('#')[0] === currentPage);
            if (hit) return [group.label, hit.text];
        }
        if (OFF_MENU[currentPage]) return OFF_MENU[currentPage];
        return ['Console', (document.title.split('·')[0] || 'Page').trim()];
    }

    let appBar = null;
    if (main) {
        appBar = document.createElement('header');
        appBar.className = 'app-bar';
        const [group, page] = crumbs();
        const mac = /Mac|iPhone|iPad/.test(navigator.platform || '');
        appBar.innerHTML = `
            <button type="button" class="bar-btn sidebar-mobile-toggle" data-mobile-nav aria-label="Open navigation" aria-expanded="false"><i class="fas fa-bars"></i></button>
            <div class="crumbs" aria-label="Breadcrumb">
                <span>${escapeHtml(group)}</span><i class="fas fa-chevron-right sep"></i><b>${escapeHtml(page)}</b>
            </div>
            <span class="app-bar-spacer"></span>
            <button type="button" class="cmdk-trigger" data-cmdk-open aria-label="Search pages and actions">
                <i class="fas fa-magnifying-glass"></i><span>Search pages and actions</span><kbd>${mac ? '⌘' : 'Ctrl'} K</kbd>
            </button>
            <div class="live-indicator" data-status="${liveStatus}" title="Live event stream">
                <span class="live-dot"></span><span class="live-label">${LIVE_LABELS[liveStatus] || liveStatus}</span>
            </div>
            <a class="bar-btn" href="docs.html" title="Documentation" aria-label="Documentation"><i class="far fa-circle-question"></i></a>
            <button type="button" class="bar-btn" data-theme-toggle aria-label="Switch theme">
                <i class="fas fa-moon theme-when-light"></i><i class="fas fa-sun theme-when-dark"></i>
            </button>
            <div class="user-wrap" data-user-wrap></div>
        `;
        main.insertBefore(appBar, main.firstChild);

        // The landing page's ribbon, top right of every console page (drawn by js/ribbon.js).
        const ribbon = document.createElement('canvas');
        ribbon.className = 'console-ribbon';
        ribbon.setAttribute('data-ribbon', 'console');
        ribbon.setAttribute('aria-hidden', 'true');
        main.insertBefore(ribbon, appBar);
        if (window.STCanvas) window.STCanvas.ribbon(ribbon); // a page already loaded it
        else {
            const draw = document.createElement('script');
            draw.src = 'js/ribbon.js';
            document.head.appendChild(draw);
        }

        // The bar is clear at the top of a page and turns to glass once content scrolls under it.
        const onScroll = () => appBar.classList.toggle('scrolled', main.scrollTop > 4);
        main.addEventListener('scroll', onScroll, { passive: true });
        onScroll();
    }

    function userName() {
        if (!currentUser) return '';
        return [currentUser.first_name, currentUser.last_name].filter(Boolean).join(' ')
            || currentUser.username || currentUser.email || '';
    }

    function renderAccount() {
        const wrap = appBar && appBar.querySelector('[data-user-wrap]');
        if (!wrap) return;
        const name = userName();
        const initials = name ? name.trim().split(/\s+/).slice(0, 2).map((w) => w[0]).join('').toUpperCase() : '?';
        wrap.innerHTML = `<button type="button" class="avatar-btn" data-user-btn aria-haspopup="menu" aria-expanded="false" title="${escapeHtml(name || 'Account')}">${escapeHtml(initials)}</button>`;
    }

    function closeUserMenu() {
        const menu = appBar && appBar.querySelector('.user-menu');
        if (menu) menu.remove();
        const btn = appBar && appBar.querySelector('[data-user-btn]');
        if (btn) btn.setAttribute('aria-expanded', 'false');
    }

    function signOut() {
        SESSION_KEYS.forEach((key) => localStorage.removeItem(key));
        window.location.href = 'login.html';
    }

    function openUserMenu() {
        const wrap = appBar.querySelector('[data-user-wrap]');
        const btn = wrap.querySelector('[data-user-btn]');
        const menu = document.createElement('div');
        menu.className = 'user-menu';
        menu.setAttribute('role', 'menu');
        if (currentUser) {
            const role = String(currentUser.role || 'user').replace(/_/g, ' ').toLowerCase();
            menu.innerHTML = `
                <div class="user-menu-head">
                    <div class="nm">${escapeHtml(userName())}</div>
                    <div class="em">${escapeHtml(currentUser.email || '')}</div>
                    <span class="badge badge-blue rl" style="text-transform:capitalize">${escapeHtml(role)}</span>
                </div>
                <a class="menu-item" role="menuitem" href="profile.html"><i class="far fa-user"></i>Profile</a>
                ${isAdmin(currentUser) ? '<a class="menu-item" role="menuitem" href="admin.html"><i class="fas fa-sliders"></i>Administration</a>' : ''}
                <a class="menu-item" role="menuitem" href="status.html"><i class="fas fa-heart-pulse"></i>System status</a>
                <a class="menu-item" role="menuitem" href="index.html"><i class="fas fa-arrow-up-right-from-square"></i>Product site</a>
                <div class="menu-sep"></div>
                <button type="button" class="menu-item" role="menuitem" data-sign-out><i class="fas fa-arrow-right-from-bracket"></i>Sign out</button>`;
        } else {
            menu.innerHTML = `
                <div class="user-menu-head"><div class="nm">${token() ? 'Session not verified' : 'Not signed in'}</div>
                <div class="em">Sign in to load your account.</div></div>
                <a class="menu-item" role="menuitem" href="login.html"><i class="fas fa-arrow-right-to-bracket"></i>Sign in</a>
                <a class="menu-item" role="menuitem" href="index.html"><i class="fas fa-arrow-up-right-from-square"></i>Product site</a>`;
        }
        wrap.appendChild(menu);
        btn.setAttribute('aria-expanded', 'true');
    }

    // ── command palette ─────────────────────────────────────────────────────
    let palette = null;
    function paletteItems() {
        const items = [];
        allGroups().forEach((group) => group.items.forEach((item) => items.push({
            group: group.label, icon: item.icon, text: item.text, run: () => { window.location.href = item.href; },
        })));
        items.push({ group: 'Account', icon: 'far fa-user', text: 'Profile', run: () => { window.location.href = 'profile.html'; } });
        items.push({ group: 'Actions', icon: 'fas fa-circle-half-stroke', text: 'Switch light or dark theme', run: () => window.stTheme && window.stTheme.toggle() });
        items.push({ group: 'Actions', icon: 'fas fa-tv', text: 'Open wallboard (full-screen view)', run: () => { window.location.href = 'wallboard.html'; } });
        items.push({ group: 'Actions', icon: 'fas fa-heart-pulse', text: 'Open system status', run: () => { window.location.href = 'status.html'; } });
        items.push({ group: 'Actions', icon: 'fas fa-book', text: 'Open documentation', run: () => { window.location.href = 'docs.html'; } });
        items.push({ group: 'Actions', icon: 'fas fa-arrow-right-from-bracket', text: 'Sign out', run: signOut });
        return items;
    }

    function closePalette() {
        if (palette) { palette.remove(); palette = null; }
    }

    function openPalette() {
        if (palette) return;
        const items = paletteItems();
        let shown = items;
        let sel = 0;
        palette = document.createElement('div');
        palette.className = 'cmdk-overlay';
        palette.innerHTML = `
            <div class="cmdk" role="dialog" aria-label="Search pages and actions">
                <div class="cmdk-input"><i class="fas fa-magnifying-glass"></i><input type="text" placeholder="Go to a page or run an action" autocomplete="off" spellcheck="false"><kbd>Esc</kbd></div>
                <div class="cmdk-list" role="listbox"></div>
                <div class="cmdk-foot"><span><kbd>↑</kbd> <kbd>↓</kbd> to move</span><span><kbd>Enter</kbd> to open</span></div>
            </div>`;
        document.body.appendChild(palette);
        const input = palette.querySelector('input');
        const list = palette.querySelector('.cmdk-list');

        function paint() {
            if (!shown.length) { list.innerHTML = '<div class="cmdk-empty">Nothing matches that.</div>'; return; }
            let html = '';
            let last = null;
            shown.forEach((item, i) => {
                if (item.group !== last) { html += `<div class="cmdk-group">${escapeHtml(item.group)}</div>`; last = item.group; }
                html += `<div class="cmdk-item${i === sel ? ' sel' : ''}" role="option" data-i="${i}"><i class="${item.icon}"></i>${escapeHtml(item.text)}${i === sel ? '<span class="hint">Enter</span>' : ''}</div>`;
            });
            list.innerHTML = html;
            const active = list.querySelector('.cmdk-item.sel');
            if (active) active.scrollIntoView({ block: 'nearest' });
        }

        input.addEventListener('input', () => {
            const q = input.value.trim().toLowerCase();
            shown = q ? items.filter((item) => (item.text + ' ' + item.group).toLowerCase().includes(q)) : items;
            sel = 0;
            paint();
        });
        input.addEventListener('keydown', (e) => {
            if (e.key === 'ArrowDown') { e.preventDefault(); sel = Math.min(shown.length - 1, sel + 1); paint(); }
            else if (e.key === 'ArrowUp') { e.preventDefault(); sel = Math.max(0, sel - 1); paint(); }
            else if (e.key === 'Enter' && shown[sel]) { e.preventDefault(); const item = shown[sel]; closePalette(); item.run(); }
        });
        list.addEventListener('mousemove', (e) => {
            const row = e.target.closest('.cmdk-item');
            if (row && +row.dataset.i !== sel) { sel = +row.dataset.i; paint(); }
        });
        list.addEventListener('click', (e) => {
            const row = e.target.closest('.cmdk-item');
            if (row) { const item = shown[+row.dataset.i]; closePalette(); item.run(); }
        });
        palette.addEventListener('mousedown', (e) => { if (e.target === palette) closePalette(); });
        paint();
        input.focus();
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
    const backdrop = document.createElement('div');
    backdrop.className = 'sidebar-backdrop';
    document.body.append(backdrop);

    function setMobileOpen(open) {
        sidebar.classList.toggle('open', open);
        backdrop.classList.toggle('open', open);
        const btn = appBar && appBar.querySelector('[data-mobile-nav]');
        if (btn) btn.setAttribute('aria-expanded', String(open));
    }

    backdrop.addEventListener('click', () => setMobileOpen(false));
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
        if (e.target.closest('a.nav-item')) {
            saveScroll();
            setMobileOpen(false);
        }
    });

    if (appBar) {
        appBar.addEventListener('click', (e) => {
            if (e.target.closest('[data-mobile-nav]')) { setMobileOpen(!sidebar.classList.contains('open')); return; }
            if (e.target.closest('[data-theme-toggle]')) { if (window.stTheme) window.stTheme.toggle(); return; }
            if (e.target.closest('[data-cmdk-open]')) { openPalette(); return; }
            if (e.target.closest('[data-sign-out]')) { signOut(); return; }
            if (e.target.closest('[data-user-btn]')) {
                if (appBar.querySelector('.user-menu')) closeUserMenu(); else openUserMenu();
            }
        });
    }

    document.addEventListener('click', (e) => {
        if (appBar && !e.target.closest('[data-user-wrap]')) closeUserMenu();
    });
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') { setMobileOpen(false); closeUserMenu(); closePalette(); return; }
        if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); if (palette) closePalette(); else openPalette(); }
    });

    window.addEventListener('beforeunload', saveScroll);
    window.addEventListener('hashchange', render);

    // ── live stream status ──────────────────────────────────────────────────
    function setLiveStatus(status) {
        liveStatus = status;
        const indicator = appBar && appBar.querySelector('.live-indicator');
        if (!indicator) return;
        indicator.dataset.status = status;
        indicator.querySelector('.live-label').textContent = LIVE_LABELS[status] || status;
    }

    document.addEventListener('st-live-status', (e) => setLiveStatus(e.detail.status));

    // A toast when the detection engine opens an incident. The live stream says that one
    // was opened; its key, title and severity are read from the incidents API.
    let lastToastId = null;
    function toastIncident() {
        fetch(`${API_BASE}/incidents?limit=1`, { headers: { Authorization: `Bearer ${token()}` }, cache: 'no-store' })
            .then((r) => (r.ok ? r.json() : null))
            .then((data) => {
                const inc = data && data.incidents && data.incidents[0];
                if (!inc || inc.id === lastToastId) return;
                // only for an incident created just now, not an older one that was updated
                const born = Date.parse(String(inc.created_at || '').replace(/Z?$/, 'Z'));
                if (!born || Date.now() - born > 180000) return;
                lastToastId = inc.id;

                let stack = document.querySelector('.st-toasts');
                if (!stack) {
                    stack = document.createElement('div');
                    stack.className = 'st-toasts';
                    stack.setAttribute('aria-live', 'polite');
                    document.body.appendChild(stack);
                }
                const toast = document.createElement('a');
                toast.className = 'st-toast';
                toast.href = 'incidents.html';
                const sev = String(inc.severity || '').toLowerCase();
                const add = (cls, text) => { const s = document.createElement('span'); s.className = cls; s.textContent = text; toast.appendChild(s); return s; };
                add('tt', `New incident · ${sev ? sev.charAt(0).toUpperCase() + sev.slice(1) : 'Unrated'}`);
                const close = document.createElement('button');
                close.type = 'button';
                close.className = 'tx';
                close.setAttribute('aria-label', 'Dismiss');
                close.textContent = '×';
                toast.appendChild(close);
                add('tb', `${inc.incident_key || ''} ${inc.title || ''}`.trim());
                add('tl', 'Open in Investigations');
                const dismiss = () => { toast.classList.add('out'); setTimeout(() => toast.remove(), 320); };
                close.addEventListener('click', (e) => { e.preventDefault(); e.stopPropagation(); dismiss(); });
                stack.appendChild(toast);
                setTimeout(dismiss, 10000);
            })
            .catch(() => { /* no toast if the API does not answer */ });
    }

    function watchIncidents() {
        window.STLive.on('detection', (summary) => { if (summary && summary.incidents > 0) toastIncident(); });
    }

    function startLive() {
        if (!token()) return;
        if (window.STLive) {
            setLiveStatus(window.STLive.status === 'idle' ? 'connecting' : window.STLive.status);
            window.STLive.connect();
            watchIncidents();
            return;
        }
        const script = document.createElement('script');
        script.src = 'js/live.js';
        script.onload = () => { if (window.STLive) { window.STLive.connect(); watchIncidents(); } };
        document.head.appendChild(script);
    }

    render();
    renderAccount();
    applyCollapsed(storedCollapsed(), false);

    // Shared console motion (count-ups, reveals, row stagger).
    if (!document.querySelector('script[data-st-console]')) {
        const motion = document.createElement('script');
        motion.src = 'js/console.js';
        motion.dataset.stConsole = '1';
        document.body.appendChild(motion);
    }
    try {
        const saved = localStorage.getItem(SCROLL_KEY);
        if (saved) sidebar.scrollTop = parseInt(saved, 10);
    } catch (_) { /* ignore */ }
    startLive();
});
