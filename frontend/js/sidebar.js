/**
 * Shared Sidebar Script
 * Renders one common sidebar across all app pages and preserves sidebar scroll position.
 */
document.addEventListener("DOMContentLoaded", function () {
    const sidebar = document.getElementById('sidebar');
    if (sidebar) {
        const currentPage = (window.location.pathname.split('/').pop() || '').split('?')[0].split('#')[0];

        function getApiBase() {
            const isLocalDev = window.location.hostname === '127.0.0.1' ||
                window.location.hostname === 'localhost' ||
                window.location.hostname === '0.0.0.0' ||
                window.location.protocol === 'file:';
            return isLocalDev ? 'http://127.0.0.1:8000/api/v1' : '/api/v1';
        }

        async function resolveAdminSession() {
            const token = localStorage.getItem('access_token') || localStorage.getItem('authToken');
            if (!token) {
                localStorage.removeItem('isAdmin');
                return false;
            }

            try {
                const response = await fetch(`${getApiBase()}/users/me`, {
                    headers: {
                        'Authorization': `Bearer ${token}`
                    },
                    cache: 'no-store'
                });

                if (!response.ok) {
                    localStorage.removeItem('isAdmin');
                    return false;
                }

                const user = await response.json();
                const isAdminRole = user.role === 'ADMIN' || user.role === 'SUPER_ADMIN';
                if (isAdminRole) {
                    localStorage.setItem('isAdmin', 'true');
                    localStorage.setItem('userRole', user.role || '');
                    return true;
                }

                localStorage.removeItem('isAdmin');
                return false;
            } catch (_) {
                // Fail closed: if role can't be verified, do not show admin links.
                localStorage.removeItem('isAdmin');
                return false;
            }
        }

        function renderSidebar(isAdminSession) {

        const navGroups = [
            {
                label: 'Command Center',
                items: [
                    { href: 'dashboard.html', icon: 'fa-th-large', text: 'Tactical Overview' },
                    { href: 'incidents.html', icon: 'fa-folder-open', text: 'Investigations' },
                    { href: 'events.html', icon: 'fa-list-alt', text: 'Event Log' },
                    { href: 'logs.html', icon: 'fa-layer-group', text: 'Logs' },
                    { href: 'reports.html', icon: 'fa-file-pdf', text: 'Reports' }
                ]
            },
            {
                label: 'Grid Monitoring',
                items: [
                    { href: 'nodes.html', icon: 'fa-server', text: 'Honeypot Nodes' },
                    { href: 'splunk.html', icon: 'fa-shield-alt', text: 'Splunk Blue Team' },
                    { href: 'geo.html', icon: 'fa-globe-americas', text: 'Geo Intelligence' }
                ]
            },
            {
                label: 'Intelligence',
                items: [
                    { href: 'mitre.html', icon: 'fa-chess-board', text: 'MITRE Matrix' },
                    { href: 'validation.html', icon: 'fa-vial', text: 'Detection Validation' },
                    { href: 'graphs.html', icon: 'fa-chart-area', text: 'Attack Analytics' },
                    { href: 'credentials.html', icon: 'fa-key', text: 'Credentials Vault' },
                    { href: 'behavior.html', icon: 'fa-user-secret', text: 'Behavior Profiling' },
                    { href: 'analysis_lab.html', icon: 'fa-terminal', text: 'Analysis Lab' }
                ]
            },
            {
                label: 'Governance',
                items: [
                    { href: 'grc.html', icon: 'fa-clipboard-check', text: 'GRC & SOC 2' }
                ]
            },
            {
                label: 'Tools Suite',
                items: [
                    { href: 'malware.html', icon: 'fa-biohazard', text: 'Binary Analysis' },
                    { href: 'urlscan.html', icon: 'fa-search-location', text: 'URL Scanner' },
                    { href: 'apk.html', icon: 'fa-mobile', text: 'APK Inspector' },
                    { href: 'vm_lab.html', icon: 'fa-laptop-code', text: 'Virtual Lab' }
                ]
            },
            {
                label: 'System',
                items: [
                    { href: 'admin_login.html', icon: 'fa-id-badge', text: 'Admin Access' },
                    { href: 'profile.html', icon: 'fa-user-circle', text: 'Officer Profile' }
                ]
            }
        ];

        // Conditional Admin Links
        if (isAdminSession) {
            const systemGroup = navGroups.find(g => g.label === 'System');
            systemGroup.items.splice(1, 0,
                { href: 'admin.html', icon: 'fa-user-shield', text: 'Admin Console' }
            );
        } else {
            // Hide the entire System block for non-admin sessions.
            const idx = navGroups.findIndex(g => g.label === 'System');
            if (idx >= 0) navGroups.splice(idx, 1);
        }

        const navHtml = navGroups.map(group => {
            const itemsHtml = group.items.map(item => {
                const isActive = currentPage === item.href;
                return `<a href="${item.href}" class="nav-item${isActive ? ' active' : ''}"><i class="fas ${item.icon}"></i> <span class="nav-text">${item.text}</span></a>`;
            }).join('');
            return `<div class="nav-group"><div class="nav-group-label">${group.label}</div>${itemsHtml}</div>`;
        }).join('');

        sidebar.innerHTML = `
            <div class="logo-area" onclick="document.getElementById('sidebar').classList.toggle('collapsed')">
                <div class="logo-icon"></div>
                <div class="logo-text">
                    <div class="logo-title">SHADOW TRUST</div>
                    <div class="logo-sub">DEFENSE GRID // V2</div>
                </div>
                <i class="fas fa-chevron-left toggle-btn" style="margin-left: auto; cursor: pointer;"></i>
            </div>
            ${navHtml}
            <div class="build-info">
                <div>UNIT: <span class="text-green">CYBER-01</span></div>
                <div>SECURE: <span class="text-green">ENCRYPTED</span></div>
            </div>
        `;

        // Restore scroll position
        const scrollPos = localStorage.getItem('sidebarScrollPosition');
        if (scrollPos) {
            sidebar.scrollTop = parseInt(scrollPos, 10);
        }

        // Save scroll position when the user leaves the page
        window.addEventListener('beforeunload', () => {
            localStorage.setItem('sidebarScrollPosition', sidebar.scrollTop);
        });

        // Also save on click of any nav item, just in case
        const navLinks = sidebar.querySelectorAll('a.nav-item');
        navLinks.forEach(link => {
            link.addEventListener('click', () => {
                localStorage.setItem('sidebarScrollPosition', sidebar.scrollTop);
            });
        });

        }

        // Render with strict role verification to avoid stale admin links from localStorage.
        resolveAdminSession().then(renderSidebar);
    }
});
