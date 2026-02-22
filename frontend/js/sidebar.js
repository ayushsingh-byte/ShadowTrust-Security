/**
 * Shared Sidebar Script
 * Renders one common sidebar across all app pages and preserves sidebar scroll position.
 */
document.addEventListener("DOMContentLoaded", function () {
    const sidebar = document.getElementById('sidebar');
    if (sidebar) {
        const currentPage = (window.location.pathname.split('/').pop() || '').split('?')[0].split('#')[0];

        const navGroups = [
            {
                label: 'Command Center',
                items: [
                    { href: 'dashboard.html', icon: 'fa-radar', text: 'Tactical Overview' },
                    { href: 'events.html', icon: 'fa-list-alt', text: 'Event Log' }
                ]
            },
            {
                label: 'Grid Monitoring',
                items: [
                    { href: 'nodes.html', icon: 'fa-server', text: 'Honeypot Nodes' },
                    { href: 'sectors.html', icon: 'fa-network-wired', text: 'Sector Monitors' },
                    { href: 'geo.html', icon: 'fa-globe-americas', text: 'Geo Intelligence' }
                ]
            },
            {
                label: 'Intelligence',
                items: [
                    { href: 'mitre.html', icon: 'fa-chess-board', text: 'MITRE Matrix' },
                    { href: 'graphs.html', icon: 'fa-chart-area', text: 'Attack Analytics' },
                    { href: 'credentials.html', icon: 'fa-key', text: 'Credentials Vault' },
                    { href: 'behavior.html', icon: 'fa-user-secret', text: 'Behavior Profiling' },
                    { href: 'simulation.html', icon: 'fa-crosshairs', text: 'Attack Sim' }
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
                    { href: 'admin.html', icon: 'fa-user-shield', text: 'Admin Console' },
                    { href: 'config.html', icon: 'fa-cogs', text: 'Global Config' },
                    { href: 'profile.html', icon: 'fa-user-circle', text: 'Officer Profile' }
                ]
            }
        ];

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
                    <div class="logo-title">SENTINEL</div>
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
});
