import { apiService } from './api.js';

let users = [];
let honeypotRows = [];
let requests24hChart = null;
let requests7dChart = null;

const usersTableBody = document.getElementById('usersTableBody');
const nodesTableBody = document.querySelector('#section-nodes tbody');

function fmtNum(v) {
    const n = Number(v || 0);
    return Number.isFinite(n) ? n.toLocaleString() : '0';
}

function clampPct(v) {
    const n = Number(v || 0);
    return `${Math.max(0, Math.min(100, Math.round(n)))}%`;
}

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

function setWidth(id, value) {
    const el = document.getElementById(id);
    if (el) el.style.width = clampPct(value);
}

function setHtml(id, html) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = html;
}

function groupByWeekdayFromTimeline(points) {
    const labels = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    const buckets = [0, 0, 0, 0, 0, 0, 0];

    points.forEach((p) => {
        const d = new Date(p.time);
        if (!Number.isNaN(d.getTime())) {
            buckets[d.getDay()] += Number(p.count || 0);
        }
    });

    return { labels, buckets };
}

function initOrUpdateCharts(timelinePoints) {
    const sorted = [...timelinePoints].sort((a, b) => new Date(a.time) - new Date(b.time));
    const labels24h = sorted.map((x) => {
        const d = new Date(x.time);
        return Number.isNaN(d.getTime()) ? x.time : `${String(d.getHours()).padStart(2, '0')}:00`;
    });
    const values24h = sorted.map((x) => Number(x.count || 0));

    const chart24hEl = document.getElementById('requests24hChart');
    if (chart24hEl) {
        if (requests24hChart) requests24hChart.destroy();
        requests24hChart = new Chart(chart24hEl, {
            type: 'line',
            data: {
                labels: labels24h,
                datasets: [{
                    label: 'Requests',
                    data: values24h,
                    borderColor: '#00f3ff',
                    backgroundColor: 'rgba(0, 243, 255, 0.1)',
                    fill: true,
                    tension: 0.35
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: { grid: { color: '#222' }, ticks: { color: '#666' } },
                    x: { grid: { display: false }, ticks: { color: '#666' } }
                }
            }
        });
    }

    const byWeek = groupByWeekdayFromTimeline(sorted);
    const chart7dEl = document.getElementById('requests7dChart');
    if (chart7dEl) {
        if (requests7dChart) requests7dChart.destroy();
        requests7dChart = new Chart(chart7dEl, {
            type: 'bar',
            data: {
                labels: byWeek.labels,
                datasets: [{
                    label: 'Volume',
                    data: byWeek.buckets,
                    backgroundColor: '#bc13fe',
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: { grid: { color: '#222' }, ticks: { color: '#666' } },
                    x: { grid: { display: false }, ticks: { color: '#666' } }
                }
            }
        });
    }
}

function renderOverviewTables(stats, categories) {
    const topPathsBody = document.getElementById('overview-paths-body');
    const endpointsBody = document.getElementById('overview-endpoints-body');
    const topIpsBody = document.getElementById('overview-topips-body');

    if (topPathsBody) {
        const topCategories = (categories || []).slice(0, 5);
        topPathsBody.innerHTML = topCategories.length
            ? topCategories.map((c) => `<tr><td class="text-mono">${c.category || 'UNKNOWN'}</td><td class="text-cyan">${fmtNum(c.count)}</td></tr>`).join('')
            : '<tr><td colspan="2" class="text-muted">No data yet</td></tr>';
    }

    if (endpointsBody) {
        const vectors = (stats?.top_vectors || []).slice(0, 5);
        endpointsBody.innerHTML = vectors.length
            ? vectors.map((v) => `<tr><td class="text-mono">${v.service || 'UNKNOWN'}:${v.port ?? '--'}</td><td class="text-pink">${fmtNum(v.count)}</td></tr>`).join('')
            : '<tr><td colspan="2" class="text-muted">No data yet</td></tr>';
    }

    if (topIpsBody) {
        const topIps = (stats?.top_attackers || []).slice(0, 5);
        topIpsBody.innerHTML = topIps.length
            ? topIps.map((ip) => `<tr><td class="text-mono">${ip.ip || '--'}</td><td class="text-yellow">${fmtNum(ip.hits)}</td></tr>`).join('')
            : '<tr><td colspan="2" class="text-muted">No data yet</td></tr>';
    }
}

function renderOverviewMetrics(stats, health, latencyMs, credentialsKpi) {
    const summary = stats?.summary || {};

    setText('admin-metric-total-requests', fmtNum(summary.total_attacks));
    setText('admin-metric-total-requests-sub', `Stored Requests (${fmtNum(summary.total_attacks)})`);

    setText('admin-metric-unique-ips', fmtNum(summary.unique_attackers));
    setText('admin-metric-unique-ips-sub', `Distinct IPs (${fmtNum(summary.hostile_sources)})`);

    const weakPasswords = Number(credentialsKpi?.weak_passwords || 0);
    setText('admin-metric-critical', fmtNum(summary.high_risk_alerts));
    setText('admin-metric-critical-sub', `High Risk Alerts | Weak Passwords: ${fmtNum(weakPasswords)}`);

    const healthStatus = health?.status || 'UNKNOWN';
    setText('admin-metric-health', healthStatus);
    setText('admin-metric-health-sub', `DB: ${health?.database || 'UNKNOWN'} | API: ${health?.api_version || 'N/A'}`);

    setText('micro-label-1', 'TOTAL EVENTS');
    setText('micro-value-1', fmtNum(summary.total_attacks));
    setWidth('micro-bar-1', Math.min(100, (Number(summary.total_attacks || 0) / 50)));

    setText('micro-label-2', 'UNIQUE ATTACKERS');
    setText('micro-value-2', fmtNum(summary.unique_attackers));
    setWidth('micro-bar-2', Math.min(100, (Number(summary.unique_attackers || 0) / 10)));

    setText('micro-label-3', 'HIGH RISK ALERTS');
    setText('micro-value-3', fmtNum(summary.high_risk_alerts));
    setWidth('micro-bar-3', Math.min(100, (Number(summary.high_risk_alerts || 0) * 5)));

    setText('micro-label-4', 'LURES TRIPPED');
    setText('micro-value-4', fmtNum(summary.lures_tripped));
    setWidth('micro-bar-4', Math.min(100, (Number(summary.lures_tripped || 0) / 50)));

    setText('micro-label-5', 'TARGETED SECTORS');
    setText('micro-value-5', fmtNum(summary.targeted_sectors));
    setWidth('micro-bar-5', Math.min(100, Number(summary.targeted_sectors || 0) * 8));

    setText('micro-label-6', 'API LATENCY');
    setText('micro-value-6', `${Math.round(latencyMs)}ms`);
    setWidth('micro-bar-6', Math.max(5, Math.min(100, 100 - (latencyMs / 5))));

    const alertsBtn = document.getElementById('btn-admin-alerts');
    if (alertsBtn) {
        alertsBtn.innerHTML = `<i class="fas fa-bell"></i> Alerts (${fmtNum(summary.high_risk_alerts)})`;
    }
}

async function loadOverview() {
    const start = performance.now();
    const token = localStorage.getItem('access_token') || localStorage.getItem('authToken');

    // Run ALL fetches in parallel — credentials no longer blocks rendering
    const settled = await Promise.allSettled([
        apiService.get('/dashboard/stats'),
        apiService.get('/admin/health'),
        apiService.get('/attacks/timeline'),
        apiService.get('/attacks/categories'),
        token ? apiService.get('/analytics/credentials') : Promise.resolve(null),
    ]);

    const stats = settled[0].status === 'fulfilled' ? settled[0].value : {
        summary: {
            total_attacks: 0,
            unique_attackers: 0,
            high_risk_alerts: 0,
            lures_tripped: 0,
            targeted_sectors: 0,
            hostile_sources: 0
        },
        top_vectors: [],
        top_attackers: []
    };

    const health = settled[1].status === 'fulfilled' ? settled[1].value : {
        status: 'DEGRADED',
        database: 'UNREACHABLE',
        api_version: 'N/A'
    };

    const timeline  = settled[2].status === 'fulfilled' ? settled[2].value : [];
    const categories = settled[3].status === 'fulfilled' ? settled[3].value : [];
    const credentialsKpi = settled[4].status === 'fulfilled' ? (settled[4].value?.kpi || {}) : {};

    const latencyMs = performance.now() - start;
    renderOverviewMetrics(stats, health, latencyMs, credentialsKpi);
    renderOverviewTables(stats, categories);
    initOrUpdateCharts(Array.isArray(timeline) ? timeline : []);
}

async function loadUsers() {
    try {
        users = await apiService.get('/users/');
        renderUsers();
    } catch (error) {
        console.error('Failed to load users:', error);
    }
}

function renderUsers() {
    if (!usersTableBody) return;

    usersTableBody.innerHTML = users.map((user) => {
        const created = user.created_at ? new Date(user.created_at).toLocaleDateString() : 'N/A';
        return `
            <tr>
                <td class="text-mono text-muted">#${user.id}</td>
                <td class="text-white font-weight-bold">${user.username || 'N/A'}</td>
                <td class="text-muted"><a href="mailto:${user.email}" class="text-cyan">${user.email}</a></td>
                <td>${getRoleBadge(user.role || 'ANALYST')}</td>
                <td>${getStatusBadge(user.status || 'PENDING')}</td>
                <td class="text-mono text-xs">${created}</td>
                <td>
                    <button class="soc-btn" style="padding:4px 8px;" onclick="editUser('${user.id}')"><i class="fas fa-edit"></i></button>
                    <button class="soc-btn" style="padding:4px 8px; border-color:var(--neon-red); color:var(--neon-red);" onclick="deleteUser('${user.id}')"><i class="fas fa-trash"></i></button>
                </td>
            </tr>
        `;
    }).join('');
}

function getRoleBadge(role) {
    const normalized = String(role || '').toUpperCase();
    if (normalized === 'SUPER_ADMIN') return '<span class="badge badge-purple">ROOT</span>';
    if (normalized === 'ADMIN') return '<span class="badge badge-pink">ADMIN</span>';
    if (normalized === 'OVERSEER') return '<span class="badge badge-cyan">OVERSEER</span>';
    return `<span class="badge badge-blue">${normalized || 'ANALYST'}</span>`;
}

function getStatusBadge(status) {
    const normalized = String(status || 'PENDING').toUpperCase();
    if (normalized === 'ACTIVE') return '<span class="text-green"><i class="fas fa-circle"></i> Active</span>';
    if (normalized === 'BLOCKED') return '<span class="text-red"><i class="fas fa-ban"></i> Blocked</span>';
    return '<span class="text-yellow"><i class="fas fa-clock"></i> Pending</span>';
}

async function loadNodes() {
    try {
        const statusRows = await apiService.get('/honeypots/status');
        honeypotRows = Array.isArray(statusRows) ? statusRows : [];
        renderNodes();
    } catch (e) {
        console.error('Node sync error:', e);
    }
}

function renderNodes() {
    if (!nodesTableBody) return;

    if (!honeypotRows.length) {
        nodesTableBody.innerHTML = '<tr><td colspan="6" class="text-muted" style="text-align:center; padding:20px;">No nodes yet</td></tr>';
        return;
    }

    nodesTableBody.innerHTML = honeypotRows.map((node, idx) => {
        const events = Number(node.events || 0);
        const active = events > 0;
        const status = active ? 'ONLINE' : 'IDLE';
        const reachability = active
            ? '<span class="text-green"><i class="fas fa-check-circle"></i> Online</span>'
            : '<span class="text-muted"><i class="fas fa-circle"></i> Idle</span>';

        return `
            <tr>
                <td class="text-white">${node.honeypot || `HP-${idx + 1}`}</td>
                <td class="text-mono">N/A</td>
                <td class="text-mono text-cyan">N/A</td>
                <td><span class="badge ${active ? 'badge-green' : 'badge-red'}">${status}</span></td>
                <td>${reachability}</td>
                <td><span class="text-mono text-xs text-muted">${fmtNum(events)} events</span></td>
            </tr>
        `;
    }).join('');

    const nodeTiles = document.querySelectorAll('#section-nodes .dashboard-grid.grid-4 .metric-tile');
    if (nodeTiles.length >= 4) {
        const total = honeypotRows.length;
        const running = honeypotRows.filter((x) => Number(x.events || 0) > 0).length;
        const stopped = total - running;
        const openPortsApprox = new Set(honeypotRows.map((x) => x.honeypot)).size;

        nodeTiles[0].querySelector('.metric-value').textContent = fmtNum(total);
        nodeTiles[1].querySelector('.metric-value').textContent = fmtNum(running);
        nodeTiles[2].querySelector('.metric-value').textContent = fmtNum(stopped);
        nodeTiles[3].querySelector('.metric-value').textContent = fmtNum(openPortsApprox);
    }
}

window.openModal = (modalId) => {
    const modal = document.getElementById(modalId);
    if (modal) modal.style.display = 'block';
};

window.closeModal = (modalId) => {
    const modal = document.getElementById(modalId);
    if (modal) modal.style.display = 'none';
};

window.createUser = async () => {
    const username = document.getElementById('newUsername')?.value?.trim();
    const email = (document.getElementById('newUserEmail') || document.getElementById('newEmail'))?.value?.trim();
    const password = (document.getElementById('newUserPassword') || document.getElementById('newPassword'))?.value;
    const role = (document.getElementById('newUserRole') || document.getElementById('newRole'))?.value || 'ANALYST';
    const firstName = document.getElementById('newUserFirstName')?.value || '';
    const lastName = document.getElementById('newUserLastName')?.value || '';

    if (!username || !email || !password) {
        alert('Username, email and password are required.');
        return;
    }

    try {
        await apiService.post('/users/', {
            username,
            email,
            password,
            role,
            first_name: firstName,
            last_name: lastName
        });
        alert('User Created Successfully');
        closeModal('createUserModal');
        loadUsers();
    } catch (e) {
        alert(`Error: ${e.message}`);
    }
};

window.editUser = (id) => {
    alert(`Edit flow for user ${id} can be wired next.`);
};

window.deleteUser = async (id) => {
    if (!confirm('Are you sure you want to delete this user? This action cannot be undone.')) return;
    try {
        await apiService.delete(`/users/${id}`);
        users = users.filter((u) => String(u.id) !== String(id));
        renderUsers();
    } catch (e) {
        alert(`Failed to delete: ${e.message}`);
    }
};

window.checkHealth = async () => {
    const healthDiv = document.getElementById('debugHealthResult');
    if (!healthDiv) return;

    healthDiv.innerHTML = '<span class="text-yellow">Running Diagnostics...</span>';

    try {
        const res = await apiService.get('/admin/health');
        healthDiv.innerHTML = `
            <div style="background:#111; padding:15px; border-radius:5px; border:1px solid #333; margin-top:10px;">
                <div style="display:flex; justify-content:space-between; margin-bottom:10px;">
                    <span class="text-white font-weight-bold">OVERALL STATUS</span>
                    <span class="badge ${res.status === 'HEALTHY' ? 'badge-green' : 'badge-red'}">${res.status}</span>
                </div>
                <div class="text-mono text-xs">
                    <div>DATABASE: <span class="${res.database === 'ONLINE' ? 'text-green' : 'text-red'}">${res.database}</span></div>
                    <div>API VERSION: ${res.api_version}</div>
                    <div>TIMESTAMP: ${res.timestamp}</div>
                    <hr style="border-color:#333; margin:10px 0;">
                    <div>SERVICES:</div>
                    ${Object.entries(res.services || {}).map(([k, v]) => `
                        <div style="display:flex; justify-content:space-between;">
                            <span>${k.toUpperCase()}</span>
                            <span class="${v === 'ONLINE' ? 'text-green' : 'text-red'}">${v}</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    } catch (e) {
        healthDiv.innerHTML = `<span class="text-red">Health Check Failed: ${e.message}</span>`;
    }
};

window.loadSettings = async () => {
    try {
        const settings = await apiService.get('/admin/settings');
        const data = settings.data || settings;
        if (!data) return;

        if (data.education) {
            const eduCheck = document.getElementById('eduEnabled');
            const eduLevel = document.getElementById('eduLevel');
            if (eduCheck) eduCheck.checked = data.education.enabled;
            if (eduLevel) eduLevel.value = data.education.level;
        }
        if (data.government) {
            const govCheck = document.getElementById('govEnabled');
            const govLevel = document.getElementById('govLevel');
            if (govCheck) govCheck.checked = data.government.enabled;
            if (govLevel) govLevel.value = data.government.level;
        }
        if (data.financial) {
            const finCheck = document.getElementById('finEnabled');
            const finLevel = document.getElementById('finLevel');
            if (finCheck) finCheck.checked = data.financial.enabled;
            if (finLevel) finLevel.value = data.financial.level;
        }
    } catch (e) {
        console.error('Failed to load settings:', e);
    }
};

window.saveSettings = async () => {
    const getVal = (id) => (document.getElementById(id) ? document.getElementById(id).value : 1);
    const getCheck = (id) => (document.getElementById(id) ? document.getElementById(id).checked : false);

    const settings = {
        education: { enabled: getCheck('eduEnabled'), level: parseInt(getVal('eduLevel'), 10) },
        government: { enabled: getCheck('govEnabled'), level: parseInt(getVal('govLevel'), 10) },
        financial: { enabled: getCheck('finEnabled'), level: parseInt(getVal('finLevel'), 10) }
    };

    try {
        await apiService.post('/admin/settings', settings);
        alert('System Settings Saved Successfully!');
    } catch (e) {
        alert(`Failed to save settings: ${e.message}`);
    }
};

function bindHeaderActions() {
    const alertsBtn = document.getElementById('btn-admin-alerts');
    if (alertsBtn) {
        alertsBtn.addEventListener('click', async () => {
            try {
                const stats = await apiService.get('/dashboard/stats');
                const highRisk = stats?.summary?.high_risk_alerts || 0;
                const recent = (stats?.recent || []).slice(0, 3)
                    .map((e) => `${e.attacker_ip || 'N/A'} -> PT:${e.target_port ?? 'N/A'} (${e.event_type || 'event'})`)
                    .join('\n');
                alert(`High Risk Alerts: ${highRisk}\n\nRecent:\n${recent || 'No recent alerts.'}`);
            } catch (e) {
                alert(`Failed to fetch alerts: ${e.message}`);
            }
        });
    }

    const backupBtn = document.getElementById('btn-system-backup');
    if (backupBtn) {
        backupBtn.addEventListener('click', async () => {
            try {
                const backup = await apiService.get('/admin/backup');
                const payload = JSON.stringify(backup, null, 2);
                const blob = new Blob([payload], { type: 'application/json;charset=utf-8' });
                const url = URL.createObjectURL(blob);
                const link = document.createElement('a');
                const stamp = new Date().toISOString().replace(/[:.]/g, '-');
                link.href = url;
                link.download = `shadowtrust-system-backup-${stamp}.json`;
                document.body.appendChild(link);
                link.click();
                link.remove();
                URL.revokeObjectURL(url);
            } catch (e) {
                alert(`Backup failed: ${e.message}`);
            }
        });
    }
}

document.addEventListener('DOMContentLoaded', async () => {
    bindHeaderActions();

    const createUserForm = document.getElementById('createUserForm');
    if (createUserForm) {
        createUserForm.addEventListener('submit', (e) => {
            e.preventDefault();
            window.createUser();
        });
    }

    await Promise.all([
        loadOverview(),
        loadUsers(),
        loadNodes(),
        window.loadSettings()
    ]);

    setInterval(loadOverview, 30000);
    setInterval(loadNodes, 15000);
});
