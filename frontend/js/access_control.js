
import { apiService } from './api.js';

// State
let pendingUsers = [];
let accessLogs = [];

// Level label mapping
const LEVEL_LABELS = {
    1: 'LEVEL 1 — Basic',
    2: 'LEVEL 2 — Intermediate',
    3: 'LEVEL 3 — Full Access'
};

const LEVEL_BADGE_COLORS = {
    1: 'var(--st-info)',
    2: 'var(--st-warning)',
    3: 'var(--st-danger)'
};

// ─── TOAST NOTIFICATION SYSTEM ───────────────────────────────────────────────

function showToast(message, type = 'success') {
    const existing = document.getElementById('acToast');
    if (existing) existing.remove();

    const colors = {
        success: { bg: 'color-mix(in srgb, var(--st-success) 12%, transparent)', border: 'var(--st-success)', text: 'var(--st-success)', icon: 'fa-check-circle' },
        error: { bg: 'color-mix(in srgb, var(--st-danger) 12%, transparent)', border: 'var(--st-danger)', text: 'var(--st-danger)', icon: 'fa-exclamation-triangle' },
        warning: { bg: 'color-mix(in srgb, var(--st-warning) 12%, transparent)', border: 'var(--st-warning)', text: 'var(--st-warning)', icon: 'fa-exclamation-circle' }
    };
    const c = colors[type] || colors.success;

    const toast = document.createElement('div');
    toast.id = 'acToast';
    toast.innerHTML = `<i class="fas ${c.icon}"></i> <span>${message}</span>`;
    toast.style.cssText = `
        position:fixed; top:24px; right:24px; z-index:9999;
        padding:14px 22px; border-radius:8px; font-size:0.9rem;
        font-family:var(--st-font-main); display:flex; align-items:center; gap:10px;
        background:${c.bg}; border:1px solid ${c.border}; color:${c.text};
        box-shadow:0 4px 24px rgba(0,0,0,0.4);
        animation:toastSlide 0.3s ease;
    `;
    document.body.appendChild(toast);

    if (!document.getElementById('toastStyle')) {
        const s = document.createElement('style');
        s.id = 'toastStyle';
        s.textContent = `
            @keyframes toastSlide { from { opacity:0; transform:translateX(40px); } to { opacity:1; transform:translateX(0); } }
            @keyframes toastOut  { from { opacity:1; transform:translateX(0); } to { opacity:0; transform:translateX(40px); } }
        `;
        document.head.appendChild(s);
    }

    setTimeout(() => {
        toast.style.animation = 'toastOut 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// ─── INITIALIZATION ──────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {
    await loadPendingUsers();
    await loadLogs(); // Pre-load audit logs so they're ready when tab is clicked
    setInterval(loadPendingUsers, 15000);
});

// ─── PENDING REQUESTS ────────────────────────────────────────────────────────

window.loadPendingUsers = async () => {
    try {
        const response = await apiService.get('/users/pending');
        pendingUsers = Array.isArray(response) ? response : (response.data || []);
        renderPendingUsers();
    } catch (error) {
        console.error("Failed to load pending users:", error);
    }
};

function renderPendingUsers() {
    const tbody = document.getElementById('pendingUsersTable');
    if (!tbody) return;

    if (pendingUsers.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No pending access requests.</td></tr>';
        return;
    }

    tbody.innerHTML = pendingUsers.map(user => {
        const reqLevel = user.requested_clearance_level || user.clearance_level || '—';
        const levelLabel = LEVEL_LABELS[reqLevel] || `Level ${reqLevel}`;
        const levelColor = LEVEL_BADGE_COLORS[reqLevel] || 'var(--st-text-muted)';

        return `
        <tr>
            <td class="text-mono text-muted">#${String(user.id).substring(0, 8)}...</td>
            <td class="text-white font-weight-bold">${user.username || '—'}</td>
            <td class="text-white">${user.email}</td>
            <td>${user.first_name || '—'} ${user.last_name || ''}</td>
            <td class="text-muted">${user.department || '—'}</td>
            <td><span class="badge" style="background:${levelColor}20; color:${levelColor}; border:1px solid ${levelColor}40; padding:3px 8px; border-radius:4px; font-size:0.75rem;">${levelLabel}</span></td>
            <td><span class="badge badge-yellow">PENDING</span></td>
            <td>
                <button class="soc-btn" style="padding:4px 8px; border-color:var(--st-success); color:var(--st-success);" onclick="openApproveModal('${user.id}', ${reqLevel})"><i class="fas fa-check"></i> APPROVE</button>
                <button class="soc-btn" style="padding:4px 8px; border-color:var(--st-danger); color:var(--st-danger);" onclick="openDenyModal('${user.id}')"><i class="fas fa-times"></i> DENY</button>
            </td>
        </tr>
    `}).join('');
}

// ─── APPROVAL WORKFLOW ───────────────────────────────────────────────────────

window.openApproveModal = (id, requestedLevel) => {
    document.getElementById('approveUserId').value = id;

    const levelInput = document.getElementById('approveLevel');
    if (levelInput && requestedLevel) levelInput.value = requestedLevel;

    const roleMap = { 1: 'OPERATIVE', 2: 'SPECIALIST', 3: 'OVERSEER' };
    const roleSelect = document.getElementById('approveRole');
    if (roleSelect && requestedLevel && roleMap[requestedLevel]) {
        roleSelect.value = roleMap[requestedLevel];
    }

    const infoDiv = document.getElementById('approveRequestedInfo');
    if (infoDiv) {
        const levelLabel = LEVEL_LABELS[requestedLevel] || `Level ${requestedLevel}`;
        infoDiv.innerHTML = `<i class="fas fa-info-circle"></i> User requested: <strong>${levelLabel}</strong>`;
    }

    document.getElementById('approveModal').style.display = 'block';
};

window.submitApproval = async () => {
    const id = document.getElementById('approveUserId').value;
    const role = document.getElementById('approveRole').value;
    const level = document.getElementById('approveLevel').value;

    try {
        await apiService.post(`/users/${id}/approve`, {
            role: role,
            clearance_level: parseInt(level),
            admin_id: "me"
        });
        showToast('User approved successfully', 'success');
        document.getElementById('approveModal').style.display = 'none';
        loadPendingUsers();
        loadLogs(); // Refresh audit logs after approval
    } catch (e) {
        showToast('Approval failed: ' + e.message, 'error');
    }
};

// ─── DENIAL WORKFLOW ─────────────────────────────────────────────────────────

window.openDenyModal = (id) => {
    document.getElementById('denyUserId').value = id;
    document.getElementById('denyModal').style.display = 'block';
};

window.submitDenial = async () => {
    const id = document.getElementById('denyUserId').value;
    const reason = document.getElementById('denyReason').value;

    if (!reason) {
        showToast('Please provide a reason for rejection.', 'warning');
        return;
    }

    try {
        await apiService.post(`/users/${id}/deny`, {
            reason: reason,
            admin_id: "me"
        });
        showToast('User request rejected', 'success');
        document.getElementById('denyModal').style.display = 'none';
        loadPendingUsers();
        loadLogs(); // Refresh audit logs after denial
    } catch (e) {
        showToast('Denial failed: ' + e.message, 'error');
    }
};

// ─── AUDIT LOGS ──────────────────────────────────────────────────────────────

window.loadLogs = async () => {
    try {
        const result = await apiService.get('/admin/logs/access');
        accessLogs = Array.isArray(result) ? result : (result.data || []);
        renderLogs();
    } catch (error) {
        console.error("Failed to load logs:", error);
    }
};

function renderLogs() {
    const tbody = document.getElementById('accessLogsTable');
    if (!tbody) return;

    if (accessLogs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No audit logs found.</td></tr>';
        return;
    }

    tbody.innerHTML = accessLogs.map(log => {
        const adminEmail = log.admin ? log.admin.email : (log.admin_id ? `ID: ${String(log.admin_id).substring(0, 8)}` : 'System');
        const targetEmail = log.target_user ? log.target_user.email : (log.target_user_id ? `ID: ${String(log.target_user_id).substring(0, 8)}` : 'Deleted/Unknown');
        const badgeColor = log.action === 'APPROVE' ? 'badge-green' : 'badge-red';

        return `
        <tr>
            <td class="text-mono text-xs text-muted">${new Date(log.timestamp).toLocaleString()}</td>
            <td class="text-white">${adminEmail}</td>
            <td class="text-white">${targetEmail}</td>
            <td><span class="badge ${badgeColor}">${log.action}</span></td>
            <td class="text-mono text-xs">${log.details || '—'}</td>
        </tr>
    `}).join('');
}
