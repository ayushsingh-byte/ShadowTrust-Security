
import { apiService } from './api.js';

// State
let pendingUsers = [];
let accessLogs = [];

// --- INITIALIZATION ---
document.addEventListener('DOMContentLoaded', async () => {
    // Load initial data
    await loadPendingUsers();
});

// --- PENDING REQUESTS ---

window.loadPendingUsers = async () => {
    try {
        pendingUsers = await apiService.get('/users/pending');
        renderPendingUsers();
    } catch (error) {
        console.error("Failed to load pending users:", error);
    }
};

function renderPendingUsers() {
    const tbody = document.getElementById('pendingUsersTable');
    if (!tbody) return;

    if (pendingUsers.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No pending access requests.</td></tr>';
        return;
    }

    tbody.innerHTML = pendingUsers.map(user => `
        <tr>
            <td class="text-mono text-muted">#${user.id}</td>
            <td class="text-white font-weight-bold">${user.email}</td>
            <td>${user.first_name || '-'} ${user.last_name || ''}</td>
            <td><span class="badge badge-yellow">PENDING</span></td>
            <td>
                <button class="soc-btn" style="padding:4px 8px; border-color:#00ff41; color:#00ff41;" onclick="openApproveModal(${user.id})"><i class="fas fa-check"></i> APPROVE</button>
                <button class="soc-btn" style="padding:4px 8px; border-color:#ff0055; color:#ff0055;" onclick="openDenyModal(${user.id})"><i class="fas fa-times"></i> DENY</button>
            </td>
        </tr>
    `).join('');
}

// --- APPROVAL WORKFLOW ---

window.openApproveModal = (id) => {
    document.getElementById('approveUserId').value = id;
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
            admin_id: 1 // Mocking Admin ID for now
        });
        alert('User Approved Successfully');
        document.getElementById('approveModal').style.display = 'none';
        loadPendingUsers();
    } catch (e) {
        alert('Approval Failed: ' + e.message);
    }
};

// --- DENIAL WORKFLOW ---

window.openDenyModal = (id) => {
    document.getElementById('denyUserId').value = id;
    document.getElementById('denyModal').style.display = 'block';
};

window.submitDenial = async () => {
    const id = document.getElementById('denyUserId').value;
    const reason = document.getElementById('denyReason').value;

    if (!reason) {
        alert("Please provide a reason for rejection.");
        return;
    }

    try {
        await apiService.post(`/users/${id}/deny`, {
            reason: reason,
            admin_id: 1 // Mocking Admin ID
        });
        alert('User Request Rejected');
        document.getElementById('denyModal').style.display = 'none';
        loadPendingUsers();
    } catch (e) {
        alert('Denial Failed: ' + e.message);
    }
};

// --- AUDIT LOGS ---

window.loadLogs = async () => {
    try {
        const result = await apiService.get('/admin/logs/access');
        // Handle Supabase response format (data vs direct array)
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
        // Safe access to nested join data if available, else Fallback
        const adminEmail = log.admin ? log.admin.email : `Admin #${log.admin_id}`;
        const targetEmail = log.target_user ? log.target_user.email : (log.target_user_id ? `User #${log.target_user_id}` : 'Deleted/Unknown');
        const badgeColor = log.action === 'APPROVE' ? 'badge-green' : 'badge-red';

        return `
        <tr>
            <td class="text-mono text-xs text-muted">${new Date(log.timestamp).toLocaleString()}</td>
            <td class="text-white">${adminEmail}</td>
            <td class="text-white">${targetEmail}</td>
            <td><span class="badge ${badgeColor}">${log.action}</span></td>
            <td class="text-mono text-xs">${log.details}</td>
        </tr>
    `}).join('');
}
