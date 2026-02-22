
import { apiService } from './api.js';

// State
let users = [];
let nodes = [];

// DOM Elements
const usersTableBody = document.getElementById('usersTableBody');
const nodesTableBody = document.querySelector('#section-nodes tbody'); // Targeting the existing table in nodes section
const healthContainer = document.getElementById('health-overview'); // Will need to add this to HTML

// --- INITIALIZATION ---
document.addEventListener('DOMContentLoaded', async () => {
    // Check Admin Access
    /* 
    // In a real app, verify token role here. 
    // For demo, we assume if they can see the page they are admin or we rely on API 403s.
    */

    // Load initial data based on active tab
    // We can just load everything for simplicity in this dashboard
    await loadUsers();
    await loadNodes();

    // Pollers
    setInterval(loadNodes, 5000); // Real-time node status

    // Auto-load settings if function exists (from inline script)
    if (typeof window.loadSettings === 'function') window.loadSettings();
});

// --- USER MANAGEMENT ---

async function loadUsers() {
    try {
        users = await apiService.get('/users/');
        renderUsers();
    } catch (error) {
        console.error("Failed to load users:", error);
    }
}

function renderUsers() {
    if (!usersTableBody) return;

    usersTableBody.innerHTML = users.map(user => `
        <tr>
            <td class="text-mono text-muted">#${user.id}</td>
            <td class="text-white font-weight-bold">${user.email}</td>
            <td class="text-muted"><a href="mailto:${user.email}" class="text-cyan">${user.email}</a></td>
            <td>${getRoleBadge(user.role)}</td>
            <td>${getStatusBadge(user.status)}</td>
            <td class="text-mono text-xs">${new Date(user.created_at).toLocaleDateString()}</td>
            <td>
                <button class="soc-btn" style="padding:4px 8px;" onclick="editUser(${user.id})"><i class="fas fa-edit"></i></button>
                <button class="soc-btn" style="padding:4px 8px; border-color:var(--neon-red); color:var(--neon-red);" onclick="deleteUser(${user.id})"><i class="fas fa-trash"></i></button>
            </td>
        </tr>
    `).join('');
}

function getRoleBadge(role) {
    role = role.toUpperCase();
    if (role === 'SUPER_ADMIN') return '<span class="badge badge-purple">ROOT</span>';
    if (role === 'ADMIN') return '<span class="badge badge-pink">ADMIN</span>';
    return '<span class="badge badge-blue">ANALYST</span>';
}

function getStatusBadge(status) {
    status = (status || 'PENDING').toUpperCase();
    if (status === 'ACTIVE') return '<span class="text-green"><i class="fas fa-circle"></i> Active</span>';
    return '<span class="text-yellow"><i class="fas fa-clock"></i> Pending</span>';
}

// Window functions for HTML onclick access
window.openModal = (modalId) => {
    document.getElementById(modalId).style.display = 'block';
};

window.closeModal = (modalId) => {
    document.getElementById(modalId).style.display = 'none';
};

window.createUser = async () => {
    const email = document.getElementById('newUserEmail').value;
    const password = document.getElementById('newUserPassword').value;
    const role = document.getElementById('newUserRole').value;
    const firstName = document.getElementById('newUserFirstName').value;
    const lastName = document.getElementById('newUserLastName').value;

    try {
        await apiService.post('/users/', {
            email, password, role, first_name: firstName, last_name: lastName
        });
        alert('User Created Successfully');
        closeModal('createUserModal');
        loadUsers();
    } catch (e) {
        alert('Error: ' + e.message);
    }
};

window.deleteUser = async (id) => {
    if (!confirm('Are you sure you want to delete this user? This action cannot be undone.')) return;
    try {
        await apiService.delete(`/users/${id}`);
        // Optimistic update
        users = users.filter(u => u.id !== id);
        renderUsers();
    } catch (e) {
        alert('Failed to delete: ' + e.message);
    }
};

// --- NODE CONTROL (Real-time) ---

async function loadNodes() {
    try {
        const data = await apiService.get('/vm/list');
        // data is object {id: {data}}
        nodes = Object.values(data);
        renderNodes();
    } catch (e) {
        console.error("Node sync error:", e);
    }
}

function renderNodes() {
    if (!nodesTableBody) return;

    nodesTableBody.innerHTML = nodes.map(node => {
        const isRunning = node.status === 'RUNNING';
        const reachability = isRunning ? '<span class="text-green"><i class="fas fa-check-circle"></i> Online</span>' : '<span class="text-muted"><i class="fas fa-circle"></i> Offline</span>';
        const actionBtn = isRunning
            ? `<button class="soc-btn" onclick="stopNode('${node.id}')" style="padding: 2px 8px; font-size:0.7rem; border-color:#ff0055; color:#ff0055;">STOP</button>`
            : `<button class="soc-btn" onclick="startNode('${node.id}')" style="padding: 2px 8px; font-size:0.7rem; border-color:#00ff41; color:#00ff41;">START</button>`;

        return `
            <tr>
                <td class="text-white">${node.name}</td>
                <td class="text-mono">${node.ip || '0.0.0.0'}</td>
                <td class="text-mono text-cyan">VARIOUS</td>
                <td><span class="badge ${isRunning ? 'badge-green' : 'badge-red'}">${node.status}</span></td>
                <td>${reachability}</td>
                <td>${actionBtn}</td>
            </tr>
        `;
    }).join('');
}

window.startNode = async (id) => {
    try {
        await apiService.post(`/vm/${id}/start`);
        loadNodes(); // Refresh immediately
    } catch (e) { alert(e.message); }
};

window.stopNode = async (id) => {
    try {
        await apiService.post(`/vm/${id}/stop`);
        loadNodes();
    } catch (e) { alert(e.message); }
};

// --- SYSTEM HEALTH ---
// Intended to be called from a specific Debug page or section
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
                    ${Object.entries(res.services).map(([k, v]) => `
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

// --- SYSTEM SETTINGS (Sector Control) ---

window.loadSettings = async () => {
    try {
        const settings = await apiService.get('/admin/settings');
        // Check for success wrapping or direct object
        // My python endpoint returns the object directly, but let's be safe
        const data = settings.data || settings;

        if (!data) return;

        // Sector Control - Education
        if (data.education) {
            const eduCheck = document.getElementById('eduEnabled');
            const eduLevel = document.getElementById('eduLevel');
            if (eduCheck) eduCheck.checked = data.education.enabled;
            if (eduLevel) eduLevel.value = data.education.level;
        }

        // Sector Control - Government
        if (data.government) {
            const govCheck = document.getElementById('govEnabled');
            const govLevel = document.getElementById('govLevel');
            if (govCheck) govCheck.checked = data.government.enabled;
            if (govLevel) govLevel.value = data.government.level;
        }

        // Sector Control - Financial
        if (data.financial) {
            const finCheck = document.getElementById('finEnabled');
            const finLevel = document.getElementById('finLevel');
            if (finCheck) finCheck.checked = data.financial.enabled;
            if (finLevel) finLevel.value = data.financial.level;
        }

        console.log("Settings loaded:", data);
    } catch (e) {
        console.error("Failed to load settings:", e);
    }
};

window.saveSettings = async () => {
    const getVal = (id) => document.getElementById(id) ? document.getElementById(id).value : 1;
    const getCheck = (id) => document.getElementById(id) ? document.getElementById(id).checked : false;

    const settings = {
        education: {
            enabled: getCheck('eduEnabled'),
            level: parseInt(getVal('eduLevel'))
        },
        government: {
            enabled: getCheck('govEnabled'),
            level: parseInt(getVal('govLevel'))
        },
        financial: {
            enabled: getCheck('finEnabled'),
            level: parseInt(getVal('finLevel'))
        }
    };

    try {
        await apiService.post('/admin/settings', settings);
        alert('System Settings Saved Successfully!');
    } catch (e) {
        alert('Failed to save settings: ' + e.message);
    }
};
