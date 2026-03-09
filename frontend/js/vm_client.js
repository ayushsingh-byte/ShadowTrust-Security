import { apiService } from './api.js';

class VMLabClient {
    constructor() {
        const saved = localStorage.getItem('_st_instances');
        this.instances = saved ? JSON.parse(saved) : {};
        this.isLoading = false;

        // Restore UI state for actively running environments when moving between pages
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.restoreUI());
        } else {
            this.restoreUI();
        }
    }

    saveState() {
        localStorage.setItem('_st_instances', JSON.stringify(this.instances));
        this.updateGlobalStats();
    }

    async updateGlobalStats() {
        try {
            const metrics = await apiService.get('/labs/cluster-metrics');
            if (metrics.status !== 'success') return;

            const totalVcpu = metrics.vcpu || 0;
            const totalRam = metrics.ram || 0;
            const activeCount = metrics.active_count || 0;

            const maxVcpu = 32;
            const maxRam = 64;

            // Update DOM elements if they exist
            const e1 = document.getElementById('global-vcpu-count');
            if (e1) e1.textContent = totalVcpu;

            const e2 = document.getElementById('global-vcpu-bar');
            if (e2) e2.style.width = `${Math.min((totalVcpu / maxVcpu) * 100, 100)}%`;

            const e3 = document.getElementById('global-ram-count');
            if (e3) e3.textContent = totalRam;

            const e4 = document.getElementById('global-ram-bar');
            if (e4) e4.style.width = `${Math.min((totalRam / maxRam) * 100, 100)}%`;

            const e5 = document.getElementById('global-instance-count');
            if (e5) e5.textContent = activeCount;

            const e6 = document.getElementById('global-instance-sub');
            if (e6) e6.textContent = activeCount;

            // Update individual VM specs with Live Data if available
            if (metrics.instances && Array.isArray(metrics.instances)) {
                for (const inst of metrics.instances) {
                    if (inst.profile_id && inst.profile_id !== 'unknown' && inst.status === 'RUNNING') {
                        const btn = document.querySelector(`button[data-profile="${inst.profile_id}"]`);
                        if (btn) {
                            const specsDiv = btn.closest('.vm-card').querySelector('.vm-specs');
                            if (specsDiv && !specsDiv.dataset.live) {
                                specsDiv.dataset.live = "true";
                                specsDiv.innerHTML = `
                                    <div style="margin-bottom: 8px;">IP Address <span style="color: var(--accent-primary); font-family: var(--font-mono);">${inst.private_ip}</span></div>
                                    <div style="margin-bottom: 8px;">Hardware <span>${inst.instance_type}</span></div>
                                    <div style="margin-bottom: 8px;">Architecture <span>${inst.architecture}</span></div>
                                    <div>Status <span class="text-green">RUNNING</span></div>
                                `;
                            }
                        }
                    }
                }
            }

        } catch (e) {
            console.warn("[VMLab] Failed to fetch live cluster metrics:", e);
        }
    }

    async restoreUI() {
        this.updateGlobalStats();
        for (const profileId in this.instances) {
            const instanceData = this.instances[profileId];
            const labId = instanceData.labId;
            const btn = document.querySelector(`button[data-profile="${profileId}"]`);

            // Cross-check with backend to ensure the VM is actually still alive
            try {
                const response = await apiService.get(`/labs/status/${labId}`);
                const status = (response.status || '').toUpperCase();

                // ── DEAD / TERMINATED ── clear the stale entry
                if (['ERROR', 'NOT_FOUND', 'TERMINATED', 'STOPPED', 'UNKNOWN'].includes(status)) {
                    delete this.instances[profileId];
                    this.saveState();
                    if (btn) this.setButtonState(btn, 'DEFAULT', 'PROVISION');

                    const orb = document.getElementById(`dot_${profileId}`);
                    if (orb) { orb.style.background = '#555'; orb.style.boxShadow = 'none'; orb.style.animation = 'none'; }
                    continue;
                }

                // ── STILL PROVISIONING ── keep the spinning state and poll for readiness
                if (status === 'PROVISIONING') {
                    if (btn) {
                        this.setButtonState(btn, 'LOADING', 'LAUNCHING...');
                        const orb = document.getElementById(`dot_${profileId}`);
                        if (orb) { orb.style.background = '#f59e0b'; orb.style.boxShadow = '0 0 10px #f59e0b'; orb.style.animation = 'pulse-red 2s infinite'; }
                    }
                    // Start polling in background — once READY it will switch to CONNECT TERMINAL
                    this._pollProvisioningStatus(profileId, labId, btn);
                    continue;
                }

                // ── READY / RUNNING ── reconnect the button
                if (btn) {
                    this.setButtonState(btn, 'ACTIVE', 'CONNECT TERMINAL');
                    const orb = document.getElementById(`dot_${profileId}`);
                    if (orb) { orb.style.background = 'var(--accent-primary)'; orb.style.boxShadow = '0 0 10px var(--accent-primary)'; orb.style.animation = 'pulse-red 2s infinite'; }
                }

            } catch (error) {
                console.warn(`[VMLab] Could not verify status for ${profileId}. Keeping state.`, error);

                // If backend is unreachable, we keep the UI in its current logical state
                if (btn && instanceData.labId) {
                    // Try to guess based on existing UI state or assume it's still active if we don't know
                    // Let's just leave it alone or set to ACTIVE so user doesn't lose the button
                    this.setButtonState(btn, 'ACTIVE', 'CONNECT TERMINAL');
                    const orb = document.getElementById(`dot_${profileId}`);
                    if (orb) { orb.style.background = 'var(--accent-primary)'; orb.style.boxShadow = '0 0 10px var(--accent-primary)'; }
                }
                continue;
            }
        }
    }

    async _pollProvisioningStatus(profileId, labId, btn) {
        // Poll every 5s until READY or ERROR, max 60 attempts (~5 min)
        let attempts = 0;
        const maxAttempts = 60;
        const interval = setInterval(async () => {
            attempts++;
            try {
                const response = await apiService.get(`/labs/status/${labId}`);
                const status = (response.status || '').toUpperCase();

                if (status === 'READY' || status === 'RUNNING') {
                    clearInterval(interval);
                    if (btn) this.setButtonState(btn, 'ACTIVE', 'CONNECT TERMINAL');
                    const orb = document.getElementById(`dot_${profileId}`);
                    if (orb) { orb.style.background = 'var(--accent-primary)'; orb.style.boxShadow = '0 0 10px var(--accent-primary)'; }
                    this.showNotification(`${profileId} is ready!`, 'success');
                } else if (['ERROR', 'TERMINATED', 'NOT_FOUND'].includes(status)) {
                    clearInterval(interval);
                    delete this.instances[profileId];
                    this.saveState();
                    if (btn) this.setButtonState(btn, 'DEFAULT', 'PROVISION');
                    const orb = document.getElementById(`dot_${profileId}`);
                    if (orb) { orb.style.background = '#555'; orb.style.boxShadow = 'none'; orb.style.animation = 'none'; }
                } else if (attempts >= maxAttempts) {
                    clearInterval(interval);
                    delete this.instances[profileId];
                    this.saveState();
                    if (btn) this.setButtonState(btn, 'DEFAULT', 'PROVISION');
                    const orb = document.getElementById(`dot_${profileId}`);
                    if (orb) { orb.style.background = '#555'; orb.style.boxShadow = 'none'; orb.style.animation = 'none'; }
                    this.showNotification(`${profileId} timed out during provisioning.`, 'error');
                }
                // else still PROVISIONING — keep polling
            } catch (e) {
                console.warn(`[VMLab] Polling error for ${profileId} at attempt ${attempts}:`, e);
                // Don't kill the interval on a transient network error, just count it as an attempt
                if (attempts >= maxAttempts) {
                    clearInterval(interval);
                    delete this.instances[profileId];
                    this.saveState();
                    if (btn) this.setButtonState(btn, 'DEFAULT', 'PROVISION');
                    this.showNotification(`${profileId} provisioning check failed permanently.`, 'error');
                }
            }
        }, 5000);
    }

    async launchInstance(profileId, btnElement) {
        this.isLoading = this.isLoading || {};
        if (this.isLoading[profileId]) return;

        try {
            this.setButtonState(btnElement, 'LOADING', 'LAUNCHING...');

            // Mocking a session ID for now. In production, this comes from Supabase Auth.
            const sessionId = "sess_" + Math.random().toString(36).substr(2, 9);
            // Lookup the dynamic AMI ID based on the requested profile button
            let amiId = '';
            if (profileId === 'win_base') amiId = localStorage.getItem('_st_ami_win_base');
            if (profileId === 'kali_base') amiId = localStorage.getItem('_st_ami_kali_base');
            if (profileId === 'win_malware') amiId = localStorage.getItem('_st_ami_win_mal');

            // Fallbacks in case the user hasn't saved the AWS config page yet
            amiId = amiId || "ami-0dab019e2f90d9a3d";

            const subnetId = localStorage.getItem('_st_subnet_id') || "subnet-0123456789abcdef0";
            let iamProfileName = localStorage.getItem('_st_iam_profile');
            // If it's literally not set yet (first load), default it. If user cleared it to "", allow empty.
            if (iamProfileName === null) {
                iamProfileName = "ShadowTrust-Analysis-Role";
            }

            // Get active protocol if select element exists
            const protocolSelect = document.getElementById(`protocol_${profileId}`);
            const protocolStr = protocolSelect ? protocolSelect.value : 'rdp';

            const response = await apiService.post('/labs/start', {
                ami_id: amiId,
                instance_type: profileId.includes('malware') ? 't3.xlarge' : 't3.medium',
                subnet_id: subnetId,
                iam_profile_name: iamProfileName,
                security_group_id: localStorage.getItem('_st_aws_sg') || undefined,
                protocol: protocolStr,
                session_id: sessionId,
                user_id: sessionId, // Mock user ID mappings 
                profile_id: profileId,
                environment_type: profileId, // Guacamole environment mapping
                aws_access_key: localStorage.getItem('_st_aws_ak') || undefined,
                aws_secret_key: localStorage.getItem('_st_aws_sk') || undefined,
                aws_region: localStorage.getItem('_st_aws_region') || undefined
            });

            if (response.status === 'provisioning' || response.status === 'success') {
                this.instances[profileId] = { instanceId: response.instance_id, labId: response.lab_id };
                this.saveState();
                this.setButtonState(btnElement, 'ACTIVE', 'CONNECT TERMINAL');

                const orb = document.getElementById(`dot_${profileId}`);
                if (orb) { orb.style.background = 'var(--accent-primary)'; orb.style.boxShadow = '0 0 10px var(--accent-primary)'; orb.style.animation = 'pulse-red 2s infinite'; }

                // Show notification
                this.showNotification(`Successfully deployed ${profileId} (${response.lab_id})`, 'success');
            } else {
                this.setButtonState(btnElement, 'DEFAULT', 'PROVISION');
                this.showNotification(`Failed to launch: ${response.message}`, 'error');
            }

        } catch (error) {
            console.error("VM Launch Error:", error);
            this.setButtonState(btnElement, 'DEFAULT', 'PROVISION');
            this.showNotification(`API Error: ${error.message}`, 'error');
        }
    }

    async terminateInstance(profileId, createBtnElement, terminateBtnElement) {
        const instanceData = this.instances[profileId];
        if (!instanceData) {
            this.showNotification("No active instance found for this profile.", "error");
            return;
        }

        const { instanceId, labId } = instanceData;

        try {
            this.setButtonState(terminateBtnElement, 'LOADING', 'TERMINATING...');

            const response = await apiService.post('/labs/stop', {
                lab_id: labId,
                instance_id: instanceId,
                aws_access_key: localStorage.getItem('_st_aws_ak') || undefined,
                aws_secret_key: localStorage.getItem('_st_aws_sk') || undefined,
                aws_region: localStorage.getItem('_st_aws_region') || undefined
            });

            if (response.status === 'success') {
                delete this.instances[profileId];
                this.saveState();
                this.setButtonState(createBtnElement, 'DEFAULT', 'PROVISION');
                this.setButtonState(terminateBtnElement, 'DEFAULT', '');

                const orb = document.getElementById(`dot_${profileId}`);
                if (orb) { orb.style.background = '#555'; orb.style.boxShadow = 'none'; orb.style.animation = 'none'; }

                this.showNotification(`Instance ${instanceId} terminated.`, 'success');
            } else {
                this.setButtonState(terminateBtnElement, 'DEFAULT', '');
                this.showNotification(`Failed to terminate: ${response.message}`, 'error');
            }
        } catch (error) {
            console.error("VM Terminate Error:", error);
            this.setButtonState(terminateBtnElement, 'DEFAULT', '');
            this.showNotification(`API Error: ${error.message}`, 'error');
        }
    }

    async openConsole(profileId) {
        const instanceData = this.instances[profileId];
        if (!instanceData || !instanceData.labId) return;

        // Route the user to our dedicated Secure Analysis Gateway, passing the Lab ID
        window.open(`vm_session.html?id=${instanceData.labId}`, '_blank');
    }

    setButtonState(btn, state, text) {
        if (!btn) return;

        this.isLoading = this.isLoading || {};
        switch (state) {
            case 'LOADING':
                this.isLoading[btn.getAttribute('data-profile')] = true;
                btn.disabled = true;
                btn.innerHTML = `<i class="fas fa-spinner fa-spin"></i> ${text}`;
                btn.style.opacity = '0.7';
                break;
            case 'ACTIVE':
                this.isLoading[btn.getAttribute('data-profile')] = false;
                btn.disabled = false;
                btn.innerHTML = `<i class="fas fa-terminal"></i> ${text}`;
                btn.style.opacity = '1';
                btn.style.background = 'var(--accent-primary)'; // Matrix green for active
                btn.style.color = '#000';

                // Swap click handler to open inline workspace
                const labId = this.instances[btn.getAttribute('data-profile')]?.labId;
                if (labId) {
                    btn.onclick = () => this.openWorkspace(labId);
                }
                break;
            case 'DEFAULT':
                this.isLoading[btn.getAttribute('data-profile')] = false;
                btn.disabled = false;

                if (text.includes('PROVISION')) {
                    btn.innerHTML = `<i class="fas fa-bolt"></i> ${text}`;
                    btn.style.background = ''; // Reset to class default
                    btn.style.color = '';
                    btn.style.borderColor = '';
                    const profileId = btn.getAttribute('data-profile');
                    btn.onclick = () => this.launchInstance(profileId, btn);
                } else {
                    // Empty text = termination button
                    btn.innerHTML = `<i class="fas fa-power-off"></i>`;
                }
                btn.style.opacity = '1';
                break;
        }
    }

    openWorkspace(labId) {
        document.body.classList.add('workspace-mode');
        this.activeWorkspaceLab = labId;
        const frame = document.getElementById('vdiFrame');
        if (frame) {
            frame.src = ''; // reset
            frame.style.display = 'none';
        }
        document.getElementById('vdiLoaderText').style.display = 'block';
        document.getElementById('vdiSubLoader').innerText = 'Negotiating cryptographic keys...';
        document.getElementById('vdiSubLoader').style.color = '#666';

        this.pollVdiStatus(labId);
    }

    async pollVdiStatus(labId) {
        if (this.activeWorkspaceLab !== labId) return; // user closed or switched
        try {
            const response = await apiService.get(`/labs/status/${labId}`);
            if (response.status === 'READY') {
                document.getElementById('vdiLoaderText').style.display = 'none';
                const frame = document.getElementById('vdiFrame');
                frame.style.display = 'block';
                // Construct Guacamole Client URL format: /guacamole/#/client/[base64(id\0c\0postgresql)]
                const guacIdString = `${response.guacamole_connection_id}\0c\0postgresql`;
                const b64Id = btoa(guacIdString);

                let sessionUrl = `http://localhost:8080/guacamole/#/client/${b64Id}`;
                if (response.auth_token) {
                    sessionUrl += `?token=${response.auth_token}`;
                }

                frame.src = sessionUrl;
            } else if (response.status === 'ERROR') {
                document.getElementById('vdiSubLoader').innerText = 'FATAL ERROR: AWS Orchestrator failed.';
                document.getElementById('vdiSubLoader').style.color = 'var(--accent-critical)';
            } else {
                setTimeout(() => this.pollVdiStatus(labId), 3000);
            }
        } catch (e) {
            console.error('Polling error', e);
            setTimeout(() => this.pollVdiStatus(labId), 3000);
        }
    }

    closeWorkspace() {
        document.body.classList.remove('workspace-mode');
        this.activeWorkspaceLab = null;
        const frame = document.getElementById('vdiFrame');
        if (frame) frame.src = '';
    }

    toggleFullscreen() {
        const workspace = document.getElementById('vdiWorkspace');
        if (!document.fullscreenElement) {
            workspace.requestFullscreen().catch(err => {
                this.showNotification(`Error entering fullscreen: ${err.message}`, 'error');
            });
        } else {
            document.exitFullscreen();
        }
    }

    showNotification(message, type = 'success') {
        const notif = document.createElement('div');
        notif.style.position = 'fixed';
        notif.style.bottom = '20px';
        notif.style.right = '20px';
        notif.style.padding = '15px 25px';
        notif.style.borderRadius = '4px';
        notif.style.color = '#fff';
        notif.style.fontFamily = "'JetBrains Mono', monospace";
        notif.style.zIndex = '9999';
        notif.style.boxShadow = '0 4px 12px rgba(0,0,0,0.5)';
        notif.style.background = type === 'success' ? 'var(--accent-primary)' : 'var(--accent-critical)';
        notif.style.color = type === 'success' ? '#000' : '#fff';
        notif.innerHTML = type === 'success' ? `<i class="fas fa-check-circle"></i> ${message}` : `<i class="fas fa-exclamation-triangle"></i> ${message}`;

        document.body.appendChild(notif);

        setTimeout(() => {
            notif.style.opacity = '0';
            notif.style.transition = 'opacity 0.5s ease-out';
            setTimeout(() => notif.remove(), 500);
        }, 4000);
    }
}

export const vmClient = new VMLabClient();

// Expose to window for inline HTML onclick handlers
window.vmClient = vmClient;
