import { apiService } from './api.js';

class VMLabClient {
    /**
     * Maps each lab card to a provider-independent environment and resource
     * tier. The backend decides what those mean — a container image and CPU/RAM
     * limits locally, an AMI and instance type on AWS. No EC2 instance types
     * are named client-side.
     */
    static CARD_PROFILES = {
        kali_base:   { environment: 'kali',    profile: 'light' },
        win_malware: { environment: 'windows', profile: 'heavy' }
    };

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

    /** Reverse of CARD_PROFILES: which card does this environment belong to? */
    cardIdFor(environment) {
        if (!environment) return null;
        const env = String(environment).toLowerCase();
        for (const [cardId, cfg] of Object.entries(VMLabClient.CARD_PROFILES)) {
            if (cfg.environment === env) return cardId;
        }
        // Tolerate legacy card ids arriving straight back from the provider.
        return VMLabClient.CARD_PROFILES[env] ? env : null;
    }

    async updateGlobalStats() {
        try {
            const metrics = await apiService.get('/labs/cluster-metrics');
            if (metrics.status !== 'success') return;

            const totalVcpu = metrics.vcpu || 0;
            const totalRam = metrics.ram || 0;
            const activeCount = metrics.active_count || 0;

            // Real host capacity from the provider (psutil on the docker host / EC2 limits).
            const maxVcpu = metrics.host_vcpu || totalVcpu || 1;
            const maxRam = metrics.host_ram_gb || totalRam || 1;

            const region = document.getElementById('global-uplink-region');
            if (region) region.textContent = `${metrics.provider || 'local'} · ${metrics.region || 'local docker host'}`
                + (metrics.host_cpu_pct != null ? ` · host CPU ${metrics.host_cpu_pct}%` : '');

            const e1 = document.getElementById('global-vcpu-count');
            if (e1) e1.textContent = totalVcpu;
            const vcpuMax = document.getElementById('global-vcpu-max');
            if (vcpuMax) vcpuMax.textContent = maxVcpu;

            const e2 = document.getElementById('global-vcpu-bar');
            if (e2) e2.style.width = `${Math.min((totalVcpu / maxVcpu) * 100, 100)}%`;

            const e3 = document.getElementById('global-ram-count');
            if (e3) e3.textContent = totalRam;
            const ramMax = document.getElementById('global-ram-max');
            if (ramMax) ramMax.textContent = maxRam;

            const e4 = document.getElementById('global-ram-bar');
            if (e4) e4.style.width = `${Math.min((totalRam / maxRam) * 100, 100)}%`;

            const e5 = document.getElementById('global-instance-count');
            if (e5) e5.textContent = activeCount;

            const e6 = document.getElementById('global-instance-sub');
            if (e6) e6.textContent = activeCount;

            // Update individual lab specs with live data if available.
            // `labs` is the provider-neutral payload; `instances` is the legacy alias.
            const labs = metrics.labs || metrics.instances;
            if (labs && Array.isArray(labs)) {
                for (const lab of labs) {
                    const cardId = this.cardIdFor(lab.environment);
                    if (!cardId || lab.status !== 'RUNNING') continue;

                    const btn = document.querySelector(`button[data-profile="${cardId}"]`);
                    if (!btn) continue;

                    const specsDiv = btn.closest('.vm-card').querySelector('.vm-specs');
                    if (specsDiv && !specsDiv.dataset.live) {
                        specsDiv.dataset.live = "true";
                        const res = lab.resources || {};
                        const tier = res.label || lab.profile || '—';
                        const size = (res.cpu && res.memory_gb)
                            ? `${res.cpu} CPU / ${res.memory_gb} GB`
                            : '—';
                        specsDiv.innerHTML = `
                            <div style="margin-bottom: 8px;">Host <span style="color: var(--accent-primary); font-family: var(--font-mono);">${lab.host || '—'}</span></div>
                            <div style="margin-bottom: 8px;">Profile <span>${tier}</span></div>
                            <div style="margin-bottom: 8px;">Resources <span>${size}</span></div>
                            <div>Status <span class="text-green">RUNNING</span></div>
                        `;
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
                console.warn(`[VMLab] Could not verify status for ${profileId}. Clearing stale state.`, error);

                // Backend unreachable — cannot confirm instance is alive, so clear the stale entry
                delete this.instances[profileId];
                this.saveState();
                if (btn) this.setButtonState(btn, 'DEFAULT', 'PROVISION');
                const orb = document.getElementById(`dot_${profileId}`);
                if (orb) { orb.style.background = '#555'; orb.style.boxShadow = 'none'; orb.style.animation = 'none'; }
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

            // Card -> provider-independent environment + resource tier.
            // The backend maps these to a container image or an AMI; the UI
            // never names an EC2 instance type.
            const card = VMLabClient.CARD_PROFILES[profileId] ||
                { environment: profileId, profile: 'standard' };

            // Get active protocol if select element exists
            const protocolSelect = document.getElementById(`protocol_${profileId}`);
            const protocolStr = protocolSelect ? protocolSelect.value : 'rdp';

            const response = await apiService.post('/labs/start', {
                environment_type: card.environment,
                profile: card.profile,
                protocol: protocolStr,
                user_id: sessionId,
                // AWS credentials are only read when the backend runs with
                // INFRA_PROVIDER=aws; in local mode they are ignored.
                aws_access_key: localStorage.getItem('_st_aws_ak') || undefined,
                aws_secret_key: localStorage.getItem('_st_aws_sk') || undefined,
                aws_region: localStorage.getItem('_st_aws_region') || undefined,
                security_group_id: localStorage.getItem('_st_aws_sg') || undefined
            });

            if (response.status === 'provisioning' || response.status === 'success') {
                this.instances[profileId] = {
                    labId: response.lab_id,
                    provider: response.provider,
                    environment: response.environment,
                    profile: response.profile
                };
                this.saveState();

                // VM is PROVISIONING — keep button in loading state until status checks pass
                this.setButtonState(btnElement, 'LOADING', 'BOOTING...');

                const orb = document.getElementById(`dot_${profileId}`);
                if (orb) { orb.style.background = '#f59e0b'; orb.style.boxShadow = '0 0 10px #f59e0b'; orb.style.animation = 'pulse-red 2s infinite'; }

                this.showNotification(`Instance ${response.lab_id} is booting. This takes 3-10 minutes...`, 'success');

                // Poll in background — button transitions to CONNECT TERMINAL when READY
                this._pollProvisioningStatus(profileId, response.lab_id, btnElement);
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

        const { labId } = instanceData;

        try {
            this.setButtonState(terminateBtnElement, 'LOADING', 'TERMINATING...');

            const response = await apiService.post('/labs/stop', {
                lab_id: labId,
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

                this.showNotification(`Lab ${labId} terminated.`, 'success');
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
                btn.style.background = '';
                btn.style.color = '';
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

        this._setupKeyboardCapture();
        this.pollVdiStatus(labId);
    }

    _setupKeyboardCapture() {
        const frame     = document.getElementById('vdiFrame');
        const workspace = document.getElementById('vdiWorkspace');
        if (!frame || !workspace) return;

        // ── Tear down any previous listeners ────────────────────────────────
        if (this._wsMdownHandler) {
            workspace.removeEventListener('mousedown',  this._wsMdownHandler,  true);
            workspace.removeEventListener('touchstart', this._wsMdownHandler,  true);
        }
        if (this._docKeyHandler) {
            document.removeEventListener('keydown', this._docKeyHandler, true);
        }

        // ── Mousedown inside workspace → focus iframe ────────────────────────
        // Using capture phase so we get it before anything else sees it.
        this._wsMdownHandler = (e) => {
            if (e.target.closest('.vdi-toolbar')) return; // don't hijack toolbar buttons
            frame.focus();
        };
        workspace.addEventListener('mousedown',  this._wsMdownHandler, true);
        workspace.addEventListener('touchstart', this._wsMdownHandler, { capture: true, passive: true });

        // ── If a keydown reaches the PARENT document while workspace is open,
        //    the iframe lost focus — push it back immediately.
        //    This handles clicks outside the iframe (e.g. on the toolbar) that
        //    steal focus back to the parent page.
        this._docKeyHandler = () => {
            if (document.body.classList.contains('workspace-mode') &&
                document.activeElement !== frame) {
                frame.focus();
            }
        };
        document.addEventListener('keydown', this._docKeyHandler, true);

        // ── Re-focus on each mouse-enter (handles alt-tab / OS-level focus loss)
        frame.onmouseenter = () => frame.focus();
    }

    async pollVdiStatus(labId) {
        if (this.activeWorkspaceLab !== labId) return; // user closed or switched
        try {
            const response = await apiService.get(`/labs/status/${labId}`);
            // Treat dead/unknown statuses as terminal failures
            const terminalStatuses = ['ERROR', 'NOT_FOUND', 'TERMINATED', 'STOPPED'];

            if (response.status === 'READY') {
                document.getElementById('vdiLoaderText').style.display = 'none';
                const frame = document.getElementById('vdiFrame');
                frame.style.display = 'block';

                const guacId = response.guacamole_connection_id;

                if (guacId) {
                    // Guacamole client URL format:
                    // base64( connectionId + NUL + "c" + NUL + "postgresql" )
                    // IMPORTANT: ?token= must come BEFORE the # — it is a real query param
                    // that Guacamole's Angular app reads via $location.search() on startup.
                    // Putting it after # makes it invisible to the Angular router.
                    const guacIdString = `${guacId}\0c\0postgresql`;
                    const b64Id = btoa(guacIdString);

                    let sessionUrl;
                    if (response.auth_token) {
                        sessionUrl = `http://localhost:8080/guacamole/?token=${response.auth_token}#/client/${b64Id}`;
                    } else {
                        // No auto-token — load Guacamole home (user logs in with guacadmin / guacadmin)
                        sessionUrl = `http://localhost:8080/guacamole/`;
                    }
                    frame.src = sessionUrl;

                    // Guacamole is a SPA that authenticates then re-renders.
                    // Focus needs to be injected at multiple points during that init.
                    // Without this, keyboard events stay trapped in the parent page.
                    [100, 500, 1200, 2500].forEach(ms =>
                        setTimeout(() => {
                            if (this.activeWorkspaceLab === labId) frame.focus();
                        }, ms)
                    );

                    // Show the keyboard-activation hint for 4 s
                    const hint = document.getElementById('vdiKeyHint');
                    if (hint) {
                        hint.style.display = 'block';
                        // Re-trigger animation cleanly
                        hint.style.animation = 'none';
                        void hint.offsetHeight;
                        hint.style.animation = 'fadeHint 4s ease-out forwards';
                        setTimeout(() => { hint.style.display = 'none'; }, 4200);
                    }
                } else {
                    // Lab is READY but Guacamole connection was not registered (Guacamole may have been offline during provisioning)
                    frame.style.display = 'none';
                    const loader = document.getElementById('vdiLoaderText');
                    loader.style.display = 'block';
                    loader.innerHTML = `
                        <i class="fas fa-exclamation-triangle" style="font-size:2rem;color:var(--accent-secondary);margin-bottom:10px;"></i>
                        <div style="color:var(--accent-secondary)">INSTANCE READY — NO BROWSER SESSION</div>
                        <div style="font-size:0.8rem;color:#888;margin-top:8px;">Guacamole session was not registered. Instance is running.</div>
                        <div style="font-size:0.85rem;color:var(--text-primary);margin-top:6px;font-family:var(--font-mono);">
                            IP: <span style="color:var(--accent-primary)">${response.host || response.private_ip || 'pending'}</span>
                        </div>
                        <div style="margin-top:12px;display:flex;gap:8px;justify-content:center;flex-wrap:wrap;">
                            <button onclick="window.vmClient.reattachGuacamole('${labId}')" class="soc-btn" style="font-size:0.75rem;padding:8px 14px;cursor:pointer;">
                                <i class="fas fa-sync"></i> Retry Connection
                            </button>
                            <a href="http://localhost:8080/guacamole/" target="_blank" class="soc-btn" style="font-size:0.75rem;padding:8px 14px;">
                                <i class="fas fa-external-link-alt"></i> Open Guacamole
                            </a>
                        </div>
                    `;
                }
            } else if (terminalStatuses.includes(response.status)) {
                // VM is dead — close the workspace panel and reset the button to PROVISION
                this.closeWorkspace();
                // Find which profile owned this lab and reset it
                for (const [profileId, data] of Object.entries(this.instances)) {
                    if (data.labId === labId) {
                        delete this.instances[profileId];
                        this.saveState();
                        const btn = document.querySelector(`button[data-profile="${profileId}"]`);
                        if (btn) this.setButtonState(btn, 'DEFAULT', 'PROVISION');
                        const orb = document.getElementById(`dot_${profileId}`);
                        if (orb) { orb.style.background = '#555'; orb.style.boxShadow = 'none'; orb.style.animation = 'none'; }
                        break;
                    }
                }
                const msg = response.status === 'ERROR'
                    ? 'Lab launch failed — infrastructure provider error. Check the backend logs and provider configuration.'
                    : `Instance is no longer available (${response.status}). Please provision a new one.`;
                this.showNotification(msg, 'error');
            } else {
                setTimeout(() => this.pollVdiStatus(labId), 3000);
            }
        } catch (e) {
            console.error('Polling error', e);
            setTimeout(() => this.pollVdiStatus(labId), 3000);
        }
    }

    async reattachGuacamole(labId) {
        this.showNotification('Re-registering Guacamole session...', 'success');
        const loader = document.getElementById('vdiLoaderText');
        if (loader) {
            loader.innerHTML = `<i class="fas fa-spinner fa-spin" style="font-size:2rem;color:var(--accent-primary);margin-bottom:10px;"></i><div style="color:#aaa;margin-top:8px;">Re-registering browser session...</div>`;
        }
        try {
            await apiService.post(`/labs/reattach/${labId}`, {});
            // Give the background task ~3s to write to Guacamole DB, then re-poll
            setTimeout(() => this.pollVdiStatus(labId), 3000);
        } catch (e) {
            this.showNotification(`Reattach failed: ${e.message}`, 'error');
            // Reset display to show the error state again
            setTimeout(() => this.pollVdiStatus(labId), 1000);
        }
    }

    closeWorkspace() {
        document.body.classList.remove('workspace-mode');
        this.activeWorkspaceLab = null;

        // Remove keyboard capture handlers
        const workspace = document.getElementById('vdiWorkspace');
        if (workspace && this._wsMdownHandler) {
            workspace.removeEventListener('mousedown',  this._wsMdownHandler, true);
            workspace.removeEventListener('touchstart', this._wsMdownHandler, true);
            this._wsMdownHandler = null;
        }
        if (this._docKeyHandler) {
            document.removeEventListener('keydown', this._docKeyHandler, true);
            this._docKeyHandler = null;
        }

        const frame = document.getElementById('vdiFrame');
        if (frame) {
            frame.onmouseenter = null;
            frame.src = '';
        }
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
