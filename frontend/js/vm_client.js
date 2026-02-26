import { apiService } from './api.js';

class VMLabClient {
    constructor() {
        this.instances = {}; // Map of profile_id to active instance_id
        this.isLoading = false;
    }

    async launchInstance(profileId, btnElement) {
        if (this.isLoading) return;

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
            const iamProfileName = localStorage.getItem('_st_iam_profile') || "ShadowTrust-Analysis-Role";

            const response = await apiService.post('/vm/launch', {
                ami_id: amiId,
                instance_type: profileId.includes('malware') ? 't3.xlarge' : 't3.medium',
                subnet_id: subnetId,
                iam_profile_name: iamProfileName,
                session_id: sessionId,
                aws_access_key: localStorage.getItem('_st_aws_ak') || undefined,
                aws_secret_key: localStorage.getItem('_st_aws_sk') || undefined,
                aws_region: localStorage.getItem('_st_aws_region') || undefined
            });

            if (response.status === 'success') {
                this.instances[profileId] = response.instance_id;
                this.setButtonState(btnElement, 'ACTIVE', 'OPEN IAM CONSOLE');

                // Show notification
                this.showNotification(`Successfully deployed ${profileId} (${response.instance_id})`, 'success');
            } else {
                this.setButtonState(btnElement, 'DEFAULT', 'CREATE');
                this.showNotification(`Failed to launch: ${response.message}`, 'error');
            }

        } catch (error) {
            console.error("VM Launch Error:", error);
            this.setButtonState(btnElement, 'DEFAULT', 'CREATE');
            this.showNotification(`API Error: ${error.message}`, 'error');
        }
    }

    async terminateInstance(profileId, createBtnElement, terminateBtnElement) {
        const instanceId = this.instances[profileId];
        if (!instanceId) {
            this.showNotification("No active instance found for this profile.", "error");
            return;
        }

        try {
            this.setButtonState(terminateBtnElement, 'LOADING', 'TERMINATING...');

            const response = await apiService.post(`/vm/${instanceId}/terminate`, {
                aws_access_key: localStorage.getItem('_st_aws_ak') || undefined,
                aws_secret_key: localStorage.getItem('_st_aws_sk') || undefined,
                aws_region: localStorage.getItem('_st_aws_region') || undefined
            });

            if (response.status === 'success') {
                delete this.instances[profileId];
                this.setButtonState(createBtnElement, 'DEFAULT', 'CREATE');
                this.setButtonState(terminateBtnElement, 'DEFAULT', 'TERMINATE');
                this.showNotification(`Instance ${instanceId} terminated.`, 'success');
            } else {
                this.setButtonState(terminateBtnElement, 'DEFAULT', 'TERMINATE');
                this.showNotification(`Failed to terminate: ${response.message}`, 'error');
            }
        } catch (error) {
            console.error("VM Terminate Error:", error);
            this.setButtonState(terminateBtnElement, 'DEFAULT', 'TERMINATE');
            this.showNotification(`API Error: ${error.message}`, 'error');
        }
    }

    async openConsole(profileId) {
        const instanceId = this.instances[profileId];
        if (!instanceId) return;

        try {
            const response = await apiService.post(`/session/${instanceId}/open`, {
                aws_access_key: localStorage.getItem('_st_aws_ak') || undefined,
                aws_secret_key: localStorage.getItem('_st_aws_sk') || undefined,
                aws_region: localStorage.getItem('_st_aws_region') || undefined
            });
            if (response.status === 'success' && response.session_url) {
                // Open SSM in a new tab
                window.open(response.session_url, '_blank');
            } else {
                this.showNotification("Failed to generate session URL.", "error");
            }
        } catch (error) {
            console.error("Session Error:", error);
            this.showNotification("Failed to fetch session URL.", "error");
        }
    }

    setButtonState(btn, state, text) {
        if (!btn) return;

        switch (state) {
            case 'LOADING':
                this.isLoading = true;
                btn.disabled = true;
                btn.innerHTML = `<i class="fas fa-spinner fa-spin"></i> ${text}`;
                btn.style.opacity = '0.7';
                break;
            case 'ACTIVE':
                this.isLoading = false;
                btn.disabled = false;
                btn.innerHTML = `<i class="fas fa-terminal"></i> ${text}`;
                btn.style.opacity = '1';
                btn.style.background = '#00ff41'; // Matrix green for active
                btn.style.color = '#000';

                // Swap click handler to open console
                const profileId = btn.getAttribute('data-profile');
                btn.onclick = () => this.openConsole(profileId);
                break;
            case 'DEFAULT':
                this.isLoading = false;
                btn.disabled = false;
                btn.innerHTML = text.includes('CREATE') ? `<i class="fas fa-play"></i> ${text}` : `<i class="fas fa-trash"></i> ${text}`;
                btn.style.opacity = '1';

                if (text.includes('CREATE')) {
                    btn.style.background = ''; // Reset to default CSS
                    btn.style.color = '';
                    const profileId = btn.getAttribute('data-profile');
                    btn.onclick = () => this.launchInstance(profileId, btn);
                }
                break;
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
        notif.style.background = type === 'success' ? '#00ff41' : '#ff0055';
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
