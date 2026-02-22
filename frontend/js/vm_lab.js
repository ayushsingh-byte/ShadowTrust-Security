import { apiService } from './api.js';

document.addEventListener('DOMContentLoaded', () => {
    loadVMs();
    setInterval(loadVMs, 10000); // Poll every 10s
});

async function loadVMs() {
    try {
        const vms = await apiService.get('/vm/list');
        renderVMs(vms);
    } catch (error) {
        console.error("Failed to load VMs", error);
    }
}

function renderVMs(vmsData) {
    // We have hardcoded cards in HTML, we will update them based on ID for now.
    // Ideally we should generate the cards dynamically.
    // For this prototype, let's target the specific IDs we know exist in HTML.

    // Iterate over the keys (vm-IDs)
    for (const [vmId, vmInfo] of Object.entries(vmsData)) {
        updateVMCard(vmId, vmInfo);
    }
}

function updateVMCard(vmId, vmInfo) {
    // Find the card by ID text? The HTML doesn't have ID on the main card div easily accessbile.
    // "ID: vm-8291f" is inside a div.

    // Better approach: Let's find all vm-cards and check their ID text.
    const cards = document.querySelectorAll('.vm-card');
    cards.forEach(card => {
        if (card.innerText.includes(vmId)) {
            // Update Status Dot and Text
            const statusDot = card.querySelector('.vm-status-dot');
            const statusText = card.querySelector('.text-green') || card.querySelector('.text-red') || card.querySelector('.vm-status-text'); // fallback

            if (vmInfo.status === 'running') {
                statusDot.className = 'vm-status-dot running';
                statusText.className = 'text-green';
                statusText.innerText = 'RUNNING';
            } else {
                statusDot.className = 'vm-status-dot stopped';
                statusText.className = 'text-red'; // We might need to define text-red in CSS if not exists, but neon-red usually exists
                statusText.innerText = 'STOPPED';
                statusText.style.color = 'var(--neon-pink)';
            }

            // Bind Buttons
            const buttons = card.querySelectorAll('button');
            const startStopBtn = buttons[2]; // The 3rd button is usually STOP or START

            // Clear old event listeners (simple way: clone node)
            const newBtn = startStopBtn.cloneNode(true);
            startStopBtn.parentNode.replaceChild(newBtn, startStopBtn);

            if (vmInfo.status === 'running') {
                newBtn.innerText = 'STOP';
                newBtn.style.color = 'var(--neon-pink)';
                newBtn.style.borderColor = 'var(--neon-pink)';
                newBtn.onclick = () => controlVM(vmId, 'stop');
            } else {
                newBtn.innerText = 'START';
                newBtn.style.color = 'var(--neon-cyan)';
                newBtn.style.borderColor = 'var(--neon-cyan)';
                newBtn.onclick = () => controlVM(vmId, 'start');
            }
        }
    });
}

async function controlVM(vmId, action) {
    try {
        // Show loading state?
        alert(`Sending ${action} signal to ${vmId}...`);
        await apiService.post(`/vm/${vmId}/${action}`);
        setTimeout(loadVMs, 2000); // Reload after brief delay
    } catch (error) {
        alert(`Failed to ${action} VM: ${error.message}`);
    }
}
