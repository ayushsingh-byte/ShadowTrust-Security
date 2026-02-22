/* Main Dashboard Controller */

document.addEventListener('DOMContentLoaded', () => {
    // Initialize components
    Charts.init();
    CyberMap.init();
    FeedTable.init();

    // Start simulations
    Dashboard.initNodeStatus();
    Dashboard.startRealTimeUpdates();
});

const Dashboard = {
    initNodeStatus: () => {
        const tbody = document.getElementById('nodeTableBody');
        if (!tbody) return;

        const nodes = [
            { id: 'NODE-01', ip: '192.168.1.101', status: 'Online' },
            { id: 'NODE-02', ip: '10.0.0.55', status: 'Online' },
            { id: 'NODE-03', ip: '172.16.23.4', status: 'Offline' },
            { id: 'NODE-04', ip: '192.168.1.200', status: 'Online' }
        ];

        nodes.forEach(node => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td class="text-mono" style="padding:10px;">${node.id}</td>
                <td>${node.ip}</td>
                <td><span class="${node.status === 'Online' ? 'text-green' : 'text-red'}">${node.status}</span></td>
                <td>${Utils.getTime()}</td>
            `;
            tbody.appendChild(tr);
        });
    },

    startRealTimeUpdates: () => {
        // Update Total Attacks Counter
        const attackCounter = document.querySelector('.metric-value.text-neon');
        if (attackCounter) {
            setInterval(() => {
                let current = parseInt(attackCounter.innerText.replace(/,/g, ''));
                current += Utils.randomInt(0, 5);
                attackCounter.innerText = current.toLocaleString();
            }, 1000);
        }

        // Add to Critical Logs
        const logPanel = document.getElementById('alertLog');
        if (logPanel) {
            setInterval(() => {
                const alerts = [
                    "New malware signature detected on Node-01",
                    "High rate of SSH failures from 192.168.x.x",
                    "Database port scanning engaged",
                    "Unusual outbound traffic detected"
                ];
                const type = alerts[Math.floor(Math.random() * alerts.length)];

                const div = document.createElement('div');
                div.className = 'log-item';
                div.innerHTML = `
                    <span class="text-red">[CRITICAL]</span>
                    <span>${type}</span>
                    <span class="text-secondary" style="font-size:0.7rem">${Utils.getTime()}</span>
                `;

                logPanel.prepend(div);

                // Limit logs
                if (logPanel.children.length > 20) {
                    logPanel.lastElementChild.remove();
                }
            }, 4000);
        }
    }
};
