/* Chart.js Configurations - Updated for Analytics */

const Charts = {
    init: () => {
        // Check if elements exist before initializing to avoid errors on pages without charts
        if (document.getElementById('attackTrendChart')) Charts.initTrendChart();
        if (document.getElementById('attackTypeChart')) Charts.initTypeChart();
    },

    initTrendChart: () => {
        const ctx = document.getElementById('attackTrendChart').getContext('2d');
        const gradient = ctx.createLinearGradient(0, 0, 0, 400);
        gradient.addColorStop(0, 'rgba(0, 229, 255, 0.5)');
        gradient.addColorStop(1, 'rgba(0, 229, 255, 0)');

        new Chart(ctx, {
            type: 'line',
            data: {
                labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00', 'Now'],
                datasets: [{
                    label: 'Attacks Detected',
                    data: [120, 190, 150, 250, 320, 280, 390],
                    borderColor: '#00e5ff',
                    backgroundColor: gradient,
                    fill: true,
                    tension: 0.4,
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { labels: { color: '#8b949e' } } },
                scales: {
                    y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#8b949e' } },
                    x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#8b949e' } }
                }
            }
        });
    },

    initTypeChart: () => {
        const ctx = document.getElementById('attackTypeChart').getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['DDoS', 'Brute Force', 'SQL Injection', 'Malware', 'Phishing'],
                datasets: [{
                    data: [35, 25, 20, 15, 5],
                    backgroundColor: ['#ff1744', '#00e5ff', '#ffd600', '#00ff9f', '#aa00ff'],
                    borderColor: '#161b22',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'right', labels: { color: '#8b949e' } } }
            }
        });
    }
};
