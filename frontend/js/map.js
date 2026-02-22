/* Leaflet Map Logic */

const CyberMap = {
    map: null,

    init: () => {
        if (!document.getElementById('cyberMap')) return;

        CyberMap.map = L.map('cyberMap', {
            center: [20, 0],
            zoom: 2,
            zoomControl: false,
            attributionControl: false
        });

        // Dark Theme Tiles
        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            maxZoom: 19
        }).addTo(CyberMap.map);

        // Add Zoom Control manually to position it better
        L.control.zoom({ position: 'bottomright' }).addTo(CyberMap.map);

        // Simulate initial markers
        for (let i = 0; i < 10; i++) {
            CyberMap.addRandomAttack();
        }

        // Add new attack every few seconds
        setInterval(CyberMap.addRandomAttack, 3000);
    },

    addRandomAttack: () => {
        // Random coords roughly within populated areas
        const lat = Utils.randomInt(-50, 70);
        const lng = Utils.randomInt(-120, 140);

        const types = ['DDoS', 'SSH Brute Force', 'Malware Beacon'];
        const type = types[Math.floor(Math.random() * types.length)];
        const color = type === 'DDoS' ? '#ff1744' : '#00e5ff';

        // Custom div icon for pulse effect
        const icon = L.divIcon({
            className: 'custom-div-icon',
            html: `<div style="background-color:${color}; width:10px; height:10px; border-radius:50%; box-shadow:0 0 10px ${color}; animation: pulse 1s infinite;"></div>`,
            iconSize: [10, 10],
            iconAnchor: [5, 5]
        });

        const marker = L.marker([lat, lng], { icon: icon }).addTo(CyberMap.map);

        marker.bindPopup(`
            <div style="text-align:center;">
                <strong style="color:${color}">${type}</strong><br>
                <span>${Utils.randomIP()}</span><br>
                <span>${Utils.getTime()}</span>
            </div>
        `); // Don't open automatically to avoid clutter

        // Remove marker after 10 seconds to keep map clean
        setTimeout(() => {
            CyberMap.map.removeLayer(marker);
        }, 10000);
    }
};
