/* DataTables Logic for Live Feed */

const FeedTable = {
    table: null,

    init: () => {
        if (!document.getElementById('attackTable')) return;

        FeedTable.table = $('#attackTable').DataTable({
            paging: true,
            pageLength: 5,
            lengthChange: false,
            searching: true,
            ordering: false, // Disable ordering for performance on streaming data
            info: false,
            language: {
                search: "_INPUT_",
                searchPlaceholder: "Search logs..."
            },
            columnDefs: [
                { className: "text-mono", targets: [1] } // Font-mono for IP
            ]
        });

        // Start Flux
        setInterval(FeedTable.addRandomRow, 2000);
    },

    addRandomRow: () => {
        const types = ['SSH Login Fail', 'SQL Injection', 'XSS Attempt', 'Port Scan', 'Malware Download'];
        const severities = ['<span class="text-red">Critical</span>', '<span class="text-neon">Info</span>', '<span style="color:var(--warning-yellow)">Warning</span>'];

        const type = types[Math.floor(Math.random() * types.length)];
        const severity = severities[Math.floor(Math.random() * severities.length)];
        const ip = Utils.randomIP();
        const country = Utils.randomCountry();
        const time = Utils.getTime();

        const rowNode = FeedTable.table.row.add([
            time,
            ip,
            country,
            `NODE-${Utils.randomInt(1, 10)}`,
            type,
            severity
        ]).draw(false).node();

        // Optional: Flash anim on new row
        $(rowNode).css('color', '#fff').animate({ color: '#8b949e' }, 1000);

        // Remove oldest if > 50 rows to prevent DOM heavy
        if (FeedTable.table.rows().count() > 50) {
            FeedTable.table.row(0).remove().draw(false);
        }
    }
};
