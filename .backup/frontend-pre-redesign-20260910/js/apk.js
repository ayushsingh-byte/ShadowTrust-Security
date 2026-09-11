const isLocalDev = window.location.hostname === '127.0.0.1'
    || window.location.hostname === 'localhost'
    || window.location.hostname === '0.0.0.0'
    || window.location.protocol === 'file:';

const mobsfServiceBase = isLocalDev
    ? 'http://127.0.0.1:5055'
    : `${window.location.origin}/mobsf-service`;

let serviceStatusCache = null;
const MAX_ROWS_PER_SECTION = 70;
const MAX_COLUMNS_PER_SECTION = 9;
const MAX_CELL_CHARS = 200;
const MAX_RAW_JSON_CHARS = 18000;
const MAX_CERT_CHARS = 6000;
const MAX_NESTED_KEYS_PER_ROW = 14;

function formatTimestamp(isoString) {
    if (!isoString || isoString === 'N/A') return 'N/A';
    const parsed = new Date(isoString);
    if (Number.isNaN(parsed.getTime())) return isoString;
    return parsed.toLocaleString();
}

function badgeForThreatLevel(score) {
    if (score >= 70) return 'badge-red';
    if (score >= 35) return 'badge-yellow';
    return 'badge-green';
}

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function setStatus(message, tone = 'muted') {
    const status = document.getElementById('mobsfStatus');
    if (!status) return;
    status.textContent = message;
    status.className = `text-${tone}`;
}

function firstValue(obj, keys, fallback = 'N/A') {
    if (!obj || typeof obj !== 'object') return fallback;
    for (const key of keys) {
        const value = obj[key];
        if (value !== undefined && value !== null && String(value).trim() !== '') {
            return value;
        }
    }
    return fallback;
}

function asInt(value, fallback = 0) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? Math.max(0, Math.trunc(parsed)) : fallback;
}

function listSize(value) {
    if (Array.isArray(value)) return value.length;
    if (value && typeof value === 'object') return Object.keys(value).length;
    return 0;
}

function exportedCount(collection) {
    if (Array.isArray(collection)) {
        let count = 0;
        collection.forEach((item) => {
            if (item && typeof item === 'object') {
                const exported = item.exported;
                if (exported === true || String(exported).toLowerCase() === 'true') {
                    count += 1;
                }
            }
        });
        return count;
    }
    return 0;
}

function renderLatestScan(report) {
    if (!report) return;

    const raw = report.raw_report || {};
    const dangerousPermissions = extractDangerousPermissions(raw, report.dangerous_permissions || []);

    const latestAppNameEl = document.getElementById('latestAppName');
    const latestThreatBadgeEl = document.getElementById('latestThreatBadge');
    const latestAnalysisDetailsEl = document.getElementById('latestAnalysisDetails');

    if (latestAppNameEl) latestAppNameEl.textContent = report.app_name || 'Unknown App';

    if (latestThreatBadgeEl) {
        latestThreatBadgeEl.textContent = `${report.threat_score || 0}/100`;
        latestThreatBadgeEl.className = `badge ${badgeForThreatLevel(report.threat_score || 0)}`;
    }

    if (latestAnalysisDetailsEl) {
        latestAnalysisDetailsEl.innerHTML = `
            <div>
                <div class="resource-row"><span>Package Name</span> <span class="text-mono text-cyan">${escapeHtml(report.package_name || 'N/A')}</span></div>
                <div class="resource-row"><span>Version</span> <span class="text-mono">${escapeHtml(report.version_name || 'N/A')}</span></div>
                <div class="resource-row"><span>SHA256</span> <span class="text-mono text-xs">${escapeHtml(report.file_hash_sha256 || 'N/A')}</span></div>
                <div class="resource-row"><span>Scan Time</span> <span class="text-mono">${escapeHtml(formatTimestamp(report.scan_time))}</span></div>
            </div>
            <div>
                <div class="resource-row"><span>Vulnerabilities</span> <span class="text-mono text-pink">${(report.findings || []).length} Detected</span></div>
                <div class="resource-row"><span>Permissions</span> <span class="text-mono text-purple">${(report.permissions || []).length} Requested</span></div>
                <div class="resource-row"><span>Dangerous</span> <span class="text-mono">${dangerousPermissions.length}</span></div>
                <div class="resource-row"><span>Threat Score</span> <span class="text-mono">${report.threat_score || 0}/100</span></div>
            </div>
        `;
    }
}

function extractDangerousPermissions(raw, fallback = []) {
    const permissions = raw?.permissions;
    if (permissions && typeof permissions === 'object' && !Array.isArray(permissions)) {
        const derived = Object.entries(permissions)
            .map(([name, meta]) => {
                const status = typeof meta === 'object' ? String(meta.status || '').toLowerCase() : '';
                const isDangerous = status.includes('danger') || status.includes('high');
                return {
                    name,
                    short_name: name.split('.').pop() || name,
                    status: typeof meta === 'object' ? meta.status || '' : '',
                    info: typeof meta === 'object' ? meta.info || meta.description || '' : '',
                    dangerous: isDangerous,
                };
            })
            .filter((item) => item.dangerous);
        if (derived.length > 0) return derived;
    }
    return Array.isArray(fallback) ? fallback : [];
}

function renderDangerousPermissions(permissions) {
    const container = document.getElementById('dangerousPermissionsList');
    if (!container) return;
    const items = Array.isArray(permissions) ? permissions : [];

    if (items.length === 0) {
        container.innerHTML = '<div class="text-xs" style="color:#22c55e; font-weight:700;">SAFE: No dangerous permissions detected</div>';
        return;
    }

    container.innerHTML = items.slice(0, 10).map((permission, index) => {
        const width = Math.max(25, 100 - (index * 12));
        return `
            <div class="text-xs" style="color:#fca5a5; font-weight:700;">${escapeHtml(permission.short_name || permission.name)}${permission.status ? ` (${escapeHtml(permission.status)})` : ''}</div>
            <div class="progress-bar"><div class="progress-fill" style="width:${width}%; background:${index === 0 ? '#ff0055' : '#ef4444'};"></div></div>
        `;
    }).join('');
}

function renderManifest(manifest, raw = {}) {
    const manifestBlock = document.getElementById('manifestViewer');
    if (!manifestBlock) return;

    if (manifest && manifest !== 'Manifest not available') {
        manifestBlock.textContent = manifest;
        return;
    }

    const manifestFindings = raw?.manifest_analysis?.manifest_findings;
    if (Array.isArray(manifestFindings) && manifestFindings.length > 0) {
        const lines = manifestFindings.slice(0, 30).map((item, index) => {
            const sev = String(item?.severity || 'info').toUpperCase();
            const title = item?.title || item?.name || item?.rule || 'Manifest finding';
            return `${index + 1}. [${sev}] ${title}`;
        });
        manifestBlock.textContent = `Manifest XML not exposed by report_json. Showing manifest findings:\n\n${lines.join('\n')}`;
        return;
    }

    manifestBlock.textContent = 'Manifest data not provided by this MobSF report.';
}

function renderFindings(findings) {
    const tbody = document.getElementById('vulnerabilityTableBody');
    if (!tbody) return;
    const rows = Array.isArray(findings) ? findings : [];

    if (rows.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" class="text-muted">No data yet</td></tr>';
        return;
    }

    const sevClass = (sev) => {
        const s = String(sev || '').toUpperCase();
        if (s === 'HIGH' || s === 'CRITICAL') return 'sev-high';
        if (s === 'MEDIUM' || s === 'WARNING') return 'sev-warning';
        return 'sev-info';
    };

    tbody.innerHTML = rows.map((finding) => `
        <tr>
            <td style="color:#fff; padding:12px; vertical-align:top;">${escapeHtml(finding.title)}</td>
            <td style="padding:12px;"><span class="sev-chip ${sevClass(finding.severity)}">${escapeHtml(finding.severity)}</span></td>
            <td class="text-muted" style="padding:12px; line-height:1.5;">${escapeHtml(finding.description || finding.source)}</td>
        </tr>
    `).join('');
}

function normalizeKeyLabel(key) {
    return String(key || '')
        .replace(/_/g, ' ')
        .replace(/\s+/g, ' ')
        .trim()
        .replace(/\b\w/g, (char) => char.toUpperCase());
}

function objectToScalarString(value) {
    if (value === null || value === undefined) return '';
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
        return String(value);
    }
    if (Array.isArray(value)) return value.slice(0, 25).map((item) => String(item)).join(', ');
    return JSON.stringify(value);
}

function clampText(value, maxLen) {
    const text = String(value ?? '');
    return text.length > maxLen ? `${text.slice(0, maxLen)} ...` : text;
}

function toRows(value, rowKeyName = 'name') {
    if (Array.isArray(value)) {
        return value.map((entry, index) => {
            if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
                return entry;
            }
            return { index: index + 1, value: objectToScalarString(entry) };
        });
    }

    if (value && typeof value === 'object') {
        const values = Object.values(value);
        const allObjectLike = values.length > 0 && values.every((entry) => entry && typeof entry === 'object' && !Array.isArray(entry));

        if (allObjectLike) {
            return Object.entries(value).map(([key, entry]) => ({ [rowKeyName]: key, ...entry }));
        }

        return Object.entries(value).map(([key, entry]) => ({ [rowKeyName]: key, value: objectToScalarString(entry) }));
    }

    if (value === null || value === undefined || value === '') return [];
    return [{ value: objectToScalarString(value) }];
}

function flattenRow(row) {
    const out = {};
    let nestedCount = 0;
    Object.entries(row || {}).forEach(([key, value]) => {
        if (value && typeof value === 'object' && !Array.isArray(value)) {
            Object.entries(value).forEach(([childKey, childValue]) => {
                if (nestedCount < MAX_NESTED_KEYS_PER_ROW) {
                    out[`${key}.${childKey}`] = clampText(objectToScalarString(childValue), MAX_CELL_CHARS);
                    nestedCount += 1;
                }
            });
        } else {
            out[key] = clampText(objectToScalarString(value), MAX_CELL_CHARS);
        }
    });
    return out;
}

function severityChip(value) {
    const normalized = String(value || '').toLowerCase();
    if (!normalized) return '';
    let klass = 'sev-info';
    if (normalized.includes('high') || normalized.includes('critical') || normalized.includes('danger')) klass = 'sev-high';
    else if (normalized.includes('warn') || normalized.includes('medium')) klass = 'sev-warning';
    else if (normalized.includes('low') || normalized.includes('normal') || normalized.includes('secure') || normalized.includes('info')) klass = 'sev-info';
    return `<span class="sev-chip ${klass}">${escapeHtml(value)}</span>`;
}

function renderCell(column, value) {
    if (value === null || value === undefined || value === '') return '<span class="text-muted">-</span>';
    const lowered = String(column).toLowerCase();
    if (['severity', 'status', 'risk', 'level'].includes(lowered)) {
        return severityChip(value);
    }
    return escapeHtml(clampText(value, MAX_CELL_CHARS));
}

function buildTableHtml(rows, preferredColumns = []) {
    const flatRows = rows.map(flattenRow);
    const discovered = [];
    flatRows.forEach((row) => {
        Object.keys(row).forEach((key) => {
            if (!discovered.includes(key)) discovered.push(key);
        });
    });

    const columnOrder = [];
    preferredColumns.forEach((key) => {
        if (discovered.includes(key)) columnOrder.push(key);
    });
    discovered.forEach((key) => {
        if (!columnOrder.includes(key)) columnOrder.push(key);
    });

    const safeColumns = columnOrder.slice(0, MAX_COLUMNS_PER_SECTION);

    if (safeColumns.length === 0) {
        return '<div class="mobsf-empty">No structured table data for this section.</div>';
    }

    const head = safeColumns.map((key) => `<th>${escapeHtml(normalizeKeyLabel(key))}</th>`).join('');
    const body = flatRows.map((row) => {
        const cells = safeColumns.map((col) => `<td>${renderCell(col, row[col])}</td>`).join('');
        return `<tr>${cells}</tr>`;
    }).join('');

    return `
        <div class="mobsf-table-wrap">
            <table class="mobsf-data-table">
                <thead><tr>${head}</tr></thead>
                <tbody>${body}</tbody>
            </table>
        </div>
    `;
}

function pickFirst(raw, keys) {
    for (const key of keys) {
        if (raw[key] !== undefined && raw[key] !== null) {
            return { key, value: raw[key] };
        }
    }
    return { key: null, value: null };
}

function renderMobSFBlocks(raw) {
    const container = document.getElementById('mobsfDynamicBlocks');
    if (!container) return;

    const sections = [
        { title: 'Application Permissions', keys: ['permissions'], rowKey: 'permission', columns: ['permission', 'status', 'info', 'description'] },
        { title: 'Android API', keys: ['android_api', 'android_apis'], rowKey: 'api', columns: ['api', 'files', 'file', 'description'] },
        { title: 'Browsable Activities', keys: ['browsable_activities'], rowKey: 'activity', columns: ['activity', 'intent', 'schemes', 'hosts', 'mime_types', 'path_patterns'] },
        { title: 'Certificate Analysis', keys: ['certificate_analysis'], rowKey: 'title', columns: ['title', 'severity', 'description'] },
        { title: 'Manifest Analysis', keys: ['manifest_analysis'], rowKey: 'issue', columns: ['issue', 'severity', 'description', 'options'] },
        { title: 'Code Analysis', keys: ['code_analysis'], rowKey: 'issue', columns: ['issue', 'severity', 'standards', 'description', 'files'] },
        { title: 'Crypto Analysis', keys: ['crypto_analysis'], rowKey: 'issue', columns: ['issue', 'severity', 'description', 'files'] },
        { title: 'Network Security', keys: ['network_security'], rowKey: 'issue', columns: ['issue', 'severity', 'description', 'files'] },
        { title: 'Binary Analysis', keys: ['binary_analysis', 'shared_library_binary_analysis'], rowKey: 'shared_object', columns: ['shared_object', 'nx', 'pie', 'stack_canary', 'relro', 'rpath', 'runpath', 'fortify', 'symbols_stripped'] },
        { title: 'Firebase Database Analysis', keys: ['firebase_database', 'firebase_database_analysis'], rowKey: 'title', columns: ['title', 'severity', 'description'] },
        { title: 'File Analysis', keys: ['file_analysis'], rowKey: 'issue', columns: ['issue', 'files'] },
        { title: 'Emails', keys: ['emails', 'email'], rowKey: 'email', columns: ['email', 'file'] },
        { title: 'Trackers', keys: ['trackers', 'trackers_data', 'tracker'], rowKey: 'tracker_name', columns: ['tracker_name', 'categories', 'url', 'name'] },
    ];

    const blocks = [];
    sections.forEach((section) => {
        const picked = pickFirst(raw, section.keys);
        if (!picked.key) return;

        const rows = toRows(picked.value, section.rowKey);
        if (rows.length === 0) return;

        const limitedRows = rows.slice(0, MAX_ROWS_PER_SECTION);
        const tableHtml = buildTableHtml(limitedRows, section.columns || []);
        const isOpenByDefault = blocks.length < 2 ? 'open' : '';
        blocks.push(`
            <div class="mobsf-analysis-block">
                <details ${isOpenByDefault}>
                    <summary class="mobsf-analysis-header">
                        <div class="mobsf-analysis-title">${escapeHtml(section.title)}</div>
                        <div class="mobsf-analysis-meta">${escapeHtml(String(rows.length))} entries${rows.length > limitedRows.length ? ` (showing ${limitedRows.length})` : ''}</div>
                    </summary>
                    ${tableHtml}
                </details>
            </div>
        `);
    });

    if (blocks.length === 0) {
        container.innerHTML = '<div class="mobsf-empty">MobSF returned no extended section data for this scan.</div>';
        return;
    }

    container.innerHTML = blocks.join('');
}

function renderDeepMobSF(report) {
    const raw = report?.raw_report || {};

    const appScore = firstValue(raw, ['security_score', 'securityScore', 'score'], 'N/A');
    const trackers = firstValue(raw, ['trackers_detection', 'trackers', 'trackers_count'], 'N/A');

    const fileName = firstValue(raw, ['file_name', 'fileName'], report?.app_name || 'N/A');
    const fileSize = firstValue(raw, ['size', 'file_size', 'apk_size'], 'N/A');
    const md5 = firstValue(raw, ['md5', 'file_hash', 'md5_hash'], 'N/A');
    const sha1 = firstValue(raw, ['sha1', 'sha1_hash'], 'N/A');
    const sha256 = firstValue(raw, ['sha256', 'file_hash_sha256'], report?.file_hash_sha256 || 'N/A');

    const appName = firstValue(raw, ['app_name', 'appName'], report?.app_name || 'N/A');
    const packageName = firstValue(raw, ['package_name', 'package', 'packageName'], report?.package_name || 'N/A');
    const mainActivity = firstValue(raw, ['main_activity', 'launcher_activity', 'mainActivity'], 'N/A');
    const targetSdk = firstValue(raw, ['target_sdk', 'targetSdkVersion', 'target_sdk_version'], 'N/A');
    const minSdk = firstValue(raw, ['min_sdk', 'minSdkVersion', 'min_sdk_version'], 'N/A');
    const maxSdk = firstValue(raw, ['max_sdk', 'maxSdkVersion', 'max_sdk_version'], 'N/A');
    const androidVersionName = firstValue(raw, ['version_name', 'android_version_name', 'versionName'], report?.version_name || 'N/A');
    const androidVersionCode = firstValue(raw, ['version_code', 'android_version_code', 'versionCode'], 'N/A');

    const infoGrid = document.getElementById('mobsfInfoGrid');
    if (infoGrid) {
        infoGrid.innerHTML = `
            <div class="mobsf-kv-card">
                <h4>APP SCORES</h4>
                <div class="mobsf-kv-row"><span>Security Score</span><span>${escapeHtml(String(appScore))}</span></div>
                <div class="mobsf-kv-row"><span>Trackers Detection</span><span>${escapeHtml(String(trackers))}</span></div>
                <div class="mobsf-kv-row"><span>Threat Score</span><span>${escapeHtml(String(report?.threat_score ?? 'N/A'))}/100</span></div>
            </div>
            <div class="mobsf-kv-card">
                <h4>FILE INFORMATION</h4>
                <div class="mobsf-kv-row"><span>File Name</span><span>${escapeHtml(String(fileName))}</span></div>
                <div class="mobsf-kv-row"><span>Size</span><span>${escapeHtml(String(fileSize))}</span></div>
                <div class="mobsf-kv-row"><span>MD5</span><span>${escapeHtml(String(md5))}</span></div>
                <div class="mobsf-kv-row"><span>SHA1</span><span>${escapeHtml(String(sha1))}</span></div>
                <div class="mobsf-kv-row"><span>SHA256</span><span>${escapeHtml(String(sha256))}</span></div>
            </div>
            <div class="mobsf-kv-card">
                <h4>APP INFORMATION</h4>
                <div class="mobsf-kv-row"><span>App Name</span><span>${escapeHtml(String(appName))}</span></div>
                <div class="mobsf-kv-row"><span>Package Name</span><span>${escapeHtml(String(packageName))}</span></div>
                <div class="mobsf-kv-row"><span>Main Activity</span><span>${escapeHtml(String(mainActivity))}</span></div>
                <div class="mobsf-kv-row"><span>Target SDK</span><span>${escapeHtml(String(targetSdk))}</span></div>
                <div class="mobsf-kv-row"><span>Min SDK</span><span>${escapeHtml(String(minSdk))}</span></div>
                <div class="mobsf-kv-row"><span>Max SDK</span><span>${escapeHtml(String(maxSdk))}</span></div>
                <div class="mobsf-kv-row"><span>Android Ver Name</span><span>${escapeHtml(String(androidVersionName))}</span></div>
                <div class="mobsf-kv-row"><span>Android Ver Code</span><span>${escapeHtml(String(androidVersionCode))}</span></div>
            </div>
        `;
    }

    const activities = raw.activities || raw.activity || [];
    const services = raw.services || raw.service || [];
    const receivers = raw.receivers || raw.receiver || [];
    const providers = raw.providers || raw.provider || [];

    const totalActivities = asInt(firstValue(raw, ['activities_count', 'activity_count', 'total_activities'], listSize(activities)));
    const totalServices = asInt(firstValue(raw, ['services_count', 'service_count', 'total_services'], listSize(services)));
    const totalReceivers = asInt(firstValue(raw, ['receivers_count', 'receiver_count', 'total_receivers'], listSize(receivers)));
    const totalProviders = asInt(firstValue(raw, ['providers_count', 'provider_count', 'total_providers'], listSize(providers)));

    const exportedActivities = asInt(firstValue(raw, ['exported_activities_count', 'exported_activity_count'], exportedCount(activities)));
    const exportedServices = asInt(firstValue(raw, ['exported_services_count', 'exported_service_count'], exportedCount(services)));
    const exportedReceivers = asInt(firstValue(raw, ['exported_receivers_count', 'exported_receiver_count'], exportedCount(receivers)));
    const exportedProviders = asInt(firstValue(raw, ['exported_providers_count', 'exported_provider_count'], exportedCount(providers)));

    const componentGrid = document.getElementById('componentCounts');
    if (componentGrid) {
        componentGrid.innerHTML = `
            <div class="component-tile"><span class="num">${exportedActivities} / ${totalActivities}</span><span class="lbl">Exported Activities</span></div>
            <div class="component-tile"><span class="num">${exportedServices} / ${totalServices}</span><span class="lbl">Exported Services</span></div>
            <div class="component-tile"><span class="num">${exportedReceivers} / ${totalReceivers}</span><span class="lbl">Exported Receivers</span></div>
            <div class="component-tile"><span class="num">${exportedProviders} / ${totalProviders}</span><span class="lbl">Exported Providers</span></div>
        `;
    }

    const certBlock = document.getElementById('signerCertBlock');
    if (certBlock) {
        const certData = firstValue(raw, ['certificate_analysis', 'certificate', 'signer_certificate'], null);
        const certText = certData && certData !== 'N/A'
            ? (typeof certData === 'string' ? certData : JSON.stringify(certData, null, 2))
            : 'No certificate data returned by MobSF for this APK.';
        certBlock.textContent = clampText(certText, MAX_CERT_CHARS);
    }

    const rawViewer = document.getElementById('rawReportViewer');
    if (rawViewer) {
        const rawText = Object.keys(raw).length > 0
            ? JSON.stringify(raw, null, 2)
            : 'No report data yet';
        rawViewer.textContent = clampText(rawText, MAX_RAW_JSON_CHARS);
    }

    renderMobSFBlocks(raw);
}

function renderHistory(history) {
    const tbody = document.querySelector('#apkTable tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (!Array.isArray(history) || history.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td style="color:#fff;">No scans yet</td>
                <td class="text-mono" style="color:#666;">-</td>
                <td class="text-mono">-</td>
                <td style="font-weight:bold; color:#fff;">-</td>
                <td class="text-muted">Upload an APK to start MobSF analysis</td>
                <td><span class="badge">N/A</span></td>
            </tr>
        `;
    } else {
        history.forEach((item) => {
            const score = Number(item.score || 0);
            const row = `
                <tr>
                    <td style="color:#fff;">${escapeHtml(item.app_name || item.original_filename || 'Unknown App')}</td>
                    <td class="text-mono" style="color:#666;">${escapeHtml(item.package_name || 'unknown')}</td>
                    <td class="text-mono">${escapeHtml(item.version_name || 'N/A')}</td>
                    <td style="font-weight:bold; color:#fff;">${score}/100</td>
                    <td class="text-muted">Scanned ${escapeHtml(formatTimestamp(item.timestamp))}</td>
                    <td><span class="badge ${badgeForThreatLevel(score)}">${score >= 70 ? 'HIGH' : score >= 35 ? 'MEDIUM' : 'LOW'}</span></td>
                </tr>
            `;
            tbody.insertAdjacentHTML('beforeend', row);
        });
    }

    if ($.fn.DataTable.isDataTable('#apkTable')) {
        $('#apkTable').DataTable().destroy();
    }

    $('#apkTable').DataTable({
        pageLength: 5,
        ordering: true,
        lengthChange: false,
    });
}

async function fetchJson(url, options = {}) {
    const response = await fetch(url, options);
    const data = await response.json().catch(() => ({}));
    if (!response.ok && response.status !== 202) {
        throw new Error(data.detail || 'Request failed');
    }
    return { status: response.status, data };
}

async function loadStatus() {
    try {
        const { data } = await fetchJson(`${mobsfServiceBase}/status`);
        serviceStatusCache = data;
        const launchLink = document.getElementById('openMobSFBt');
        const docsLink = document.getElementById('mobsfDocsLink');
        if (launchLink && data.api_docs_url) {
            launchLink.dataset.url = data.api_docs_url;
        }
        if (docsLink && data.api_docs_url) {
            docsLink.href = data.api_docs_url;
        }
        if (data.api_key_configured) {
            setStatus(`MobSF ready at ${data.mobsf_url}`, 'green');
        } else {
            setStatus(`MobSF ready at ${data.mobsf_url}. Paste the API key into backend/mobsf_service/config.py`, 'yellow');
        }
        renderHistory(data.history || []);
    } catch (error) {
        serviceStatusCache = null;
        setStatus(error.message, 'pink');
    }
}

async function uploadApk(file) {
    const formData = new FormData();
    formData.append('file', file);
    const { data } = await fetchJson(`${mobsfServiceBase}/upload-apk`, {
        method: 'POST',
        body: formData,
    });
    return data;
}

async function startScan(hash) {
    const { data } = await fetchJson(`${mobsfServiceBase}/start-scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hash }),
    });
    return data;
}

async function pollReport(hash, attempt = 0) {
    const { status, data } = await fetchJson(`${mobsfServiceBase}/report/${encodeURIComponent(hash)}`);
    if (status === 202 && attempt < 19) {
        await new Promise((resolve) => window.setTimeout(resolve, 3000));
        return pollReport(hash, attempt + 1);
    }
    return data;
}

function applyReport(report) {
    const raw = report.raw_report || {};
    const dangerousPermissions = extractDangerousPermissions(raw, report.dangerous_permissions || []);
    renderLatestScan(report);
    renderDangerousPermissions(dangerousPermissions);
    renderManifest(report.manifest || 'Manifest not available', raw);
    renderFindings(report.findings || []);
    renderDeepMobSF(report);
}

async function refreshHistory() {
    try {
        const { data } = await fetchJson(`${mobsfServiceBase}/history`);
        renderHistory(data.history || []);
    } catch (error) {
        console.error('Failed to refresh APK history:', error);
    }
}

function bindActions() {
    const scanButton = document.getElementById('startScanBtn');
    const fileInput = document.getElementById('apkFileInput');
    const openButton = document.getElementById('openMobSFBt');

    if (openButton) {
        openButton.addEventListener('click', () => {
            const targetUrl = openButton.dataset.url;
            if (targetUrl) {
                window.open(targetUrl, '_blank', 'noopener,noreferrer');
            }
        });
    }

    if (scanButton && fileInput) {
        scanButton.addEventListener('click', async () => {
            const [file] = fileInput.files;
            if (!file) {
                setStatus('Choose an APK file first.', 'yellow');
                return;
            }

            try {
                scanButton.disabled = true;
                setStatus('Uploading APK to MobSF...', 'cyan');
                const upload = await uploadApk(file);
                setStatus(`Upload complete. Starting scan for ${upload.hash}...`, 'cyan');
                await startScan(upload.hash);
                setStatus('Scan submitted. Waiting for report...', 'cyan');
                const report = await pollReport(upload.hash);
                applyReport(report);
                await refreshHistory();
                setStatus(`Analysis complete for ${report.app_name}.`, 'green');
            } catch (error) {
                console.error('APK scan failed:', error);
                setStatus(`Scan failed: ${error.message}`, 'pink');
            } finally {
                scanButton.disabled = false;
            }
        });
    }
}

window.addEventListener('DOMContentLoaded', async () => {
    bindActions();
    await loadStatus();
});
