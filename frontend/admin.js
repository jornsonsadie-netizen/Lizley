/**
 * AI Proxy - Admin Dashboard JavaScript
 * Handles admin authentication, configuration, key management, IP banning,
 * request logs, and key analytics
 */

// Constants
const ADMIN_PASSWORD_KEY = 'ai_proxy_admin_password';
const REFRESH_INTERVAL = 3000; // 3 seconds

// State
let adminPassword = null;
let refreshInterval = null;
let consoleMessages = [];
const MAX_CONSOLE_MESSAGES = 50;

// Render Cache (Prevents jitter/scroll resets on auto-refresh)
let lastKeysJson = '';
let lastLogsJson = '';
let lastTopJson = '';
let lastBannedJson = '';

// DOM Elements
const passwordModal = document.getElementById('password-modal');
const analyticsModal = document.getElementById('analytics-modal');
const adminContent = document.getElementById('admin-content');
const passwordForm = document.getElementById('password-form');
const passwordError = document.getElementById('password-error');
const adminStatus = document.getElementById('admin-status');
const consoleLog = document.getElementById('console-log');

// Config form elements
const configForm = document.getElementById('config-form');
const maxContextInput = document.getElementById('max-context');
const maxOutputTokensInput = document.getElementById('max-output-tokens');

// Keys table elements
const keysTable = document.getElementById('keys-table');
const keysTbody = document.getElementById('keys-tbody');
const noKeysMessage = document.getElementById('no-keys-message');
const keyCount = document.getElementById('key-count');

// Banned IPs elements
const banIpForm = document.getElementById('ban-ip-form');
const banIpInput = document.getElementById('ban-ip-input');
const banReasonInput = document.getElementById('ban-reason-input');
const bannedTbody = document.getElementById('banned-tbody');
const noBannedMessage = document.getElementById('no-banned-message');

// Request logs elements
const requestLogsEl = document.getElementById('request-logs');
const topRequestsEl = document.getElementById('top-requests');
const analyticsContent = document.getElementById('analytics-content');

/**
 * Initialize the admin dashboard
 */
function init() {
    const storedPassword = sessionStorage.getItem(ADMIN_PASSWORD_KEY);

    if (storedPassword) {
        adminPassword = storedPassword;
        verifyAndLoadDashboard();
    } else {
        showPasswordModal();
    }

    // Start UTC time update
    updateUtcTime();
    setInterval(updateUtcTime, 1000);

}

/**
 * Update UTC time display
 */
function updateUtcTime() {
    const utcTimeEl = document.getElementById('utc-time');
    if (utcTimeEl) {
        const now = new Date();
        utcTimeEl.textContent = now.toUTCString().replace('GMT', 'UTC');
    }
}

/**
 * Add message to console log
 */
function logToConsole(message, type = 'info') {
    const timestamp = new Date().toLocaleTimeString();
    consoleMessages.unshift({ timestamp, message, type });

    // Keep only last N messages
    if (consoleMessages.length > MAX_CONSOLE_MESSAGES) {
        consoleMessages = consoleMessages.slice(0, MAX_CONSOLE_MESSAGES);
    }

    renderConsole();
}

/**
 * Render console log
 */
function renderConsole() {
    if (!consoleLog) return;

    consoleLog.innerHTML = consoleMessages.map(msg => `
        <div class="console-entry ${msg.type}">
            <span class="timestamp">[${msg.timestamp}]</span>
            ${escapeHtml(msg.message)}
        </div>
    `).join('') || '<div class="console-entry info">Waiting for activity...</div>';
}

/**
 * Show the password modal
 */
function showPasswordModal() {
    passwordModal.classList.add('active');
    passwordModal.classList.remove('hidden');
    adminContent.classList.add('hidden');
    document.getElementById('admin-password').focus();
}

/**
 * Hide the password modal and show dashboard
 */
function showDashboard() {
    passwordModal.classList.remove('active');
    passwordModal.classList.add('hidden');
    adminContent.classList.remove('hidden');
}

/**
 * Handle password form submission
 */
async function handlePasswordSubmit(event) {
    event.preventDefault();

    const passwordInput = document.getElementById('admin-password');
    const password = passwordInput.value;

    if (!password) {
        showPasswordError('Please enter a password');
        return;
    }

    adminPassword = password;
    const isValid = await verifyPassword();

    if (isValid) {
        sessionStorage.setItem(ADMIN_PASSWORD_KEY, password);
        hidePasswordError();
        showDashboard();
        loadAllData();
        startAutoRefresh();
        logToConsole('Admin authenticated successfully', 'success');
    } else {
        showPasswordError('Invalid password');
        adminPassword = null;
    }
}

/**
 * Verify password by making a test request
 */
async function verifyPassword() {
    try {
        const response = await fetch('/admin/config', {
            headers: { 'X-Admin-Password': adminPassword }
        });
        return response.ok;
    } catch (error) {
        logToConsole(`Auth error: ${error.message}`, 'error');
        return false;
    }
}

/**
 * Verify stored password and load dashboard
 */
async function verifyAndLoadDashboard() {
    const isValid = await verifyPassword();

    if (isValid) {
        showDashboard();
        loadAllData();
        startAutoRefresh();
        logToConsole('Session restored', 'info');
    } else {
        sessionStorage.removeItem(ADMIN_PASSWORD_KEY);
        adminPassword = null;
        showPasswordModal();
    }
}

/**
 * Show password error message
 */
function showPasswordError(message) {
    passwordError.textContent = message;
    passwordError.classList.remove('hidden');
}

/**
 * Hide password error message
 */
function hidePasswordError() {
    passwordError.classList.add('hidden');
}

/**
 * Logout
 */
function logout() {
    sessionStorage.removeItem(ADMIN_PASSWORD_KEY);
    adminPassword = null;
    stopAutoRefresh();
    showPasswordModal();
    document.getElementById('admin-password').value = '';
    logToConsole('Logged out', 'info');
}

/**
 * Start auto-refresh (every 3 seconds)
 */
function startAutoRefresh() {
    stopAutoRefresh();
    refreshInterval = setInterval(() => {
        loadKeys(true);
        loadBannedIps(true);
        loadRequestLogs(true);
        loadTopRequests(true);
    }, REFRESH_INTERVAL);
}

/**
 * Stop auto-refresh
 */
function stopAutoRefresh() {
    if (refreshInterval) {
        clearInterval(refreshInterval);
        refreshInterval = null;
    }
}

/**
 * Load all dashboard data
 */
async function loadAllData() {
    await Promise.all([
        loadConfig(),
        loadKeys(),
        loadBannedIps(),
        loadRequestLogs(),
        loadTopRequests(),
        loadModels(),
    ]);
}

/**
 * Make authenticated admin request
 */
async function adminFetch(url, options = {}) {
    const headers = {
        'X-Admin-Password': adminPassword,
        'Cache-Control': 'no-cache',
        ...options.headers
    };

    // Auto-add Content-Type for JSON bodies
    if (options.body && (!headers['Content-Type'] && !headers['content-type'])) {
        headers['Content-Type'] = 'application/json';
    }

    try {
        const response = await fetch(url, {
            ...options,
            headers,
            cache: 'no-store'  // Prevent browser caching
        });
        console.log(`[AdminFetch] ${options.method || 'GET'} ${url} -> ${response.status}`);
        return response;
    } catch (error) {
        console.error(`[AdminFetch] ${options.method || 'GET'} ${url} -> Error:`, error);
        throw error;
    }
}


// ===================================
// Configuration Management
// ===================================

function renderProviders(providers) {
    const list = document.getElementById('providers-list');
    if (!list) return;
    list.innerHTML = '';
    providers.forEach((p, i) => {
        const isPrimary = i === 0;
        const row = document.createElement('div');
        row.className = 'provider-row';
        row.dataset.index = i;
        row.innerHTML = `
            <span class="provider-badge ${isPrimary ? 'primary' : 'fallback'}">${isPrimary ? 'Primary' : `#${i + 1}`}</span>
            <div class="provider-url-input">
                <input type="url" placeholder="https://api.example.com/v1" value="${escapeHtml(p.url || '')}" data-field="url" ${isPrimary ? 'required' : ''}>
            </div>
            <div class="provider-key-input">
                <input type="password" placeholder="${p.keyMasked || 'API Key'}" value="${escapeHtml(p.key || '')}" data-field="key">
            </div>
            ${!isPrimary ? `<button type="button" class="btn btn-danger btn-sm provider-delete-btn" onclick="removeProvider(${i})" title="Remove provider">✕</button>` : '<span style="width:2rem;flex-shrink:0"></span>'}
        `;
        list.appendChild(row);
    });
}

function getProvidersFromDOM() {
    const rows = document.querySelectorAll('.provider-row');
    return Array.from(rows).map(row => ({
        url: row.querySelector('[data-field="url"]').value.trim(),
        key: row.querySelector('[data-field="key"]').value.trim(),
    }));
}

let _providers = [{ url: '', key: '', keyMasked: 'sk-...' }];

function addProvider() {
    _providers = getProvidersFromDOM().map((p, i) => ({ ...p, keyMasked: _providers[i]?.keyMasked || 'sk-...' }));
    _providers.push({ url: '', key: '', keyMasked: 'sk-...' });
    renderProviders(_providers);
}

function removeProvider(index) {
    _providers = getProvidersFromDOM().map((p, i) => ({ ...p, keyMasked: _providers[i]?.keyMasked || 'sk-...' }));
    if (_providers.length <= 1) return;
    _providers.splice(index, 1);
    renderProviders(_providers);
}

async function loadConfig() {
    try {
        const response = await adminFetch('/admin/config');

        if (response.ok) {
            const data = await response.json();

            // Build provider list from providers array returned by backend
            if (data.providers && data.providers.length > 0) {
                _providers = data.providers.map(p => ({
                    url: p.url || '',
                    key: '',
                    keyMasked: p.key_masked || 'sk-...',
                }));
            } else {
                _providers = [{ url: data.target_api_url || '', key: '', keyMasked: data.target_api_key_masked || 'sk-...' }];
            }
            renderProviders(_providers);

            maxContextInput.value = data.max_context || 128000;
            if (maxOutputTokensInput) maxOutputTokensInput.value = data.max_output_tokens ?? 4096;
            const maxKeysEl = document.getElementById('max-keys-per-ip');
            if (maxKeysEl) maxKeysEl.textContent = data.max_keys_per_ip ?? '—';
        } else if (response.status === 401) {
            logout();
        } else {
            logToConsole('Failed to load configuration', 'error');
        }
    } catch (error) {
        logToConsole(`Config error: ${error.message}`, 'error');
    }
}

async function saveConfig(event) {
    event.preventDefault();

    const domProviders = getProvidersFromDOM();
    if (!domProviders[0]?.url) {
        showAdminStatus('Primary provider URL is required', 'error');
        return;
    }

    // Merge DOM values with cached masked keys (keep existing key if field left blank)
    const providers = domProviders.map((p, i) => {
        const entry = { url: p.url };
        if (p.key) entry.key = p.key;
        // If no key entered, send empty string — backend will keep existing for primary
        else entry.key = '';
        return entry;
    });

    const maxContext = parseInt(maxContextInput.value, 10);
    const maxOutputTokens = maxOutputTokensInput ? parseInt(maxOutputTokensInput.value, 10) : 4096;

    const payload = {
        providers,
        max_context: maxContext,
        max_output_tokens: Math.max(1, Math.min(128000, maxOutputTokens)),
    };

    try {
        const response = await adminFetch('/admin/config', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (response.ok) {
            logToConsole('Configuration saved', 'success');
            showAdminStatus('Configuration saved successfully', 'success');
            await loadConfig();
        } else if (response.status === 401) {
            logout();
        } else {
            const data = await response.json().catch(() => ({}));
            logToConsole(`Config save failed: ${data.detail || data.error || 'Unknown error'}`, 'error');
            showAdminStatus(data.detail || data.error || 'Failed to save configuration', 'error');
        }
    } catch (error) {
        logToConsole(`Config save error: ${error.message}`, 'error');
        showAdminStatus('Network error saving configuration', 'error');
    }
}

// ===================================
// Request Logs
// ===================================

async function loadRequestLogs(silent = false) {
    try {
        const response = await adminFetch('/admin/request-logs?limit=40');

        if (response.ok) {
            const logs = await response.json();

            // Optimization: Only update DOM if logs changed
            const logsJson = JSON.stringify(logs);
            if (lastLogsJson === logsJson) return;
            lastLogsJson = logsJson;

            displayRequestLogs(logs);
        } else if (response.status === 401) {
            logout();
        } else if (!silent) {
            logToConsole('Failed to load request logs', 'error');
        }
    } catch (error) {
        if (!silent) {
            logToConsole(`Request logs error: ${error.message}`, 'error');
        }
    }
}

function displayRequestLogs(logs) {
    if (!requestLogsEl) return;

    if (!logs || logs.length === 0) {
        requestLogsEl.innerHTML = '<div class="loading-cell">No requests yet</div>';
        return;
    }

    // Filter out "models" requests (these are just model list fetches, not actual API calls)
    const filteredLogs = logs.filter(log => log.model !== 'models');

    if (filteredLogs.length === 0) {
        requestLogsEl.innerHTML = '<div class="loading-cell">No requests yet</div>';
        return;
    }

    // Update count if element exists
    const countEl = document.getElementById('request-count');
    if (countEl) {
        countEl.textContent = `${filteredLogs.length} recent`;
    }

    requestLogsEl.innerHTML = filteredLogs.map(log => `
        <div class="log-entry ${log.success ? 'success' : 'error'}">
            <div class="log-header">
                <span class="log-model">${escapeHtml(log.model)}</span>
                <span class="log-time">${formatTime(log.request_time)}</span>
            </div>
            <div class="log-details">
                <span class="log-key">${escapeHtml(log.key_prefix)}</span>
                <span class="log-tokens">↓ ${formatNumber(log.input_tokens)} · ↑ ${formatNumber(log.output_tokens)} · Σ ${formatNumber(log.total_tokens)}</span>
            </div>
            ${log.error_message ? `<div class="log-error">${escapeHtml(log.error_message)}</div>` : ''}
        </div>
    `).join('');
}

async function loadTopRequests(silent = false) {
    try {
        const response = await adminFetch('/admin/top-requests?limit=3');

        if (response.ok) {
            const logs = await response.json();

            // Optimization: Only update DOM if top requests changed
            const topJson = JSON.stringify(logs);
            if (lastTopJson === topJson) return;
            lastTopJson = topJson;

            displayTopRequests(logs);
        } else if (response.status === 401) {
            logout();
        } else if (!silent) {
            logToConsole('Failed to load top requests', 'error');
        }
    } catch (error) {
        if (!silent) {
            logToConsole(`Top requests error: ${error.message}`, 'error');
        }
    }
}

function displayTopRequests(logs) {
    if (!topRequestsEl) return;

    if (!logs || logs.length === 0) {
        topRequestsEl.innerHTML = '<div class="loading-cell">No requests yet</div>';
        return;
    }

    // Filter out "models" requests
    const filteredLogs = logs.filter(log => log.model !== 'models');

    if (filteredLogs.length === 0) {
        topRequestsEl.innerHTML = '<div class="loading-cell">No requests yet</div>';
        return;
    }

    topRequestsEl.innerHTML = filteredLogs.map((log, i) => `
        <div class="log-entry success">
            <div class="log-header">
                <span class="log-model">#${i + 1} · ${escapeHtml(log.model)}</span>
                <span class="log-time">${formatTime(log.request_time)}</span>
            </div>
            <div class="log-details">
                <span class="log-key">${escapeHtml(log.key_prefix)}</span>
                <span class="log-tokens">✧ ${formatNumber(log.total_tokens)} tokens</span>
            </div>
        </div>
    `).join('');
}

// ===================================
// API Keys Management
// ===================================

/**
 * Enable an API key by its full string (Customer Enabler tool)
 */
async function enableKeyByFull(event) {
    if (event) event.preventDefault();
    
    const form = document.getElementById('enabler-form');
    const input = document.getElementById('enabler-key-input');
    const statusEl = document.getElementById('enabler-status');
    const fullKey = input.value.trim();
    
    if (!fullKey) return;
    
    if (!fullKey.startsWith('sk-')) {
        showStatus('enabler-status', 'Key must start with "sk-"', 'error');
        return;
    }
    
    try {
        logToConsole(`Enabling customer key: ${fullKey.substring(0, 10)}...`, 'info');
        
        const response = await adminFetch('/admin/keys/enable-by-full-key', {
            method: 'POST',
            body: JSON.stringify({ full_key: fullKey })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showStatus('enabler-status', data.message, 'success');
            logToConsole(data.message, 'success');
            input.value = ''; // Clear form
            
            // Refresh keys table to show changes
            loadKeys(true);
        } else {
            showStatus('enabler-status', data.detail || 'Failed to enable key', 'error');
            logToConsole(`Enable error: ${data.detail}`, 'error');
        }
    } catch (error) {
        showStatus('enabler-status', `Error: ${error.message}`, 'error');
        logToConsole(`Enable key JS error: ${error.message}`, 'error');
    }
}

async function loadKeys(silent = false) {
    if (!silent) {
        keysTbody.innerHTML = '<tr><td colspan="7" class="loading-cell">Loading...</td></tr>';
    }
    noKeysMessage.classList.add('hidden');

    try {
        const response = await adminFetch('/admin/keys');

        if (response.ok) {
            const keys = await response.json();

            // Optimization: Only update DOM if keys changed
            const keysJson = JSON.stringify(keys);
            if (lastKeysJson === keysJson) {
                // Still update counts if they are visible
                if (keyCount) keyCount.textContent = `(${keys.length} keys)`;
                return;
            }
            lastKeysJson = keysJson;

            displayKeys(keys);
            if (keyCount) {
                keyCount.textContent = `(${keys.length} keys)`;
            }
        } else if (response.status === 401) {
            logout();
        } else if (!silent) {
            logToConsole('Failed to load API keys', 'error');
            keysTbody.innerHTML = '<tr><td colspan="7" class="loading-cell">Error loading keys</td></tr>';
        }
    } catch (error) {
        if (!silent) {
            logToConsole(`Keys error: ${error.message}`, 'error');
            keysTbody.innerHTML = '<tr><td colspan="7" class="loading-cell">Error loading keys</td></tr>';
        }
    }
}

function displayKeys(keys) {
    if (!keys || keys.length === 0) {
        keysTbody.innerHTML = '';
        noKeysMessage.classList.remove('hidden');
        return;
    }

    noKeysMessage.classList.add('hidden');

    if (keys.length === 0) {
        keysTbody.innerHTML = '';
        noKeysMessage.classList.remove('hidden');
    } else {
        keysTbody.innerHTML = keys.map(key => `
        <tr data-key-id="${key.id}" class="clickable" onclick="showKeyAnalytics(${key.id})">
            <td class="key-prefix">${escapeHtml(key.key_prefix)}</td>
            <td class="discord-email">
                ${escapeHtml(key.discord_email || key.ip_address || 'Unknown')}

            </td>
            <td>
                <span class="status-badge ${key.enabled ? 'enabled' : 'disabled'}">
                    ${key.enabled ? 'Enabled' : 'Disabled'}
                </span>
            </td>
            <td>
                <span class="status-badge ${key.bypass_ip_ban ? 'enabled' : 'disabled'}">
                    ${key.bypass_ip_ban ? 'Bypass' : 'No'}
                </span>
                <div class="action-buttons" onclick="event.stopPropagation()" style="margin-top: 4px;">
                    <button onclick="setBypassIp(${key.id}, ${!key.bypass_ip_ban})"
                            class="btn btn-ghost btn-sm" title="${key.bypass_ip_ban ? 'Disable IP bypass' : 'Allow this key from banned IPs'}">
                        ${key.bypass_ip_ban ? 'Disable bypass' : 'Enable bypass'}
                    </button>
                </div>
            </td>
            <td>${key.current_rpm}/10</td>
            <td title="Tokens today / 150K limit">${key.tokens_used_today != null ? key.tokens_used_today.toLocaleString() : key.current_rpd}/${(150000).toLocaleString()}</td>
            <td>
                <div class="action-buttons" onclick="event.stopPropagation()">
                    <button onclick="toggleKey(${key.id}, ${key.enabled})"
                            class="btn ${key.enabled ? 'btn-warning' : 'btn-ghost'} btn-sm">
                        ${key.enabled ? 'Disable' : 'Enable'}
                    </button>
                    <button onclick="deleteKey(${key.id})" class="btn btn-danger btn-sm">
                        Delete
                    </button>
                </div>
            </td>
        </tr>
    `).join('');
    }
}

/**
 * Display pending applications as prominent cards
 */
async function setBypassIp(keyId, bypass) {
    try {
        const response = await adminFetch(`/admin/keys/${keyId}/bypass-ip`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ bypass })
        });
        if (response.ok) {
            logToConsole(`IP bypass ${bypass ? 'enabled' : 'disabled'} for key`, 'success');
            showAdminStatus(bypass ? 'Key can now be used from banned IPs' : 'IP bypass disabled for this key', 'success');
            await loadKeys();
        } else if (response.status === 401) {
            logout();
        } else if (response.status === 404) {
            logToConsole('Key not found', 'error');
            await loadKeys();
        } else {
            logToConsole('Failed to set IP bypass', 'error');
        }
    } catch (error) {
        logToConsole(`Set bypass error: ${error.message}`, 'error');
    }
}

async function toggleKey(keyId, currentlyEnabled) {
    try {
        const response = await adminFetch(`/admin/keys/${keyId}/toggle`, { method: 'PUT' });

        if (response.ok) {
            logToConsole(`Key ${currentlyEnabled ? 'disabled' : 'enabled'}`, 'success');
            showAdminStatus(`Key ${currentlyEnabled ? 'disabled' : 'enabled'} successfully`, 'success');
            await loadKeys();
        } else if (response.status === 401) {
            logout();
        } else if (response.status === 404) {
            logToConsole('Key not found', 'error');
            await loadKeys();
        } else {
            logToConsole('Failed to toggle key', 'error');
        }
    } catch (error) {
        logToConsole(`Toggle key error: ${error.message}`, 'error');
    }
}

async function deleteKey(keyId) {
    if (!confirm('Are you sure you want to delete this API key?')) return;

    try {
        const response = await adminFetch(`/admin/keys/${keyId}`, { method: 'DELETE' });

        if (response.ok) {
            logToConsole('Key deleted', 'success');
            showAdminStatus('Key deleted successfully', 'success');
            await loadKeys();
        } else if (response.status === 401) {
            logout();
        } else if (response.status === 404) {
            logToConsole('Key not found', 'error');
            await loadKeys();
        } else {
            logToConsole('Failed to delete key', 'error');
        }
    } catch (error) {
        logToConsole(`Delete key error: ${error.message}`, 'error');
    }
}


// ===================================
// Key Analytics Modal
// ===================================

async function showKeyAnalytics(keyId) {
    const modal = document.getElementById('analytics-modal');
    const content = document.getElementById('analytics-content');

    modal.classList.add('active');
    modal.classList.remove('hidden');
    content.innerHTML = '<div class="loading-cell">Loading analytics...</div>';

    try {
        const response = await adminFetch(`/admin/keys/${keyId}/analytics`);

        if (response.ok) {
            const data = await response.json();
            displayKeyAnalytics(data);
            logToConsole(`Loaded analytics for key ${data.key_prefix}`, 'info');
        } else if (response.status === 401) {
            closeAnalyticsModal();
            logout();
        } else if (response.status === 404) {
            content.innerHTML = '<div class="loading-cell">Key not found</div>';
        } else {
            content.innerHTML = '<div class="loading-cell">Failed to load analytics</div>';
        }
    } catch (error) {
        logToConsole(`Analytics error: ${error.message}`, 'error');
        content.innerHTML = '<div class="loading-cell">Error loading analytics</div>';
    }
}

function displayKeyAnalytics(data) {
    const content = document.getElementById('analytics-content');

    const successRate = data.total_requests > 0
        ? Math.round((data.successful_requests / data.total_requests) * 100)
        : 0;

    content.innerHTML = `
        <!-- Key Info Block -->
        <div class="analytics-block key-info-block">
            <div class="block-label">API Key</div>
            <div class="key-info-content">
                <div class="key-mono">${escapeHtml(data.key_prefix)}...</div>
                <div class="key-ip">${escapeHtml(data.ip_address)}</div>
            </div>
        </div>
        
        <!-- Stats Row -->
        <div class="analytics-row">
            <div class="analytics-block stat-block">
                <div class="block-label">Total Tokens</div>
                <div class="stat-big">${formatNumber(data.total_tokens)}</div>
            </div>
            <div class="analytics-block stat-block">
                <div class="block-label">Requests</div>
                <div class="stat-big">${data.total_requests}</div>
            </div>
            <div class="analytics-block stat-block ${successRate >= 80 ? 'stat-success' : successRate >= 50 ? 'stat-warning' : 'stat-danger'}">
                <div class="block-label">Success Rate</div>
                <div class="stat-big">${successRate}%</div>
            </div>
        </div>
        
        <!-- Token Breakdown Row -->
        <div class="analytics-row">
            <div class="analytics-block token-block">
                <div class="block-label">↓ Input Tokens</div>
                <div class="stat-medium">${formatNumber(data.total_input_tokens)}</div>
            </div>
            <div class="analytics-block token-block">
                <div class="block-label">↑ Output Tokens</div>
                <div class="stat-medium">${formatNumber(data.total_output_tokens)}</div>
            </div>
        </div>
        
        <!-- Model Block -->
        ${data.most_used_model ? `
        <div class="analytics-block model-block">
            <div class="block-label">Most Used Model</div>
            <div class="model-info">
                <span class="model-name">${escapeHtml(data.most_used_model)}</span>
                <span class="model-badge">${data.model_usage_count} requests</span>
            </div>
        </div>
        ` : ''}
        
        <!-- Recent Requests Block -->
        <div class="analytics-block requests-block">
            <div class="block-label">Recent Requests</div>
            <div class="requests-list">
                ${data.recent_requests.length > 0 ? data.recent_requests.map(req => `
                    <div class="request-item ${req.success ? '' : 'request-failed'}">
                        <div class="request-left">
                            <div class="request-model">${escapeHtml(req.model)}</div>
                            <div class="request-time">${formatTime(req.request_time)}</div>
                        </div>
                        <div class="request-right">
                            ${req.total_tokens > 0 ? `<div class="request-tokens">${formatNumber(req.total_tokens)}</div>` : '<div class="request-tokens">-</div>'}
                            <div class="request-status">${req.success ? '✓' : '✗'}</div>
                        </div>
                    </div>
                `).join('') : '<div class="no-requests">No requests yet</div>'}
            </div>
        </div>
    `;
}

function closeAnalyticsModal() {
    const modal = document.getElementById('analytics-modal');
    modal.classList.remove('active');
    setTimeout(() => {
        modal.classList.add('hidden');
    }, 500); // Wait for transition
}

// Close modal when clicking outside
document.addEventListener('click', (e) => {
    const modal = document.getElementById('analytics-modal');
    if (e.target === modal) {
        closeAnalyticsModal();
    }
});


// ===================================
// Pending Application Card Actions
// ===================================

async function approveFromCard(keyId) {
    await toggleKey(keyId, false);  // false = currently disabled, so toggle enables it
    logToConsole(`Approved application for key #${keyId}`, 'success');
    showAdminStatus('Application approved — key enabled', 'success');
}

async function denyFromCard(keyId) {
    if (!confirm('Deny this application and delete the key?')) return;
    await deleteKey(keyId);
    logToConsole(`Denied application for key #${keyId}`, 'info');
    showAdminStatus('Application denied — key deleted', 'info');
}


// ===================================
// Banned IPs Management
// ===================================

async function loadBannedIps(silent = false) {
    if (!silent) {
        bannedTbody.innerHTML = '<tr><td colspan="4" class="loading-cell">Loading...</td></tr>';
    }
    noBannedMessage.classList.add('hidden');

    try {
        const response = await adminFetch('/admin/banned-ips');

        if (response.ok) {
            const ips = await response.json();

            // Optimization: Only update DOM if banned IPs changed
            const bannedJson = JSON.stringify(ips);
            if (lastBannedJson === bannedJson) return;
            lastBannedJson = bannedJson;

            displayBannedIps(ips);
        } else if (response.status === 401) {
            logout();
        } else if (!silent) {
            logToConsole('Failed to load banned IPs', 'error');
            bannedTbody.innerHTML = '<tr><td colspan="4" class="loading-cell">Error loading banned IPs</td></tr>';
        }
    } catch (error) {
        if (!silent) {
            logToConsole(`Banned IPs error: ${error.message}`, 'error');
            bannedTbody.innerHTML = '<tr><td colspan="4" class="loading-cell">Error loading banned IPs</td></tr>';
        }
    }
}

function displayBannedIps(ips) {
    if (!ips || ips.length === 0) {
        bannedTbody.innerHTML = '';
        noBannedMessage.classList.remove('hidden');
        return;
    }

    noBannedMessage.classList.add('hidden');
    bannedTbody.innerHTML = ips.map(ip => `
        <tr>
            <td>${escapeHtml(ip.ip_address)}</td>
            <td>${ip.reason ? escapeHtml(ip.reason) : '<em>No reason</em>'}</td>
            <td>${formatDate(ip.banned_at)}</td>
            <td>
                <button type="button" class="btn btn-ghost btn-sm unban-btn" data-ip="${escapeAttr(ip.ip_address)}">
                    Unban
                </button>
            </td>
        </tr>
    `).join('');
    // Attach unban handlers (avoids putting IP in onclick - XSS safe)
    bannedTbody.querySelectorAll('.unban-btn').forEach(btn => {
        btn.addEventListener('click', () => unbanIp(btn.getAttribute('data-ip')));
    });
}

async function banIp(event) {
    event.preventDefault();

    const ipAddress = banIpInput.value.trim();
    const reason = banReasonInput.value.trim();

    if (!ipAddress) {
        showAdminStatus('Please enter an IP address', 'error');
        return;
    }

    try {
        const response = await adminFetch('/admin/ban-ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip_address: ipAddress, reason: reason || null })
        });

        if (response.ok) {
            logToConsole(`Banned IP: ${ipAddress}`, 'success');
            showAdminStatus(`IP ${ipAddress} has been banned`, 'success');
            banIpInput.value = '';
            banReasonInput.value = '';
            await loadBannedIps();
        } else if (response.status === 401) {
            logout();
        } else {
            const data = await response.json().catch(() => ({}));
            logToConsole(`Ban IP failed: ${data.error || 'Unknown error'}`, 'error');
            showAdminStatus(data.error || 'Failed to ban IP', 'error');
        }
    } catch (error) {
        logToConsole(`Ban IP error: ${error.message}`, 'error');
        showAdminStatus('Network error banning IP', 'error');
    }
}

async function unbanIp(ipAddress) {
    if (!confirm(`Are you sure you want to unban ${ipAddress}?`)) return;

    try {
        const response = await adminFetch(`/admin/ban-ip/${encodeURIComponent(ipAddress)}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            logToConsole(`Unbanned IP: ${ipAddress}`, 'success');
            showAdminStatus(`IP ${ipAddress} has been unbanned`, 'success');
            await loadBannedIps();
        } else if (response.status === 401) {
            logout();
        } else if (response.status === 404) {
            logToConsole('IP not found in ban list', 'error');
            await loadBannedIps();
        } else {
            logToConsole('Failed to unban IP', 'error');
        }
    } catch (error) {
        logToConsole(`Unban IP error: ${error.message}`, 'error');
    }
}


// ===================================
// Rate Limit Reset
// ===================================

async function resetAllRpm() {
    if (!confirm('Are you sure you want to reset RPM counters for all keys?')) return;

    try {
        const response = await adminFetch('/admin/reset-all-rpm', { method: 'POST' });

        if (response.ok) {
            const data = await response.json();
            logToConsole(`Reset RPM for ${data.count} keys`, 'success');
            showAdminStatus(data.message, 'success');
            await loadKeys();
        } else if (response.status === 401) {
            logout();
        } else {
            logToConsole('Failed to reset RPM', 'error');
            showAdminStatus('Failed to reset RPM counters', 'error');
        }
    } catch (error) {
        logToConsole(`Reset RPM error: ${error.message}`, 'error');
        showAdminStatus('Network error resetting RPM', 'error');
    }
}

async function resetAllRpd() {
    if (!confirm('Are you sure you want to reset RPD counters for all keys?')) return;

    try {
        const response = await adminFetch('/admin/reset-all-rpd', { method: 'POST' });

        if (response.ok) {
            const data = await response.json();
            logToConsole(`Reset RPD for ${data.count} keys`, 'success');
            showAdminStatus(data.message, 'success');
            await loadKeys();
        } else if (response.status === 401) {
            logout();
        } else {
            logToConsole('Failed to reset RPD', 'error');
            showAdminStatus('Failed to reset RPD counters', 'error');
        }
    } catch (error) {
        logToConsole(`Reset RPD error: ${error.message}`, 'error');
        showAdminStatus('Network error resetting RPD', 'error');
    }
}


async function purgeAllKeys() {
    if (!confirm('⚠️ WARNING: This will DELETE ALL API keys and usage logs!\n\nEvery user will need to re-register via Discord.\n\nAre you absolutely sure?')) return;
    if (!confirm('FINAL CONFIRMATION: Purge ALL keys? This cannot be undone.')) return;

    try {
        const response = await adminFetch('/admin/purge-all-keys', { method: 'POST' });

        if (response.ok) {
            const data = await response.json();
            logToConsole(`Purged ${data.count} keys and all usage logs`, 'success');
            showAdminStatus(data.message, 'success');
            await loadKeys();
        } else if (response.status === 401) {
            logout();
        } else {
            logToConsole('Failed to purge keys', 'error');
            showAdminStatus('Failed to purge keys', 'error');
        }
    } catch (error) {
        logToConsole(`Purge error: ${error.message}`, 'error');
        showAdminStatus('Network error purging keys', 'error');
    }
}


// ===================================
// Model Management
// ===================================

async function loadModels() {
    try {
        const response = await adminFetch('/admin/models');
        if (response.ok) {
            const data = await response.json();
            renderModelsTable(data.models);
            
            // Show/hide persistence warning for Vercel users
            const warningEl = document.getElementById('models-persistence-warning');
            if (warningEl) {
                if (data.persistence_warning) {
                    warningEl.classList.remove('hidden');
                } else {
                    warningEl.classList.add('hidden');
                }
            }
        } else if (response.status === 401) {
            logout();
        } else {
            let errorMsg = "Failed to load models.";
            try {
                const errData = await response.json();
                if (errData.detail) errorMsg = errData.detail;
            } catch (e) { }
            document.getElementById('models-tbody').innerHTML = `<tr><td colspan="4" class="loading-cell" style="color:var(--danger-color);">${escapeHtml(errorMsg)}</td></tr>`;
        }
    } catch (error) {
        logToConsole(`Error loading models: ${error.message}`, 'error');
        document.getElementById('models-tbody').innerHTML = `<tr><td colspan="4" class="loading-cell error">Network error loading models.</td></tr>`;
    }
}

function renderModelsTable(models) {
    const tbody = document.getElementById('models-tbody');
    
    if (!models || models.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="loading-cell">No upstream models found.</td></tr>`;
        return;
    }

    tbody.innerHTML = models.map(m => {
        const isEnabled = m.enabled;
        const toggleHtml = `
            <label class="switch">
                <input type="checkbox" 
                    id="toggle-model-${escapeHtml(m.id)}" 
                    onchange="toggleModel('${escapeHtml(m.id)}', this)" 
                    ${isEnabled ? 'checked' : ''}>
                <span class="slider"></span>
            </label>
        `;
        
        return `
            <tr>
                <td class="key-cell"><code>${escapeHtml(m.id)}</code></td>
                <td>
                    <div class="toggle-group">
                        ${toggleHtml}
                        <span id="model-status-${escapeHtml(m.id)}" class="${isEnabled ? 'status-active' : 'status-revoked'}">
                            ${isEnabled ? 'Enabled' : 'Disabled'}
                        </span>
                    </div>
                }
                </td>
                <td>
                    <input type="text" class="form-control" style="width: 150px; padding: 4px; font-size: 0.85rem;" 
                           placeholder="Custom alias..." 
                           value="${escapeAttr(m.alias || '')}" 
                           onchange="updateModelAlias('${escapeHtml(m.id)}', this.value)">
                </td>
                <td>
                    ${isEnabled ? `<span style="color:var(--text-secondary);font-size:0.8rem;">Available for chat</span>` : `<span style="color:var(--danger-color);font-size:0.8rem;">Blocked</span>`}
                </td>
            </tr>
        `;
    }).join('');
}

async function toggleModel(modelId, checkbox) {
    const enabled = checkbox.checked;
    const statusSpan = document.getElementById(`model-status-${modelId}`);
    
    // Optimistic UI update
    if (statusSpan) {
        statusSpan.textContent = enabled ? 'Enabled' : 'Disabled';
        statusSpan.className = enabled ? 'status-active' : 'status-revoked';
    }

    try {
        const response = await adminFetch('/admin/models/toggle', {
            method: 'POST',
            body: JSON.stringify({ model_id: modelId, enabled: enabled })
        });

        if (!response.ok) {
            throw new Error(`Server returned ${response.status}`);
        }
        
        const data = await response.json();
        logToConsole(`Model ${modelId} ${enabled ? 'enabled' : 'disabled'}`, 'info');
        // REMOVED: loadModels(); // Avoid jarring re-sort/re-render on every toggle
    } catch (error) {
        logToConsole(`Failed to toggle model: ${error.message}`, 'error');
        // Revert UI on failure
        checkbox.checked = !enabled;
        if (statusSpan) {
            statusSpan.textContent = !enabled ? 'Enabled' : 'Disabled';
            statusSpan.className = !enabled ? 'status-active' : 'status-revoked';
        }
        showAdminStatus("Failed to toggle model", "error");
    }
}

async function bulkModelAction(action) {
    if (action === 'disable_all' && !confirm("Are you sure you want to disable ALL models? Users won't be able to chat until you enable them again.")) {
        return;
    }

    try {
        const response = await adminFetch('/admin/models/bulk-action', {
            method: 'POST',
            body: JSON.stringify({ action: action })
        });

        if (response.ok) {
            logToConsole(`Bulk action ${action} completed`, 'success');
            showAdminStatus(`Models ${action === 'enable_all' ? 'enabled' : 'disabled'}`, 'success');
            loadModels();
        } else {
            throw new Error(`Server returned ${response.status}`);
        }
    } catch (error) {
        logToConsole(`Failed bulk action ${action}: ${error.message}`, 'error');
        showAdminStatus(`Error during bulk action`, 'error');
    }
}

async function updateModelAlias(modelId, alias) {
    try {
        const response = await adminFetch('/admin/models/alias', {
            method: 'POST',
            body: JSON.stringify({ model_id: modelId, alias: alias })
        });

        if (response.ok) {
            logToConsole(`Alias updated for ${modelId}`, 'success');
            showAdminStatus("Alias updated", "success");
        } else {
            throw new Error(`Server returned ${response.status}`);
        }
    } catch (error) {
        logToConsole(`Failed to update alias: ${error.message}`, 'error');
        showAdminStatus(`Error updating alias`, 'error');
        loadModels(); // Revert
    }
}

// ===================================
// Utility Functions
// ===================================

function showAdminStatus(message, type = 'info') {
    if (!adminStatus) return;

    adminStatus.textContent = message;
    adminStatus.className = `status-message ${type}`;
    adminStatus.classList.remove('hidden');

    // Auto-hide after 5 seconds
    setTimeout(() => {
        adminStatus.classList.add('hidden');
    }, 5000);
}

function formatDate(isoString) {
    if (!isoString) return 'N/A';
    const date = new Date(isoString);
    return date.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric'
    });
}

function formatTime(isoString) {
    if (!isoString) return 'N/A';
    const date = new Date(isoString);
    return date.toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function formatNumber(num) {
    if (num === null || num === undefined) return '0';
    if (num >= 1000000) {
        return (num / 1000000).toFixed(1) + 'M';
    }
    if (num >= 1000) {
        return (num / 1000).toFixed(1) + 'K';
    }
    return num.toLocaleString();
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/** Escape for HTML attribute value (e.g. data-ip) to prevent break-out and XSS */
function escapeAttr(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML.replace(/"/g, '&quot;');
}


// ===================================
// Theme Management
// ===================================

function toggleTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

    html.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
}

function loadTheme() {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
        document.documentElement.setAttribute('data-theme', savedTheme);
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    loadTheme();
    init();
});
