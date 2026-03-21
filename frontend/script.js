/**
 * AI Proxy - Frontend JavaScript
 * Handles API key display and usage stats
 */

// Constants
const STORAGE_KEY_PREFIX = 'ai_proxy_key_prefix';
const STORAGE_FULL_KEY = 'ai_proxy_full_key';
const STORAGE_CLIENT_ID = 'ai_proxy_client_id';

// State
let currentKeyPrefix = null;
let fullKey = null;

// DOM Elements
const noKeyView = document.getElementById('no-key-view');
const hasKeyView = document.getElementById('has-key-view');
const keyPrefixEl = document.getElementById('key-prefix');
const fullKeyDisplay = document.getElementById('full-key-display');
const fullKeyText = document.getElementById('full-key-text');
const usageSection = document.getElementById('usage-section');
const statusMessage = document.getElementById('status-message');

// RPM elements
const rpmProgress = document.getElementById('rpm-progress');
const rpmUsed = document.getElementById('rpm-used');
const rpmLimit = document.getElementById('rpm-limit');

// RPD elements
const rpdProgress = document.getElementById('rpd-progress');
const rpdUsed = document.getElementById('rpd-used');
const rpdLimit = document.getElementById('rpd-limit');

// Total tokens
const totalTokens = document.getElementById('total-tokens');

/**
 * Fetch and display public models
 */
async function fetchPublicModels() {
    const dropdown = document.getElementById('model-dropdown');
    if (!dropdown) return;
    
    try {
        const response = await fetch('/api/public-models');
        if (!response.ok) throw new Error('Failed to fetch models');
        
        const data = await response.json();
        const models = data.models || [];
        
        dropdown.innerHTML = ''; // Clear loading text
        
        if (models.length === 0) {
            const option = document.createElement('option');
            option.value = '';
            option.textContent = 'No models available';
            dropdown.appendChild(option);
            return;
        }
        
        models.forEach(model => {
            const option = document.createElement('option');
            option.value = model.id;
            option.textContent = `${model.id} - ${model.status}`;
            
            if (model.status === 'DOWN') {
                option.style.color = 'var(--accent-red, #ff4d4d)';
            } else {
                option.style.color = 'var(--accent-green, #4dff4d)';
            }
            
            dropdown.appendChild(option);
        });
    } catch (error) {
        console.error('Error fetching public models:', error);
        dropdown.innerHTML = '<option value="">Error loading models</option>';
    }
}

/**
 * Initialize the application
 */
async function init() {
    await checkLoggedIn();
    await fetchPublicModels();
    
    // Show Terms of Service on every refresh
    const tosModal = document.getElementById('tos-modal');
    if (tosModal) {
        setTimeout(() => {
            tosModal.classList.add('active');
        }, 500); // Slight delay for better entrance effect
    }
}

/**
 * Compute Hardware Fingerprint
 */
async function getHardwareFingerprint() {
    const gl = document.createElement('canvas').getContext('webgl');
    const debugInfo = gl ? gl.getExtension('WEBGL_debug_renderer_info') : null;
    const renderer = debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : '';
    const vendor = debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : '';
    const screenInfo = `${window.screen.width}x${window.screen.height}x${window.screen.colorDepth}`;
    const cores = navigator.hardwareConcurrency || '';
    const ram = navigator.deviceMemory || '';
    const os = navigator.platform;
    
    // Persistent ID for stability on refresh even if hardware flags fluctuate
    let clientId = localStorage.getItem(STORAGE_CLIENT_ID);
    if (!clientId) {
        clientId = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
        localStorage.setItem(STORAGE_CLIENT_ID, clientId);
    }
    
    const str = `${renderer}-${vendor}-${screenInfo}-${cores}-${ram}-${os}-${clientId}`;
    
    // Use fallback hashing locally over HTTP since crypto.subtle requires HTTPS
    if (!window.crypto || !window.crypto.subtle) {
        console.warn('Crypto.subtle API not available (requires HTTPS). Using insecure fallback hash.');
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32bit int
        }
        return Math.abs(hash).toString(16) + str.length.toString(16);
    }
    
    const msgUint8 = new TextEncoder().encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Generate API Key using Fingerprint
 */
async function generateKey() {
    try {
        const btn = document.getElementById('generate-btn');
        if (btn) {
            btn.textContent = 'Generating...';
            btn.disabled = true;
        }
        
        const fingerprint = await getHardwareFingerprint();
        const response = await fetch('/api/generate-key', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ fingerprint })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            fullKey = data.key;
            currentKeyPrefix = data.key_prefix;
            localStorage.setItem(STORAGE_FULL_KEY, data.key);
            localStorage.setItem(STORAGE_KEY_PREFIX, data.key_prefix);
            
            showHasKeyView();
            showFullKey(data.key);
            showStatus(data.message, 'success');
            await fetchUsage();
        } else {
            showStatus(data.detail || 'Failed to generate key', 'error');
        }
    } catch (e) {
        showStatus('Network error generating key', 'error');
        console.error(e);
    } finally {
        const btn = document.getElementById('generate-btn');
        if (btn) {
            btn.textContent = 'Generate API Key';
            btn.disabled = false;
        }
    }
}

/**
 * Check if user is logged in via /api/my-key endpoint
 */
async function checkLoggedIn() {
    try {
        const fp = await getHardwareFingerprint();
        const response = await fetch('/api/my-key?fingerprint=' + encodeURIComponent(fp));
        
        if (response.ok) {
            const data = await response.json();
            currentKeyPrefix = data.key_prefix;
            
            if (data.enabled === false) {
                showStatus('Your API key is disabled.', 'error');
                showNoKeyView();
                return;
            }
            
            if (data.full_key) {
                fullKey = data.full_key;
                localStorage.setItem(STORAGE_FULL_KEY, data.full_key);
            }
            localStorage.setItem(STORAGE_KEY_PREFIX, data.key_prefix);
            showHasKeyView();
            if (fullKey || localStorage.getItem(STORAGE_FULL_KEY)) {
                showFullKey(fullKey || localStorage.getItem(STORAGE_FULL_KEY));
            }
            await fetchUsage(fp); // Use the fingerprint we already fetched
        } else if (response.status === 404) {
            // Key not found on server - DB might be wiped. Attempt to restore if we have local key.
            const savedFullKey = localStorage.getItem(STORAGE_FULL_KEY);
            if (savedFullKey) {
                console.log('Key not found in DB. Attempting to restore from local storage...');
                try {
                    const restoreResponse = await fetch('/api/restore-key', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            full_key: savedFullKey,
                            fingerprint: fp
                        })
                    });
                    
                    if (restoreResponse.ok) {
                        const restoreData = await restoreResponse.json();
                        fullKey = restoreData.key;
                        currentKeyPrefix = restoreData.key_prefix;
                        showHasKeyView();
                        showFullKey(fullKey);
                        console.log('Session seamlessly restored!');
                        await fetchUsage(fp);
                        return; // Restoration successful
                    }
                } catch (err) {
                    console.error('Failed to restore key:', err);
                }
            }
            
            // If restore fails or no saved key is found, clear local storage to allow regeneration
            console.log('Could not restore key, clearing local storage.');
            localStorage.removeItem(STORAGE_FULL_KEY);
            localStorage.removeItem(STORAGE_KEY_PREFIX);
            showNoKeyView();
        } else {
            // OTHER ERROR (500, etc.): FALLBACK to localStorage if we have it
            const savedFullKey = localStorage.getItem(STORAGE_FULL_KEY);
            const savedPrefix = localStorage.getItem(STORAGE_KEY_PREFIX);
            
            if (savedFullKey && savedPrefix) {
                console.log('Server session lost. Using localStorage fallback.');
                fullKey = savedFullKey;
                currentKeyPrefix = savedPrefix;
                showHasKeyView();
                showFullKey(savedFullKey);
                await fetchUsage(fp); // Still try with current fp
            } else {
                showNoKeyView();
            }
        }
    } catch (error) {
        console.error('Error checking login status:', error);
        // Even on network error, try to show the key from localStorage if we have it
        const savedFullKey = localStorage.getItem(STORAGE_FULL_KEY);
        if (savedFullKey) {
            fullKey = savedFullKey;
            currentKeyPrefix = localStorage.getItem(STORAGE_KEY_PREFIX);
            showHasKeyView();
            showFullKey(savedFullKey);
        } else {
            showNoKeyView();
        }
    }
}

/**
 * Fetch and display usage statistics
 * @param {string} fingerprint - Optional hardware fingerprint to identify the key
 */
async function fetchUsage(fingerprint = null) {
    try {
        // Use provided fingerprint or fetch it
        const fp = fingerprint || await getHardwareFingerprint();
        const response = await fetch('/api/my-usage?fingerprint=' + encodeURIComponent(fp));
        
        if (response.ok) {
            const data = await response.json();
            updateUsageDisplay(data);
            if (usageSection) usageSection.classList.remove('hidden');
        } else {
            if (usageSection) usageSection.classList.add('hidden');
        }
    } catch (error) {
        console.error('Error fetching usage:', error);
    }
}

/**
 * Update the usage display with new data (RPM, requests per day, total tokens)
 */
function updateUsageDisplay(data) {
    const rpmLimitVal = data.rpm_limit ?? 10;
    const rpdLimitVal = data.rpd_limit ?? 200;
    
    // Update RPM
    const rpm = data.rpm_used ?? 0;
    const rpmPercent = rpmLimitVal > 0 ? (rpm / rpmLimitVal) * 100 : 0;
    rpmProgress.style.width = `${Math.min(rpmPercent, 100)}%`;
    rpmUsed.textContent = rpm;
    rpmLimit.textContent = rpmLimitVal;
    
    // Update requests per day (current_rpd = requests used today)
    const rpd = data.rpd_used ?? 0;
    const rpdPercent = rpdLimitVal > 0 ? (rpd / rpdLimitVal) * 100 : 0;
    if (rpdProgress) rpdProgress.style.width = `${Math.min(rpdPercent, 100)}%`;
    if (rpdUsed) rpdUsed.textContent = typeof rpd === 'number' ? rpd.toLocaleString() : String(rpd);
    if (rpdLimit) rpdLimit.textContent = typeof rpdLimitVal === 'number' ? rpdLimitVal.toLocaleString() : rpdLimitVal;
    
    // Total tokens used (all time)
    if (totalTokens) {
        const total = data.total_tokens ?? 0;
        totalTokens.textContent = typeof total === 'number' ? total.toLocaleString() : total;
    }
}

/**
 * Copy API key to clipboard
 */
async function copyKey() {
    let keyToCopy = localStorage.getItem(STORAGE_FULL_KEY) || fullKey;
    
    if (!keyToCopy || keyToCopy.length < 10) {
        showStatus('Full key not available. It was only shown once during generation.', 'error');
        return;
    }
    
    try {
        await navigator.clipboard.writeText(keyToCopy);
        showStatus(`API key copied! (${keyToCopy.length} chars)`, 'success');
        
        const copyBtn = document.getElementById('copy-btn');
        if (copyBtn) {
            const originalText = copyBtn.textContent;
            copyBtn.textContent = 'Copied!';
            setTimeout(() => {
                copyBtn.textContent = originalText;
            }, 2000);
        }
    } catch (error) {
        console.error('Error copying to clipboard:', error);
        
        // Fallback
        const textArea = document.createElement('textarea');
        textArea.value = keyToCopy;
        textArea.style.position = 'fixed';
        textArea.style.left = '-9999px';
        document.body.appendChild(textArea);
        textArea.select();
        
        try {
            document.execCommand('copy');
            showStatus(`API key copied!`, 'success');
        } catch (err) {
            showStatus('Failed to copy. Please copy manually.', 'error');
        }
        
        document.body.removeChild(textArea);
    }
}

/**
 * Show the "no key" view (login prompt)
 */
function showNoKeyView() {
    noKeyView.classList.remove('hidden');
    hasKeyView.classList.add('hidden');
    if (usageSection) usageSection.classList.add('hidden');
}

/**
 * Show the "has key" view
 */
function showHasKeyView() {
    noKeyView.classList.add('hidden');
    hasKeyView.classList.remove('hidden');
    // Usage section (Per minute + Tokens per day) — keep visible so TPD is always on screen
    if (usageSection) usageSection.classList.remove('hidden');
    
    // Update key prefix display
    if (currentKeyPrefix) {
        keyPrefixEl.textContent = currentKeyPrefix;
    }
}

/**
 * Show the full key
 */
function showFullKey(key) {
    if (!key) return;
    
    fullKeyText.textContent = key;
    fullKeyDisplay.classList.remove('hidden');
    
    fullKey = key;
    localStorage.setItem(STORAGE_FULL_KEY, key);
    
    fullKeyText.style.userSelect = 'text';
    fullKeyText.style.cursor = 'text';
}

/**
 * Show a status message
 */
function showStatus(message, type = 'info') {
    statusMessage.textContent = message;
    statusMessage.className = `status-message ${type}`;
    statusMessage.classList.remove('hidden');
    
    setTimeout(() => {
        statusMessage.classList.add('hidden');
    }, 5000);
}

/**
 * Refresh usage data periodically
 */
function startUsageRefresh() {
    setInterval(async () => {
        if (currentKeyPrefix) {
            await fetchUsage();
        }
    }, 30000);
}

/**
 * Toggle between light and dark theme
 */
function toggleTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    html.setAttribute('data-theme', newTheme);
    localStorage.setItem('ai_proxy_theme', newTheme);
}

/**
 * Load saved theme preference
 */
function loadTheme() {
    const savedTheme = localStorage.getItem('ai_proxy_theme');
    if (savedTheme) {
        document.documentElement.setAttribute('data-theme', savedTheme);
    }
}

/**
 * Close the Terms of Service modal
 */
function closeTos() {
    const tosModal = document.getElementById('tos-modal');
    if (tosModal) {
        tosModal.classList.remove('active');
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    loadTheme();
    init();
    startUsageRefresh();
});
