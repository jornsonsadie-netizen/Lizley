import codecs
import re

# ==========================================
# 1. Patch index.html
# ==========================================
with codecs.open('frontend/index.html', 'r', 'utf-8') as f:
    index_html = f.read()

discord_btn_pattern = re.search(r'<div id="no-key-view" class="key-view">.*?</div>', index_html, re.DOTALL)
if discord_btn_pattern:
    new_no_key_view = '''<div id="no-key-view" class="key-view">
                    <p class="info-text">Generate your unique API Key bound to this device.</p>
                    <button id="generate-btn" onclick="generateKey()" class="btn btn-primary">
                        Generate API Key
                    </button>
                </div>'''
    index_html = index_html.replace(discord_btn_pattern.group(0), new_no_key_view)

index_html = index_html.replace('<div id="user-email" class="user-email"></div>', '')
index_html = index_html.replace('<a href="/auth/logout" class="btn btn-ghost">Logout</a>', '')

with codecs.open('frontend/index.html', 'w', 'utf-8') as f:
    f.write(index_html)

# ==========================================
# 2. Patch script.js
# ==========================================
with codecs.open('frontend/script.js', 'r', 'utf-8') as f:
    script_js = f.read()

new_script_functions = '''
async function getHardwareFingerprint() {
    const gl = document.createElement('canvas').getContext('webgl');
    const debugInfo = gl ? gl.getExtension('WEBGL_debug_renderer_info') : null;
    const renderer = debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : '';
    const vendor = debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : '';
    const screenInfo = `${window.screen.width}x${window.screen.height}x${window.screen.colorDepth}`;
    const cores = navigator.hardwareConcurrency || '';
    const ram = navigator.deviceMemory || '';
    const os = navigator.platform;
    const str = `${renderer}-${vendor}-${screenInfo}-${cores}-${ram}-${os}`;
    
    const msgUint8 = new TextEncoder().encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function generateKey() {
    try {
        const btn = document.getElementById('generate-btn');
        btn.textContent = 'Generating...';
        btn.disabled = true;
        
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
    } finally {
        const btn = document.getElementById('generate-btn');
        if (btn) {
            btn.textContent = 'Generate API Key';
            btn.disabled = false;
        }
    }
}

async function init() {
    await checkLoggedIn();
}

async function checkLoggedIn() {
    try {
        const response = await fetch('/api/my-key');
        if (response.ok) {
            const data = await response.json();
            currentKeyPrefix = data.key_prefix;
            
            if (data.enabled === false) {    
                showStatus('Your API key is disabled.', 'error');
                showNoKeyView();
                return;
            }
            localStorage.setItem(STORAGE_KEY_PREFIX, data.key_prefix);
            showHasKeyView();
            
            if (fullKey || localStorage.getItem(STORAGE_FULL_KEY)) {
                showFullKey(fullKey || localStorage.getItem(STORAGE_FULL_KEY));
            }
            await fetchUsage();
        } else {
            showNoKeyView();
        }
    } catch (error) {
        showNoKeyView();
    }
}

async function fetchUsage() {
    try {
        const response = await fetch('/api/my-usage');
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
'''
script_js = re.sub(r'async function init\(\).*?async function fetchUsage\(\) {[\s\S]*?\} \(error\) \{\s*console\.error[\s\S]*?\}', new_script_functions, script_js, flags=re.DOTALL)
script_js = re.sub(r'// Handle OAuth callback.*?return;\s*\}', '', script_js, flags=re.DOTALL)
script_js = re.sub(r'function showPendingApprovalView\(\).*?function showHasKeyView', 'function showHasKeyView', script_js, flags=re.DOTALL)

with codecs.open('frontend/script.js', 'w', 'utf-8') as f:
    f.write(script_js)


# ==========================================
# 3. Patch admin.html
# ==========================================
with codecs.open('frontend/admin.html', 'r', 'utf-8') as f:
    admin_html = f.read()

# Remove pending section
pending_section = re.search(r'<!-- Pending Applications Section -->.*?</section>', admin_html, re.DOTALL)
if pending_section:
    admin_html = admin_html.replace(pending_section.group(0), '')

# Remove Discord Account column from table
admin_html = admin_html.replace('<th>Discord Account</th>', '<th>IP / Hardware</th>')

with codecs.open('frontend/admin.html', 'w', 'utf-8') as f:
    f.write(admin_html)

# ==========================================
# 4. Patch admin.js
# ==========================================
with codecs.open('frontend/admin.js', 'r', 'utf-8') as f:
    admin_js = f.read()

# Remove pending logic from displayKeys
admin_js = re.sub(r'// Separate pending applications from active keys.*?// Render active/non-pending keys in the table\s*if \(activeKeys\.length === 0\) \{', 'if (keys.length === 0) {', admin_js, flags=re.DOTALL)
admin_js = re.sub(r'displayPendingApplications\(pendingKeys\);', '', admin_js)

# Fix the table body mapping
admin_js = admin_js.replace('activeKeys.map', 'keys.map')

# Fix Discord Email display in the table
discord_email_html = r'''<td class="discord-email">
                \$\{escapeHtml\(key\.discord_email \|\| key\.ip_address \|\| 'Unknown'\)\}
                \$\{key\.rp_application \? `<div class="rp-info">RP: \$\{escapeHtml\(key\.rp_application\.length > 50 \? key\.rp_application\.substring\(0, 50\) \+ '\.\.\.' : key\.rp_application\)\}</div>` : ''\}
            </td>'''
new_hw_html = r'''<td class="discord-email" title="${escapeHtml(key.browser_fingerprint || 'Unknown Fingerprint')}">
                ${escapeHtml(key.ip_address)}<br>
                <small>${key.browser_fingerprint ? key.browser_fingerprint.substring(0,8)+'...' : 'No Fingerprint'}</small>
            </td>'''
admin_js = re.sub(discord_email_html, new_hw_html, admin_js)

# Remove displayPendingApplications function entirely
pending_fn = re.search(r'/\*\*.*?Display pending applications.*?function displayPendingApplications\(pendingKeys\) \{.*?</section>', admin_js, re.DOTALL)
# Actually it's easier to just ignore it, or blindly match the boundary.
admin_js = re.sub(r'function displayPendingApplications\(pendingKeys\).*?function setBypassIp', 'function setBypassIp', admin_js, flags=re.DOTALL)

with codecs.open('frontend/admin.js', 'w', 'utf-8') as f:
    f.write(admin_js)

print("done frontend patch")
