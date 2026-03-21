/**
 * LizRP Frontend Logic - Premium Redesign Consolidated
 */

// ===================================
// State & Configuration
// ===================================
const RP_TOKEN_KEY = 'lizrp_access_token';

let currentUser = null;
let currentChatId = null;
let currentBotId = null;
let isGenerating = false;
let myOcs = [];
let currentChatMessages = [];
let currentWallpaperBase64 = null;
let pendingModalBase64 = { bot: null, oc: null, user: null };
let pendingImageBase64 = null;

// DOM Elements
const botsGrid = document.getElementById('bots-grid');
const oldChatsList = document.getElementById('old-chats-list');
const chatMessagesContainer = document.getElementById('chat-messages');
const chatInput = document.getElementById('chat-input');
const modelSelect = document.getElementById('menu-model-select');
const ocSelect = document.getElementById('menu-oc-select');
const chatMenuDropdown = document.getElementById('chat-menu-dropdown');
const chatMenuToggle = document.getElementById('chat-menu-toggle');

// ===================================
// Initialization
// ===================================

document.addEventListener('DOMContentLoaded', () => {
    loadTheme();
    initRP();
    initEventListeners();
});

function initEventListeners() {
    console.log("Initializing event listeners...");

    // Navigation Buttons (Bottom Nav)
    const navItems = ['home', 'create', 'chats', 'profile'];
    navItems.forEach(id => {
        const btn = document.getElementById(`nav-${id}`);
        if (btn) {
            btn.addEventListener('click', () => showView(id));
        }
    });

    // Chat Menu Toggle
    if (chatMenuToggle) {
        chatMenuToggle.addEventListener('click', (e) => {
            e.stopPropagation();
            if (chatMenuDropdown) chatMenuDropdown.classList.toggle('hidden');
        });
    }

    // Close dropdowns on outside click
    document.addEventListener('click', (e) => {
        if (chatMenuDropdown && !chatMenuDropdown.contains(e.target)) {
            chatMenuDropdown.classList.add('hidden');
        }
    });

    // Global Key Listeners
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            const modals = document.querySelectorAll('.modal:not(.hidden)');
            modals.forEach(m => closeModal(m.id));
            if (chatMenuDropdown) chatMenuDropdown.classList.add('hidden');
        }
    });

    // Authentication Forms
    const authForm = document.getElementById('auth-form');
    if (authForm) {
        authForm.addEventListener('submit', handleAuthSubmit);
    }

    // Bot/OC Creation Forms
    const createBotForm = document.getElementById('create-bot-form');
    if (createBotForm) {
        createBotForm.addEventListener('submit', handleBotSubmit);
    }

    const ocForm = document.getElementById('oc-form');
    if (ocForm) {
        ocForm.addEventListener('submit', handleOcSubmit);
    }

    // Admin Forms
    const adminAuthForm = document.getElementById('admin-auth-form');
    if (adminAuthForm) {
        adminAuthForm.addEventListener('submit', handleAdminAuth);
    }

    const adminConfigForm = document.getElementById('admin-config-form');
    if (adminConfigForm) {
        adminConfigForm.addEventListener('submit', handleAdminConfigSubmit);
    }
    
    // User Profile Edit Form
    const profileForm = document.getElementById('profile-edit-form');
    if (profileForm) {
        profileForm.addEventListener('submit', handleProfileUpdate);
    }
}

async function initRP() {
    await checkAuth();
    await loadPublicModels();
    await loadDiscoveryHub();
    loadSavedWallpaper();
}

function loadTheme() {
    const savedTheme = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
}

function toggleTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
}

// ===================================
// Navigation & Views
// ===================================

function showView(viewName) {
    const targetId = viewName.startsWith('view-') ? viewName : `view-${viewName}`;
    const panel = document.getElementById(targetId) || document.getElementById(viewName);

    // Special handling for auth requirement
    if ((viewName === 'create' || viewName === 'chats' || viewName === 'profile') && !currentUser) {
        if (viewName !== 'profile') {
            showToast('Please sign in to access this feature', 'info');
            showView('profile');
            return;
        }
    }

    // Hide all panels
    document.querySelectorAll('.view-panel').forEach(p => {
        p.classList.add('hidden');
        p.classList.remove('active-view');
    });

    // Show target panel
    if (panel) {
        panel.classList.remove('hidden');
        setTimeout(() => panel.classList.add('active-view'), 10);
    }

    // Update Bottom Nav active state
    updateBottomNav(viewName);

    // Refresh data if needed
    if (viewName === 'home') loadDiscoveryHub();
    if (viewName === 'chats') loadUserContent();
    
    // Auto scroll chat if entering chat
    if (viewName === 'chat-interface') {
        setTimeout(scrollToBottom, 60);
    }
}

function updateBottomNav(viewName) {
    const navIds = ['home', 'create', 'chats', 'profile'];
    navIds.forEach(id => {
        const btn = document.getElementById(`nav-${id}`);
        if (btn) {
            if (id === viewName || (viewName === 'chat-interface' && id === 'chats')) {
                btn.classList.add('active');
            } else {
                btn.classList.remove('active');
            }
        }
    });
}

// ===================================
// Authentication
// ===================================

let isLoginMode = true;

function showLoginModal() {
    isLoginMode = true;
    document.getElementById('auth-title').textContent = 'Sign In';
    document.getElementById('auth-submit-btn').textContent = 'Sign In';
    document.getElementById('auth-error').classList.add('hidden');
    openModal('auth-modal');
}

function toggleAuthMode() {
    isLoginMode = !isLoginMode;
    const title = document.getElementById('auth-title');
    const btn = document.getElementById('auth-submit-btn');
    const link = document.querySelector('#auth-form .accent-link');
    
    if (isLoginMode) {
        title.textContent = 'Sign In';
        btn.textContent = 'Sign In';
        link.textContent = "Don't have an account? Register here";
    } else {
        title.textContent = 'Create Account';
        btn.textContent = 'Register';
        link.textContent = "Already have an account? Sign in here";
    }
}

async function handleAuthSubmit(e) {
    e.preventDefault();
    const btn = document.getElementById('auth-submit-btn');
    const errorEl = document.getElementById('auth-error');
    const username = document.getElementById('auth-username').value.trim();
    const password = document.getElementById('auth-password').value;
    
    btn.disabled = true;
    errorEl.classList.add('hidden');
    
    const endpoint = isLoginMode ? '/login' : '/register';
    
    try {
        const res = await fetch(`/api/rp${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        const data = await res.json();
        if (res.ok) {
            localStorage.setItem(RP_TOKEN_KEY, data.access_token);
            closeModal('auth-modal');
            await checkAuth();
            showToast(`Welcome, ${username}!`, 'success');
            showView('home');
        } else {
            errorEl.textContent = data.detail || 'Authentication failed';
            errorEl.classList.remove('hidden');
        }
    } catch (err) {
        errorEl.textContent = "Server error. Please try again later.";
        errorEl.classList.remove('hidden');
    } finally {
        btn.disabled = false;
    }
}

async function checkAuth() {
    const token = localStorage.getItem(RP_TOKEN_KEY);
    if (!token) {
        handleLogoutState();
        return;
    }
    
    try {
        const res = await fetch('/api/rp/profile', {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (res.ok) {
            currentUser = await res.json();
            handleLoginState();
            await loadUserContent();
        } else {
            localStorage.removeItem(RP_TOKEN_KEY);
            handleLogoutState();
        }
    } catch (err) {
        console.error("Auth check failed:", err);
    }
}

function handleLoginState() {
    const topAuthBtn = document.getElementById('auth-nav-btn');
    if (topAuthBtn) topAuthBtn.classList.add('hidden');
    
    // Update Profile View Groups
    document.getElementById('profile-auth-group').classList.add('hidden');
    document.getElementById('profile-settings-group').classList.remove('hidden');
    document.getElementById('profile-actions-group').classList.remove('hidden');
    
    // Admin check
    if (currentUser.is_admin) {
        const adminSection = document.getElementById('admin-section');
        if (adminSection) adminSection.classList.remove('hidden');
    }

    // Update Profile Info
    document.getElementById('page-username').textContent = currentUser.username;
    document.getElementById('page-user-id').textContent = `@${currentUser.username.toLowerCase()}`;
    if (currentUser.avatar) {
        const avatarImg = document.getElementById('page-user-avatar');
        if (avatarImg) avatarImg.src = currentUser.avatar;
    }
}

function handleLogoutState() {
    currentUser = null;
    const topAuthBtn = document.getElementById('auth-nav-btn');
    if (topAuthBtn) topAuthBtn.classList.remove('hidden');
    
    document.getElementById('profile-auth-group').classList.remove('hidden');
    document.getElementById('profile-settings-group').classList.add('hidden');
    document.getElementById('profile-actions-group').classList.add('hidden');
    document.getElementById('admin-section').classList.add('hidden');
    
    document.getElementById('page-username').textContent = 'Guest User';
    document.getElementById('page-user-id').textContent = 'Sign in to unlock full features';
    document.getElementById('page-user-avatar').src = '/static/default-avatar.png';
}

function logoutRp() {
    localStorage.removeItem(RP_TOKEN_KEY);
    handleLogoutState();
    showView('home');
    showToast('Logged out successfully', 'info');
}

// ===================================
// Data Loading
// ===================================

async function loadPublicModels() {
    try {
        const res = await fetch('/api/public-models');
        if (res.ok) {
            const data = await res.json();
            const models = data.models || [];
            if (modelSelect) {
                modelSelect.innerHTML = models.map(m => {
                    const isHealthy = m.status === 'HEALTHY';
                    const icon = isHealthy ? '🟢' : '🔴';
                    return `<option value="${m.id}" ${!isHealthy ? 'disabled' : ''}>${icon} ${m.alias || m.id}</option>`;
                }).join('');
            }
        }
    } catch (e) {}
}

async function loadDiscoveryHub() {
    const grid = document.getElementById('bots-grid');
    if (!grid) return;

    try {
        const res = await fetch('/api/rp/bots');
        if (res.ok) {
            const data = await res.json();
            const bots = data.bots;
            
            if (bots.length === 0) {
                grid.innerHTML = '<div class="info-text">No characters found yet.</div>';
                return;
            }
            
            grid.innerHTML = bots.map(bot => `
                <div class="bot-card" onclick="openBotView('${bot.id}')">
                    <img src="${bot.avatar || '/static/default-bot.png'}" loading="lazy" alt="${escapeHtml(bot.name)}" onerror="this.src='/static/default-bot.png'">
                    <div class="bot-card-info">
                        <span class="bot-card-name">${escapeHtml(bot.name)}</span>
                        <span class="bot-card-creator">by ${escapeHtml(bot.creator_name || 'System')}</span>
                    </div>
                </div>
            `).join('');
        } else {
            const error = await res.json();
            grid.innerHTML = `<div class="error-text">Failed to load: ${error.detail}</div>`;
        }
    } catch (e) {
        console.error("Hub load failed", e);
        grid.innerHTML = '<div class="error-text">Network error loading Discovery Hub.</div>';
    }
}

async function loadUserContent() {
    const token = localStorage.getItem(RP_TOKEN_KEY);
    if (!token) return;
    
    const headers = { 'Authorization': `Bearer ${token}` };
    
    // Load OCs
    try {
        const ocRes = await fetch('/api/rp/ocs', { headers });
        if (ocRes.ok) {
            const ocData = await ocRes.json();
            myOcs = ocData.ocs;
            if (ocSelect) {
                ocSelect.innerHTML = '<option value="">No OC (Playing as yourself)</option>' + 
                    myOcs.map(oc => `<option value="${oc.id}">${escapeHtml(oc.name)}</option>`).join('');
            }
        }
    } catch (e) {}
    
    // Load Chats
    try {
        const chatRes = await fetch('/api/rp/chats', { headers });
        if (chatRes.ok) {
            const chatData = await chatRes.json();
            if (oldChatsList) {
                if (chatData.chats.length === 0) {
                    oldChatsList.innerHTML = '<div class="info-text" style="padding: 1.5rem; opacity: 0.6;">No previous chats.</div>';
                } else {
                    oldChatsList.innerHTML = chatData.chats.map(c => `
                        <div class="menu-item" onclick="loadChatHistory('${c.id}')">
                            <div style="display:flex; align-items:center; gap: 12px;">
                                <img src="${c.bot_avatar || '/static/default-bot.png'}" style="width:40px;height:40px;border-radius:50%;object-fit:cover;">
                                <div>
                                    <div style="font-weight:600;">${escapeHtml(c.bot_name)}</div>
                                    <div style="font-size:0.75rem; opacity:0.6;">${formatShortDate(c.updated_at)}</div>
                                </div>
                            </div>
                        </div>
                    `).join('');
                }
            }
        }
    } catch (e) {}
}

async function openBotView(botId) {
    try {
        const res = await fetch(`/api/rp/bots/${botId}`);
        if (res.ok) {
            const bot = await res.json();
            currentBotId = bot.id;
            
            document.getElementById('profile-bot-name').textContent = bot.name;
            document.getElementById('profile-bot-avatar').src = bot.avatar || '/static/default-bot.png';
            document.getElementById('profile-bot-creator').textContent = `by ${bot.creator_name || 'System'}`;
            document.getElementById('profile-bot-desc').textContent = bot.description || 'No description provided.';
            
            const tagsEl = document.getElementById('profile-tags');
            tagsEl.innerHTML = bot.tags ? bot.tags.split(',').map(t => `<span class="bot-tag">${escapeHtml(t.trim())}</span>`).join('') : '';

            showView('bot-profile-view');
        }
    } catch (e) {
        showToast("Failed to load character profile", "error");
    }
}

// ===================================
// Chat Interaction
// ===================================

async function startNewChat() {
    if (!currentBotId || !currentUser) {
        if (!currentUser) showView('profile');
        return;
    }
    
    const token = localStorage.getItem(RP_TOKEN_KEY);
    try {
        const res = await fetch('/api/rp/chats', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ bot_id: currentBotId })
        });
        
        if (res.ok) {
            const chat = await res.json();
            loadChatHistory(chat.id);
        }
    } catch (e) {
        showToast("Failed to start chat", "error");
    }
}

async function loadChatHistory(chatId) {
    const token = localStorage.getItem(RP_TOKEN_KEY);
    currentChatId = chatId;
    
    try {
        const res = await fetch(`/api/rp/chats/${chatId}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (res.ok) {
            const chat = await res.json();
            currentChatMessages = chat.messages_parsed || []; // Use pre-parsed messages from backend
            currentBotId = chat.bot_id;
            
            document.getElementById('chat-bot-name').textContent = chat.bot_name;
            document.getElementById('chat-bot-avatar').src = chat.bot_avatar || '/static/default-bot.png';
            document.getElementById('chat-bot-creator').textContent = `by ${chat.bot_creator_name || 'System'}`;
            
            if (chat.wallpaper) applyWallpaper(chat.wallpaper);
            
            renderChatMessages();
            showView('chat-interface');
        }
    } catch (e) {
        showToast("Failed to load chat", "error");
    }
}

function renderChatMessages() {
    if (!chatMessagesContainer) return;
    
    if (currentChatMessages.length === 0) {
        chatMessagesContainer.innerHTML = '<div class="info-text" style="text-align:center; padding: 2rem;">Starting a new story...</div>';
        return;
    }
    
    const displayMsgs = currentChatMessages.filter(m => m.role !== 'system');
    
    chatMessagesContainer.innerHTML = displayMsgs.map(msg => {
        const isUser = msg.role === 'user';
        const wrapperClass = isUser ? 'msg-user' : 'msg-bot';
        
        let contentHtml = '';
        if (Array.isArray(msg.content)) {
            msg.content.forEach(part => {
                if (part.type === 'text') contentHtml += `<p>${formatTextMarkup(escapeHtml(part.text))}</p>`;
                else if (part.type === 'image_url') contentHtml += `<img src="${part.image_url.url}" class="attached-image">`;
            });
        } else {
            contentHtml = `<p>${formatTextMarkup(escapeHtml(msg.content))}</p>`;
        }
        
        return `
            <div class="chat-bubble ${wrapperClass}">
                ${contentHtml}
            </div>
        `;
    }).join('');
}

async function sendMessage() {
    if (isGenerating || !currentChatId) return;
    
    const input = document.getElementById('chat-input');
    const text = input.value.trim();
    if (!text && !pendingImageBase64) return;
    
    const token = localStorage.getItem(RP_TOKEN_KEY);
    
    let userMsg = { role: "user", content: text };
    if (pendingImageBase64) {
        userMsg.content = [
            { type: "text", text: text || " " },
            { type: "image_url", image_url: { url: pendingImageBase64 } }
        ];
    }
    
    currentChatMessages.push(userMsg);
    renderChatMessages();
    scrollToBottom();
    
    input.value = '';
    input.style.height = 'auto';
    removeImage();
    
    isGenerating = true;
    let fullResponse = "";
    
    try {
        const res = await fetch('/api/rp/chat/completions', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ chat_id: currentChatId, message: text })
        });
        
        if (!res.ok) throw new Error("Generation failed");
        
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        
        const botBubble = document.createElement('div');
        botBubble.className = 'chat-bubble msg-bot';
        botBubble.innerHTML = '<span class="typing-indicator">...</span>';
        chatMessagesContainer.appendChild(botBubble);
        scrollToBottom();
        
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            
            const chunk = decoder.decode(value);
            const lines = chunk.split('\n');
            for (let line of lines) {
                if (line.startsWith('data: ')) {
                    const dataStr = line.replace('data: ', '').trim();
                    if (!dataStr || dataStr === '[DONE]') continue;
                    try {
                        const parsed = JSON.parse(dataStr);
                        const content = parsed.choices[0].delta.content;
                        if (content) {
                            if (fullResponse === "") botBubble.innerHTML = "";
                            fullResponse += content;
                            botBubble.innerHTML = `<p>${formatTextMarkup(escapeHtml(fullResponse))}</p>`;
                            scrollToBottom();
                        }
                    } catch(e){}
                }
            }
        }
        
        currentChatMessages.push({ role: "assistant", content: fullResponse });
        await updateChatState();
        
    } catch (err) {
        showToast("Error during generation", "error");
    } finally {
        isGenerating = false;
    }
}

async function updateChatState() {
    if (!currentChatId) return;
    const token = localStorage.getItem(RP_TOKEN_KEY);
    await fetch(`/api/rp/chats/${currentChatId}`, {
        method: 'PUT',
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            messages: JSON.stringify(currentChatMessages),
            wallpaper: currentWallpaperBase64
        })
    });
}

// ===================================
// Forms & Modals
// ===================================

function openModal(id) {
    const m = document.getElementById(id);
    if (m) {
        m.classList.remove('hidden');
        m.classList.add('active');
    }
}

function closeModal(id) {
    const m = document.getElementById(id);
    if (m) {
        m.classList.remove('active');
        m.classList.add('hidden');
    }
}

async function handleBotSubmit(e) {
    e.preventDefault();
    const token = localStorage.getItem(RP_TOKEN_KEY);
    
    const payload = {
        name: document.getElementById('bot-name').value,
        avatar: pendingModalBase64.bot,
        description: document.getElementById('bot-description').value,
        personality: document.getElementById('bot-personality').value,
        lore: document.getElementById('bot-lore').value,
        tags: document.getElementById('bot-tags').value
    };

    try {
        const res = await fetch('/api/rp/bots', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });
        
        if (res.ok) {
            showToast('Character created!', 'success');
            e.target.reset();
            pendingModalBase64.bot = null;
            document.getElementById('bot-avatar-preview').classList.add('hidden');
            document.getElementById('bot-avatar-placeholder').classList.remove('hidden');
            showView('home');
        } else {
            const err = await res.json();
            showToast(err.detail || 'Creation failed', 'error');
        }
    } catch(err) {
        showToast('Network error', 'error');
    }
}

async function handleOcSubmit(e) {
    e.preventDefault();
    const token = localStorage.getItem(RP_TOKEN_KEY);
    
    const payload = {
        name: document.getElementById('oc-name').value,
        avatar: pendingModalBase64.oc,
        description: document.getElementById('oc-description').value,
        personality: document.getElementById('oc-personality').value
    };

    try {
        const res = await fetch('/api/rp/ocs', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        if (res.ok) {
            showToast('OC Persona Created!', 'success');
            closeModal('oc-modal');
            loadUserContent();
        }
    } catch(e){}
}

async function handleProfileSubmit(e) {
    e.preventDefault();
    const token = localStorage.getItem(RP_TOKEN_KEY);
    const payload = {
        username: document.getElementById('profile-username').value.trim(),
        avatar: pendingModalBase64.user || currentUser.avatar
    };

    try {
        const res = await fetch('/api/rp/profile', {
            method: 'PUT',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (res.ok) {
            showToast('Profile updated!', 'success');
            closeModal('profile-modal');
            await checkAuth();
        }
    } catch(e){}
}

// ===================================
// Admin Control Center
// ===================================

let currentAdminPassword = null;

function showAdminAuth() {
    openModal('admin-auth-modal');
}

async function handleAdminAuth(e) {
    e.preventDefault();
    const pw = document.getElementById('admin-password-input').value;
    try {
        const res = await fetch('/admin/config', { headers: { 'X-Admin-Password': pw } });
        if (res.ok) {
            currentAdminPassword = pw;
            closeModal('admin-auth-modal');
            showAdminDashboard();
        } else {
            showToast('Invalid Password', 'error');
        }
    } catch(e) { showToast('Auth Error', 'error'); }
}

async function showAdminDashboard() {
    if (!currentAdminPassword) return;
    openModal('admin-dashboard-modal');
    try {
        const res = await fetch('/admin/config', { headers: { 'X-Admin-Password': currentAdminPassword } });
        const cfg = await res.json();
        document.getElementById('admin-api-url').value = cfg.target_api_url || '';
        document.getElementById('admin-max-context').value = cfg.max_context || 4096;
        document.getElementById('admin-max-output').value = cfg.max_output_tokens || 1024;
        document.getElementById('admin-max-keys-ip').value = cfg.max_keys_per_ip || 20;
    } catch(e){}
}

async function handleAdminConfigSubmit(e) {
    e.preventDefault();
    const payload = {
        target_api_url: document.getElementById('admin-api-url').value,
        target_api_key: document.getElementById('admin-api-key').value,
        max_context: parseInt(document.getElementById('admin-max-context').value),
        max_output_tokens: parseInt(document.getElementById('admin-max-output').value),
        max_keys_per_ip: parseInt(document.getElementById('admin-max-keys-ip').value)
    };
    try {
        const res = await fetch('/admin/config', {
            method: 'PUT',
            headers: { 'X-Admin-Password': currentAdminPassword, 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (res.ok) {
            showToast('Config Updated', 'success');
            closeModal('admin-dashboard-modal');
        }
    } catch(e){}
}

// ===================================
// Utilities & Media
// ===================================

function showToast(msg, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const t = document.createElement('div');
    t.className = `toast ${type}`;
    t.textContent = msg;
    container.appendChild(t);
    setTimeout(() => t.remove(), 4000);
}

function escapeHtml(text) {
    if (!text) return "";
    const p = document.createElement('p');
    p.textContent = text;
    return p.innerHTML;
}

function fileToBase64(file) {
    return new Promise((r, j) => {
        const reader = new FileReader();
        reader.onload = () => r(reader.result);
        reader.onerror = j;
        reader.readAsDataURL(file);
    });
}

function handleAvatarChange(e, type) {
    const file = e.target.files[0];
    if (!file) return;
    fileToBase64(file).then(base64 => {
        pendingModalBase64[type] = base64;
        const preview = document.getElementById(`${type}-avatar-preview`) || document.getElementById('bot-avatar-preview');
        const placeholder = document.getElementById(`${type}-avatar-placeholder`) || document.getElementById('bot-avatar-placeholder');
        if (preview) {
            preview.src = base64;
            preview.classList.remove('hidden');
        }
        if (placeholder) placeholder.classList.add('hidden');
    });
}

function applyWallpaper(base64) {
    currentWallpaperBase64 = base64;
    document.getElementById('rp-background').style.backgroundImage = `url(${base64})`;
}

function loadSavedWallpaper() {
    const wp = localStorage.getItem('rp_wallpaper');
    if (wp) applyWallpaper(wp);
}

function triggerWallpaperUpload() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = 'image/*';
    input.onchange = (e) => {
        const file = e.target.files[0];
        if (file) {
            fileToBase64(file).then(base64 => {
                applyWallpaper(base64);
                if (currentChatId) updateChatState();
                else localStorage.setItem('rp_wallpaper', base64);
            });
        }
    };
    input.click();
}

function autoResizeTextarea(el) {
    el.style.height = 'auto';
    el.style.height = el.scrollHeight + 'px';
}

function scrollToBottom() {
    if (chatMessagesContainer) {
        chatMessagesContainer.scrollTop = chatMessagesContainer.scrollHeight;
    }
}

function formatTextMarkup(text) {
    if (!text) return '';
    return text.split('\n').join('<br>')
               .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
               .replace(/\*(.*?)\*/g, '<em>$1</em>');
}

function triggerChatAttachment() {
    document.getElementById('chat-attachment').click();
}

function handleChatAttachment(e) {
    const file = e.target.files[0];
    if (file) {
        fileToBase64(file).then(base64 => {
            pendingImageBase64 = base64;
            const prev = document.getElementById('image-preview');
            prev.src = base64;
            document.getElementById('image-preview-container').classList.remove('hidden');
        });
    }
}

function removeImage() {
    pendingImageBase64 = null;
    document.getElementById('image-preview-container').classList.add('hidden');
}

function handleChatKeydown(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
}

function triggerCardImport() {
    showToast('Legacy card import logic (PNG/JSON) is active.', 'info');
    document.getElementById('card-upload')?.click();
}

// Ensure character card logic remains if needed but simplified for Redesign
async function handleCardImport(e) {
    const file = e.target.files[0];
    if (!file) return;
    showToast('Processing character card...', 'info');
    // Simplified: in this version we just show the create view and let user fill info
    showView('create');
}
