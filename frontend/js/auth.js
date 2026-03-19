// API Config
const API_BASE = 'http://localhost:8000/api/v1';

document.addEventListener('DOMContentLoaded', () => {
    // ─── Credential Token Login (from issued credential email) ──────────────
    const urlParams = new URLSearchParams(window.location.search);
    const credToken = urlParams.get('token');
    if (credToken && document.getElementById('loginForm')) {
        _handleCredentialTokenLogin(credToken);
    }

    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');

    // Handle Login Flow
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = loginForm.querySelector('button[type="submit"]');
            const originalText = btn.innerHTML;

            // Clear any previous error messages
            clearStatusMessage();

            // UI Loading State
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Authenticating...';
            btn.style.opacity = '0.7';

            try {
                // Get email and password from standard DOM elements
                const inputs = loginForm.querySelectorAll('input');
                let username = '';
                let password = '';

                inputs.forEach(input => {
                    if (input.type === 'email' || (input.type === 'text' && input.placeholder.toLowerCase().includes('email'))) {
                        username = input.value;
                    }
                    if (input.type === 'password') {
                        password = input.value;
                    }
                });

                if (!username || !password) {
                    throw new Error("Please fill out all required fields.");
                }

                // Call local backend login endpoint
                const formData = new URLSearchParams();
                formData.append('username', username);
                formData.append('password', password);

                const response = await fetch(`${API_BASE}/auth/login`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: formData
                });

                if (!response.ok) {
                    const err = await response.json();
                    const detail = err.detail || "Authentication Failed";

                    // Handle specific status codes with styled messages
                    if (response.status === 403) {
                        showStatusMessage(detail, 'warning');
                        btn.innerHTML = originalText;
                        btn.style.opacity = '1';
                        return;
                    }
                    throw new Error(detail);
                }

                const data = await response.json();

                // Save Token
                localStorage.setItem('access_token', data.access_token);
                localStorage.setItem('authToken', data.access_token);

                // Fetch user details to store role, clearance, and admin status
                const userResp = await fetch(`${API_BASE}/users/me`, {
                    headers: {
                        'Authorization': `Bearer ${data.access_token}`
                    }
                });

                if (userResp.ok) {
                    const userData = await userResp.json();
                    localStorage.setItem('userRole', userData.role || '');
                    localStorage.setItem('clearanceLevel', userData.clearance_level || '');
                    localStorage.setItem('userEmail', userData.email || '');

                    if (userData.role === "SUPER_ADMIN" || userData.role === "ADMIN") {
                        localStorage.setItem('isAdmin', 'true');
                    } else {
                        localStorage.removeItem('isAdmin');
                    }
                }

                window.location.href = 'dashboard.html';

            } catch (error) {
                showStatusMessage(error.message, 'error');
                btn.innerHTML = originalText;
                btn.style.opacity = '1';
            }
        });
    }

    // Developer Bypass Login
    const devBypassBtn = document.getElementById('devBypassBtn');
    if (devBypassBtn) {
        devBypassBtn.addEventListener('click', async () => {
            const originalText = devBypassBtn.innerHTML;
            devBypassBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Bypassing...';
            devBypassBtn.style.opacity = '0.7';

            try {
                const response = await fetch(`${API_BASE}/auth/dev-bypass`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });

                if (!response.ok) {
                    throw new Error("Bypass Failed. Ensure backend is running.");
                }

                const data = await response.json();

                localStorage.setItem('access_token', data.access_token);
                localStorage.setItem('authToken', data.access_token);
                localStorage.setItem('isAdmin', 'true');
                localStorage.setItem('userRole', 'SUPER_ADMIN');
                localStorage.setItem('clearanceLevel', '3');

                window.location.href = 'dashboard.html';
            } catch (error) {
                showStatusMessage("Developer Bypass Error: " + error.message, 'error');
                devBypassBtn.innerHTML = originalText;
                devBypassBtn.style.opacity = '1';
            }
        });
    }

    // Handle Registration Flow
    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = registerForm.querySelector('button[type="submit"]');
            const originalText = btn.innerHTML;

            // Clear any previous messages
            clearStatusMessage();

            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Requesting Access...';
            btn.style.opacity = '0.7';

            try {
                // Read all fields by ID
                const username = document.getElementById('regUsername')?.value?.trim();
                const firstName = document.getElementById('regFirstName')?.value?.trim();
                const lastName = document.getElementById('regLastName')?.value?.trim();
                const email = document.getElementById('regEmail')?.value?.trim();
                const department = document.getElementById('regDepartment')?.value || '';
                const clearanceLevel = parseInt(document.getElementById('regClearanceLevel')?.value || '1');
                const password = document.getElementById('regPassword')?.value;

                if (!username || !email || !password) {
                    throw new Error("Please fill out all required fields.");
                }

                if (password.length < 12) {
                    throw new Error("Passphrase must be at least 12 characters.");
                }

                const response = await fetch(`${API_BASE}/auth/register`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        username: username,
                        email: email,
                        password: password,
                        first_name: firstName || '',
                        last_name: lastName || '',
                        department: department,
                        clearance_level: clearanceLevel
                    })
                });

                if (!response.ok) {
                    const err = await response.json();
                    throw new Error(err.detail || "Registration Failed");
                }

                const data = await response.json();

                // Show success message with pending approval info
                showStatusMessage(
                    data.message || "Registration successful! Your account is pending admin approval.",
                    'success'
                );

                // Redirect to login after a delay
                setTimeout(() => {
                    window.location.href = 'login.html';
                }, 3000);

            } catch (error) {
                showStatusMessage(error.message, 'error');
                btn.innerHTML = originalText;
                btn.style.opacity = '1';
            }
        });
    }

    // Auth Guard Check for protected pages
    checkAuthGuard();
});

// ─── Inline Status Messages (styled, non-intrusive) ─────────────────────────

function showStatusMessage(message, type = 'error') {
    clearStatusMessage();

    const msgDiv = document.createElement('div');
    msgDiv.id = 'authStatusMessage';
    msgDiv.style.cssText = `
        margin-top: 20px;
        padding: 16px 20px;
        border-radius: 8px;
        font-size: 0.9rem;
        font-family: 'Outfit', sans-serif;
        display: flex;
        align-items: center;
        gap: 12px;
        animation: fadeSlideIn 0.3s ease;
    `;

    let icon, borderColor, bgColor, textColor;

    switch (type) {
        case 'warning':
            icon = 'fas fa-clock';
            borderColor = '#f59e0b';
            bgColor = 'rgba(245, 158, 11, 0.08)';
            textColor = '#f59e0b';
            break;
        case 'success':
            icon = 'fas fa-check-circle';
            borderColor = '#10b981';
            bgColor = 'rgba(16, 185, 129, 0.08)';
            textColor = '#10b981';
            break;
        case 'error':
        default:
            icon = 'fas fa-exclamation-triangle';
            borderColor = '#ef4444';
            bgColor = 'rgba(239, 68, 68, 0.08)';
            textColor = '#ef4444';
            break;
    }

    msgDiv.style.border = `1px solid ${borderColor}`;
    msgDiv.style.background = bgColor;
    msgDiv.style.color = textColor;
    msgDiv.innerHTML = `<i class="${icon}"></i> <span>${message}</span>`;

    // Insert after the form
    const form = document.getElementById('loginForm') || document.getElementById('registerForm');
    if (form) {
        form.parentNode.insertBefore(msgDiv, form.nextSibling);
    }

    // Add animation keyframes if not present
    if (!document.getElementById('authAnimationStyle')) {
        const style = document.createElement('style');
        style.id = 'authAnimationStyle';
        style.textContent = `
            @keyframes fadeSlideIn {
                from { opacity: 0; transform: translateY(-8px); }
                to { opacity: 1; transform: translateY(0); }
            }
        `;
        document.head.appendChild(style);
    }
}

function clearStatusMessage() {
    const existing = document.getElementById('authStatusMessage');
    if (existing) existing.remove();
}

// ─── Credential Token Login ──────────────────────────────────────────────────

async function _handleCredentialTokenLogin(token) {
    const loginPane = document.querySelector('.login-pane') || document.body;
    const existingForm = document.getElementById('loginForm');

    // Validate token with backend first
    try {
        const res = await fetch(`${API_BASE}/credentials/token/${token}`);
        const data = await res.json();

        if (!data.valid) {
            showStatusMessage(`Token error: ${data.reason || 'Invalid or expired token'}`, 'error');
            return;
        }

        // Token is valid — replace login form with a "Set New Password" form
        if (existingForm) existingForm.style.display = 'none';

        const div = document.createElement('div');
        div.id = 'tokenLoginBox';
        div.innerHTML = `
            <div style="background:rgba(0,198,255,0.08);border:1px solid #00c6ff;border-radius:6px;padding:18px 20px;margin-bottom:28px;">
                <div style="color:#00c6ff;font-size:0.8rem;font-weight:700;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;">
                    <i class="fas fa-key"></i> Credential Token Detected
                </div>
                <div style="color:#ccc;font-size:0.9rem;">Welcome, <strong style="color:#fff">${data.username}</strong>. Set your new password to activate your account.</div>
            </div>
            <form id="tokenLoginForm">
                <div class="input-group">
                    <label>New Password</label>
                    <input type="password" id="newPassInput" class="clean-input" placeholder="Minimum 8 characters" required>
                </div>
                <div class="input-group">
                    <label>Confirm Password</label>
                    <input type="password" id="confirmPassInput" class="clean-input" placeholder="••••••••••••" required>
                </div>
                <button type="submit" class="btn-clean">Activate Account & Sign In</button>
            </form>`;

        const loginHeader = document.querySelector('.login-header');
        if (loginHeader) loginHeader.insertAdjacentElement('afterend', div);
        else loginPane.prepend(div);

        document.getElementById('tokenLoginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const np = document.getElementById('newPassInput').value;
            const cp = document.getElementById('confirmPassInput').value;
            const btn = e.target.querySelector('button');

            if (np.length < 8) { showStatusMessage('Password must be at least 8 characters.', 'error'); return; }
            if (np !== cp) { showStatusMessage('Passwords do not match.', 'error'); return; }

            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Activating...';
            btn.style.opacity = '0.7';

            try {
                // Activate account: set new password via credential token
                const activateRes = await fetch(`${API_BASE}/auth/activate-account`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ credential_token: token, new_password: np })
                });
                if (!activateRes.ok) {
                    const err = await activateRes.json();
                    throw new Error(err.detail || 'Account activation failed');
                }
                const loginData = await activateRes.json();
                localStorage.setItem('access_token', loginData.access_token);
                localStorage.setItem('authToken', loginData.access_token);
                localStorage.setItem('userRole', loginData.user?.role || '');
                if (['SUPER_ADMIN','ADMIN'].includes(loginData.user?.role)) localStorage.setItem('isAdmin','true');
                window.location.href = 'dashboard.html';
            } catch (err) {
                showStatusMessage(err.message, 'error');
                btn.innerHTML = 'Activate Account & Sign In';
                btn.style.opacity = '1';
            }
        });
    } catch (e) {
        // Token fetch failed — just show login normally
    }
}

// ─── Forgot Password Handler ─────────────────────────────────────────────────

const forgotForm = document.getElementById('forgotForm');
if (forgotForm) {
    forgotForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const btn = forgotForm.querySelector('button[type="submit"]');
        const email = document.getElementById('forgotEmail')?.value?.trim();
        if (!email) return;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Sending...';
        btn.style.opacity = '0.7';
        try {
            await fetch(`${API_BASE}/auth/forgot-password`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email })
            });
            document.getElementById('forgotStep1').style.display = 'none';
            document.getElementById('forgotSuccess').style.display = 'block';
        } catch {
            showStatusMessage('Failed to send reset email. Try again.', 'error');
            btn.innerHTML = 'Send Reset Link';
            btn.style.opacity = '1';
        }
    });
}

const resetForm = document.getElementById('resetForm');
if (resetForm) {
    resetForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const btn = resetForm.querySelector('button[type="submit"]');
        const token = new URLSearchParams(window.location.search).get('token');
        const np = document.getElementById('resetNewPass')?.value;
        const cp = document.getElementById('resetConfirmPass')?.value;
        if (np !== cp) { showStatusMessage('Passwords do not match.', 'error'); return; }
        if (np.length < 8) { showStatusMessage('Password must be at least 8 characters.', 'error'); return; }
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Resetting...';
        btn.style.opacity = '0.7';
        try {
            const res = await fetch(`${API_BASE}/auth/reset-password`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token, new_password: np })
            });
            if (!res.ok) { const e = await res.json(); throw new Error(e.detail || 'Reset failed'); }
            document.getElementById('resetStep').style.display = 'none';
            document.getElementById('resetSuccess').style.display = 'block';
            setTimeout(() => window.location.href = 'login.html', 2500);
        } catch (err) {
            showStatusMessage(err.message, 'error');
            btn.innerHTML = 'Set New Password';
            btn.style.opacity = '1';
        }
    });
}

// ─── Auth Guard ─────────────────────────────────────────────────────────────

async function checkAuthGuard() {
    // If not on login/register pages, enforce session existence
    const path = window.location.pathname;
    const isPublicPage = path.includes('login.html') || path.includes('register.html') || path.includes('index.html') || path.includes('forgot_password.html') || path.includes('admin_login.html') || path.endsWith('/');

    if (!isPublicPage) {
        const token = localStorage.getItem('access_token');

        if (!token) {
            console.warn("No active session found. Redirecting to login.");
            window.location.href = 'login.html';
            return;
        }

        try {
            // Verify token with backend
            const response = await fetch(`${API_BASE}/users/me`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (!response.ok) {
                throw new Error("Invalid session");
            }

            // Update stored user info on every page load
            const userData = await response.json();
            localStorage.setItem('userRole', userData.role || '');
            localStorage.setItem('clearanceLevel', userData.clearance_level || '');

            const isAdminRole = userData.role === 'SUPER_ADMIN' || userData.role === 'ADMIN';
            if (isAdminRole) {
                localStorage.setItem('isAdmin', 'true');
            } else {
                localStorage.removeItem('isAdmin');
            }
        } catch (e) {
            console.warn("Session verification failed. Redirecting to login.");
            localStorage.removeItem('access_token');
            localStorage.removeItem('authToken');
            localStorage.removeItem('isAdmin');
            localStorage.removeItem('userRole');
            localStorage.removeItem('clearanceLevel');
            window.location.href = 'login.html';
        }
    }
}