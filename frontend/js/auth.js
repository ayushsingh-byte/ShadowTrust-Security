// API Config
const API_BASE = 'http://localhost:8000/api/v1';

document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');

    // Handle Login Flow
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = loginForm.querySelector('button');
            const originalText = btn.innerHTML;

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
                    throw new Error(err.detail || "Authentication Failed");
                }

                const data = await response.json();

                // Save Token
                localStorage.setItem('access_token', data.access_token);
                localStorage.setItem('authToken', data.access_token);

                // We can fetch user details right away to store admin status
                const userResp = await fetch(`${API_BASE}/users/me`, {
                    headers: {
                        'Authorization': `Bearer ${data.access_token}`
                    }
                });

                if (userResp.ok) {
                    const userData = await userResp.json();
                    if (userData.role === "SUPER_ADMIN" || userData.role === "ADMIN") {
                        localStorage.setItem('isAdmin', 'true');
                    } else {
                        localStorage.removeItem('isAdmin');
                    }
                }

                window.location.href = 'dashboard.html';

            } catch (error) {
                alert("Login Failed: " + error.message);
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

                window.location.href = 'dashboard.html';
            } catch (error) {
                alert("Developer Bypass Error: " + error.message);
                devBypassBtn.innerHTML = originalText;
                devBypassBtn.style.opacity = '1';
            }
        });
    }

    // Handle Registration Flow
    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = registerForm.querySelector('button');
            const originalText = btn.innerHTML;

            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Requesting Access...';
            btn.style.opacity = '0.7';

            try {
                const inputs = registerForm.querySelectorAll('input');
                let email = '';
                let password = '';
                let fullName = '';

                inputs.forEach(input => {
                    if (input.type === 'email' || (input.placeholder && input.placeholder.toLowerCase().includes('email'))) email = input.value;
                    if (input.type === 'password') password = input.value;
                    if (input.type === 'text' && input.placeholder && input.placeholder.toLowerCase().includes('name')) fullName = input.value;
                });

                if (!email || !password) {
                    throw new Error("Please fill out all required fields.");
                }

                // Basic separation of full name into first/last
                const nameParts = fullName.split(' ');
                const firstName = nameParts[0] || '';
                const lastName = nameParts.length > 1 ? nameParts.slice(1).join(' ') : '';

                const response = await fetch(`${API_BASE}/auth/register`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        email: email,
                        password: password,
                        username: email, // Using email as username
                        first_name: firstName,
                        last_name: lastName
                    })
                });

                if (!response.ok) {
                    const err = await response.json();
                    throw new Error(err.detail || "Registration Failed");
                }

                alert("Registration successful! Please login.");
                window.location.href = 'login.html';

            } catch (error) {
                alert("Registration Failed: " + error.message);
                btn.innerHTML = originalText;
                btn.style.opacity = '1';
            }
        });
    }

    // Auth Guard Check for protected pages
    checkAuthGuard();
});

async function checkAuthGuard() {
    // If not on login/register pages, enforce session existence
    const path = window.location.pathname;
    const isPublicPage = path.includes('login.html') || path.includes('register.html') || path.includes('index.html') || path.endsWith('/');

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
        } catch (e) {
            console.warn("Session verification failed. Redirecting to login.");
            localStorage.removeItem('access_token');
            localStorage.removeItem('authToken');
            window.location.href = 'login.html';
        }
    }
}