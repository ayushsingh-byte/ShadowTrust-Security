// Initialize Supabase Client
const SUPABASE_URL = 'https://nghuctaefsoanxxujtpg.supabase.co';
// Note: In a production environment with sensitive data, the Anon Key should be used on the frontend, not the Service Role key.
// Using the provided key for the prototype connection.
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5naHVjdGFlZnNvYW54eHVqdHBnIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3MDcyODY2NCwiZXhwIjoyMDg2MzA0NjY0fQ.8JkbpyXTBMuOMIXskfPy8CVHjK_nBBUoFk-8CUhA5Eg';

const supabaseClient = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY);

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
                // Assuming the first type="text" or "email" is email, and type="password" is password.
                const inputs = loginForm.querySelectorAll('input');
                let email = '';
                let password = '';

                inputs.forEach(input => {
                    if (input.type === 'email' || (input.type === 'text' && input.placeholder.toLowerCase().includes('email'))) {
                        email = input.value;
                    }
                    if (input.type === 'password') {
                        password = input.value;
                    }
                });

                // Bypass Authentication
                localStorage.setItem('access_token', 'mock_token');
                localStorage.setItem('authToken', 'mock_token');

                // Explicitly strip admin flag on normal login
                localStorage.removeItem('isAdmin');

                window.location.href = 'dashboard.html';

            } catch (error) {
                alert("Login Failed: " + error.message);
                btn.innerHTML = originalText;
                btn.style.opacity = '1';
            }
        });
    }

    // Handle Registration / OTP Flow
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

                // Register with Supabase
                const { data, error } = await supabaseClient.auth.signUp({
                    email: email,
                    password: password,
                    options: {
                        data: {
                            full_name: fullName,
                        }
                    }
                });

                if (error) {
                    throw error;
                }

                alert("Registration successful! Please check your email for the confirmation OPT/Link.");
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
    if (!path.includes('login.html') && !path.includes('register.html') && !path.includes('index.html') && !path.endsWith('/')) {
        const { data: { session } } = await supabaseClient.auth.getSession();

        if (!session && !localStorage.getItem('access_token')) {
            console.warn("No active Supabase session or fallback token found. Redirecting to login.");
            window.location.href = 'login.html';
        } else if (session) {
            // keep legacy token updated
            localStorage.setItem('access_token', session.access_token);
            localStorage.setItem('authToken', session.access_token);
        }
    }
}