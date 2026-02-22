/* Authentication Logic */

document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');

    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = loginForm.querySelector('button');
            const originalText = btn.innerHTML;

            // UI Loading State
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Authenticating...';
            btn.style.opacity = '0.7';

            try {
                // In a real app, we would gather form data here
                // const email = document.getElementById('email').value;
                // const password = document.getElementById('password').value;

                // Simulating Success for Demo
                setTimeout(() => {
                    localStorage.setItem('authToken', 'mock_token');
                    window.location.href = 'dashboard.html';
                }, 1500);

            } catch (error) {
                alert(error.message);
                btn.innerHTML = originalText;
                btn.style.opacity = '1';
            }
        });
    }

    if (registerForm) {
        registerForm.addEventListener('submit', (e) => {
            e.preventDefault();
            // similar logic...
            setTimeout(() => {
                window.location.href = 'login.html';
            }, 1500);
        });
    }

    // Check Auth on Dashboard pages
    // if (window.location.pathname.includes('dashboard.html')) {
    //     if (!localStorage.getItem('authToken')) {
    //         window.location.href = 'login.html';
    //     }
    // }
});