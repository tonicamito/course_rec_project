document.addEventListener('DOMContentLoaded', function() {
            console.log("✅ DOM fully loaded");
            
            // Password visibility toggle
            const passwordToggle = document.getElementById('passwordToggle');
            const passwordInput = document.getElementById('password');
            
            passwordToggle.addEventListener('click', function() {
                const isPassword = passwordInput.type === 'password';
                passwordInput.type = isPassword ? 'text' : 'password';
                this.classList.toggle('fa-eye');
                this.classList.toggle('fa-eye-slash');
            });
            
            // Form submission
            const loginForm = document.getElementById('loginForm');
            const loginButton = document.getElementById('loginButton');
            const loadingIndicator = document.getElementById('loadingIndicator');
            const errorAlert = document.getElementById('errorAlert');
            const successAlert = document.getElementById('successAlert');
            
            loginForm.addEventListener('submit', async function(e) {
                e.preventDefault();
                
                const username = document.getElementById('username').value.trim();
                const password = document.getElementById('password').value;
                
                // Clear previous alerts
                errorAlert.style.display = 'none';
                successAlert.style.display = 'none';
                
                // Basic validation
                if (!username || !password) {
                    showError('Please fill in all fields');
                    return;
                }
                
                try {
                    // Show loading state
                    loginButton.disabled = true;
                    loadingIndicator.style.display = 'block';
                    const buttonText = loginButton.querySelector('span');
                    if (buttonText) buttonText.textContent = 'Authenticating...';
                    
                    const response = await fetch('/login', {
                        method: 'POST',
                        headers: { 
                            'Content-Type': 'application/json',
                            'X-Requested-With': 'XMLHttpRequest'
                        },
                        body: JSON.stringify({ username, password }),
                        credentials: 'include'
                    });
                    
                    console.log("📡 Response status:", response.status);
                    
                    let data;
                    const contentType = response.headers.get('content-type');
                    if (contentType && contentType.includes('application/json')) {
                        data = await response.json();
                    } else {
                        console.error("❌ Unexpected response format:", await response.text());
                        throw new Error("Server returned non-JSON response");
                    }
                    
                    console.log("📦 Response JSON:", data);
                    
                    if (!response.ok) {
                        if (data.error) {
                            showError(data.error);
                        } else if (response.status === 401) {
                            showError('Invalid username or password');
                        } else if (response.status === 403) {
                            if (data.password_reset_required) {
                                showError('Password reset required. Please check your email.');
                            } else {
                                showError('Account not verified. Please check your email.');
                            }
                        } else {
                            showError('Login failed. Please try again.');
                        }
                        return;
                    }
                    
                    // Successful login
                    if (data.token) {
                        sessionStorage.setItem('auth_token', data.token);
                    }
                    
                    // Show success message and redirect
                    showSuccess('Login successful! Redirecting...');
                    
                    // Redirect after a short delay
                    setTimeout(() => {
                        if (data.user_info && data.user_info.is_admin) {
                            window.location.href = '/admin';
                        } else {
                            window.location.href = '/index';
                        }
                    }, 1500);
                    
                } catch (error) {
                    console.error('Login error:', error);
                    showError('Connection error. Please try again.');
                } finally {
                    // Reset UI state
                    loginButton.disabled = false;
                    const buttonText = loginButton.querySelector('span');
                    if (buttonText) buttonText.textContent = 'Sign In';
                    loadingIndicator.style.display = 'none';
                    document.getElementById('password').value = '';
                }
            });
            
            // Show error message
            function showError(message) {
                const errorMessage = document.getElementById('errorAlert');
                if (errorMessage) {
                    errorMessage.textContent = message;
                }
                errorAlert.style.display = 'flex';
                errorAlert.classList.add('error-shake');
                
                setTimeout(() => {
                    errorAlert.classList.remove('error-shake');
                }, 600);
            }
            
            // Show success message
            function showSuccess(message) {
                const successMessage = document.getElementById('successAlert');
                if (successMessage) {
                    successMessage.textContent = message;
                }
                successAlert.style.display = 'flex';
            }
        });