window.onload = function () {
    const registerForm = document.getElementById("registerForm");

    if (registerForm) {
        registerForm.addEventListener("submit", async function (e) {
            e.preventDefault();

            const firstName = document.getElementById('firstName').value.trim();
            const lastName = document.getElementById('lastName').value.trim();
            const username = document.getElementById('username').value.trim();
            const email = document.getElementById('email').value.trim();
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            const educationLevel = document.getElementById('educationLevel').value;
            const termsAgreement = document.getElementById('termsAgreement').checked;

            const errorMessage = document.getElementById('errorMessage');
            const successMessage = document.getElementById('successMessage');
            const loading = document.querySelector('.loading');
            const registerButton = document.querySelector('.btn-register');

            // Reset messages
            errorMessage.style.display = 'none';
            successMessage.style.display = 'none';

            // Validation checks
            if (!firstName || !lastName || !username || !email || !password || !educationLevel) {
                errorMessage.textContent = 'Please fill in all fields.';
                errorMessage.style.display = 'block';
                return;
            }

            if (password !== confirmPassword) {
                errorMessage.textContent = 'Passwords do not match';
                errorMessage.style.display = 'block';
                return;
            }

            if (!termsAgreement) {
                errorMessage.textContent = 'You must agree to the Terms of Service and Privacy Policy';
                errorMessage.style.display = 'block';
                return;
            }

            // Show loading spinner
            loading.style.display = 'block';
            registerButton.disabled = true;

            try {
                const response = await fetch('/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        firstName,
                        lastName,
                        username,
                        email,
                        password,
                        confirmPassword,
                        educationLevel
                    })
                });

                const data = await response.json();

                // Hide loading spinner
                loading.style.display = 'none';
                registerButton.disabled = false;

                if (response.ok) {
                    successMessage.textContent = 'Registration successful! Please check your email to verify your account.';
                    successMessage.style.display = 'block';
                    

                    // Clear form
                    registerForm.reset();

                    
                } else {
                    errorMessage.textContent = data.error || 'Registration failed. Please try again.';
                    errorMessage.style.display = 'block';
                }
            } catch (error) {
                // Hide loading spinner
                loading.style.display = 'none';
                registerButton.disabled = false;

                // Show error message
                errorMessage.textContent = 'Connection error. Please try again.';
                errorMessage.style.display = 'block';
                console.error('Registration error:', error);
            }
        });
    } else {
        console.error("Error: 'registerForm' not found. Make sure the script is loaded after the form.");
    }

    // Password visibility toggle
    document.querySelectorAll('.password-toggle').forEach(toggle => {
        toggle.addEventListener('click', function () {
            const passwordInput = this.previousElementSibling;
            passwordInput.type = passwordInput.type === 'password' ? 'text' : 'password';
            this.classList.toggle('fa-eye');
            this.classList.toggle('fa-eye-slash');
        });
    });

    // Username availability check
    const usernameField = document.getElementById('username');
    if (usernameField) {
        usernameField.addEventListener('blur', function () {
            const username = this.value;
            const usernameStatus = document.getElementById('usernameStatus');

            if (username.length < 3) {
                usernameStatus.textContent = 'Username must be at least 3 characters';
                usernameStatus.style.color = '#ff6b6b';
                return;
            }

            // Simulate username availability check
            setTimeout(() => {
                // Replace this with an actual API call
                const isAvailable = Math.random() > 0.3; // Random availability for demo

                if (isAvailable) {
                    usernameStatus.textContent = 'Username available';
                    usernameStatus.style.color = '#28a745';
                } else {
                    usernameStatus.textContent = 'Username already taken';
                    usernameStatus.style.color = '#ff6b6b';
                }
            }, 500);
        });
    }

    // Password strength checker
    const passwordField = document.getElementById('password');
    if (passwordField) {
        passwordField.addEventListener('input', function () {
            const password = this.value;
            const strengthBar = document.getElementById('passwordStrengthBar');
            const strengthText = document.getElementById('passwordStrengthText');

            // Calculate password strength
            let strength = 0;
            if (password.length >= 8) strength += 25;
            if (password.match(/[a-z]/) && password.match(/[A-Z]/)) strength += 25;
            if (password.match(/\d/)) strength += 25;
            if (password.match(/[^a-zA-Z\d]/)) strength += 25;

            // Update strength bar
            strengthBar.style.width = strength + '%';

            // Update strength text and color
            if (strength < 25) {
                strengthBar.style.backgroundColor = '#ff6b6b';
                strengthText.textContent = 'Very Weak';
                strengthText.style.color = '#ff6b6b';
            } else if (strength < 50) {
                strengthBar.style.backgroundColor = '#ffaa71';
                strengthText.textContent = 'Weak';
                strengthText.style.color = '#ffaa71';
            } else if (strength < 75) {
                strengthBar.style.backgroundColor = '#ffd700';
                strengthText.textContent = 'Medium';
                strengthText.style.color = '#ffd700';
            } else {
                strengthBar.style.backgroundColor = '#28a745';
                strengthText.textContent = 'Strong';
                strengthText.style.color = '#28a745';
            }
        });
    }

    // Password match checker
    const confirmPasswordField = document.getElementById('confirmPassword');
    if (confirmPasswordField) {
        confirmPasswordField.addEventListener('input', function () {
            const password = document.getElementById('password').value;
            const confirmPassword = this.value;
            const passwordMatch = document.getElementById('passwordMatch');

            if (confirmPassword === '') {
                passwordMatch.textContent = '';
            } else if (password === confirmPassword) {
                passwordMatch.textContent = 'Passwords match';
                passwordMatch.style.color = '#28a745';
            } else {
                passwordMatch.textContent = 'Passwords do not match';
                passwordMatch.style.color = '#ff6b6b';
            }
        });
    }
};

