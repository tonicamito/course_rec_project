document.addEventListener('DOMContentLoaded', function() {
    // Initialize password toggles
    document.querySelectorAll('.password-toggle').forEach(toggle => {
        toggle.addEventListener('click', function() {
            const passwordInput = this.previousElementSibling;
            passwordInput.type = passwordInput.type === 'password' ? 'text' : 'password';
            this.classList.toggle('fa-eye');
            this.classList.toggle('fa-eye-slash');
        });
    });

    // Get token from URL
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    
    // DEBUG: Log the current URL and token
    console.log('Current URL:', window.location.href);
    console.log('Token from URL:', token);
    console.log('All URL parameters:', Object.fromEntries(urlParams));
    
    const tokenExpiredDiv = document.getElementById('tokenExpired');
    const resetPasswordFormDiv = document.getElementById('resetPasswordForm');
    const passwordResetForm = document.getElementById('passwordResetForm');
    
    // If no token is provided, show token expired message
    if (!token) {
        console.log('No token found in URL - showing expired message');
        tokenExpiredDiv.style.display = 'block';
        resetPasswordFormDiv.style.display = 'none';
        return;
    }
    
    console.log('Token found, proceeding to verify...');
    
    // First verify if token is valid
    verifyToken(token);
    
    // Password strength meter
    const passwordInput = document.getElementById('password');
    const passwordStrengthMeter = document.getElementById('passwordStrengthMeter');
    const passwordStrengthText = document.getElementById('passwordStrengthText');
    
    passwordInput.addEventListener('input', function() {
        const password = this.value;
        const strength = checkPasswordStrength(password);
        
        // Remove all classes
        passwordStrengthMeter.className = 'password-strength-meter';
        
        // Add class based on strength
        if (password.length > 0) {
            if (strength >= 80) {
                passwordStrengthMeter.classList.add('very-strong');
                passwordStrengthText.textContent = 'Very Strong';
            } else if (strength >= 60) {
                passwordStrengthMeter.classList.add('strong');
                passwordStrengthText.textContent = 'Strong';
            } else if (strength >= 40) {
                passwordStrengthMeter.classList.add('medium');
                passwordStrengthText.textContent = 'Medium';
            } else {
                passwordStrengthMeter.classList.add('weak');
                passwordStrengthText.textContent = 'Weak';
            }
        } else {
            passwordStrengthText.textContent = 'Password strength';
        }
    });
    
    if (passwordResetForm) {
        passwordResetForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            const errorMessage = document.getElementById('errorMessage');
            const successMessage = document.getElementById('successMessage');
            const submitButton = this.querySelector('button[type="submit"]');
            const loadingSpinner = document.querySelector('.loading');
            
            // Clear previous messages
            errorMessage.style.display = 'none';
            successMessage.style.display = 'none';
            
            // Validation
            if (!password || !confirmPassword) {
                errorMessage.textContent = 'Please fill in all fields';
                errorMessage.style.display = 'block';
                return;
            }
            
            if (password !== confirmPassword) {
                errorMessage.textContent = 'Passwords do not match';
                errorMessage.style.display = 'block';
                return;
            }
            
            // Password strength validation
            const strength = checkPasswordStrength(password);
            if (strength < 40) {
                errorMessage.textContent = 'Password is too weak. Include uppercase, lowercase, numbers, and special characters.';
                errorMessage.style.display = 'block';
                return;
            }
            
            try {
                // Disable button and show loading spinner
                submitButton.disabled = true;
                loadingSpinner.style.display = 'block';
                
                const response = await fetch(`/api/reset-password?token=${encodeURIComponent(token)}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password })
                });
                if (response.status === 404) {
                    errorMessage.textContent = 'User account not found';
                    errorMessage.style.display = 'block';
                    return;
                }
                
                const data = await response.json();
                
                if (response.ok) {
                    successMessage.textContent = 'Password reset successful! Redirecting to login...';
                    successMessage.style.display = 'block';
                    
                    // Clear the form
                    passwordResetForm.reset();
                    
                    // Redirect to login page after 3 seconds
                    setTimeout(() => {
                        window.location.href = '/login';
                    }, 3000);
                } else {
                    if (!response.ok) {
                        if (data.error === 'Token has expired') {
                            showTokenExpired();
                        } else if (data.error === 'Invalid token') {
                            errorMessage.textContent = 'Invalid security token';
                            errorMessage.style.display = 'block';
                        } else {
                            errorMessage.textContent = data.error || 'An error occurred';
                            errorMessage.style.display = 'block';
                        }
                    }
                }
            } catch (error) {
                console.error('Error:', error);
                errorMessage.textContent = 'Connection error. Please try again.';
                errorMessage.style.display = 'block';
            } finally {
                // Re-enable button and hide loading spinner
                submitButton.disabled = false;
                loadingSpinner.style.display = 'none';
            }
        });
    }
    
    // Function to check password strength
    function checkPasswordStrength(password) {
        // Initialize score
        let score = 0;
        
        // If password is empty, return 0
        if (password.length === 0) {
            return 0;
        }
        
        // Award points for length
        if (password.length >= 8) {
            score += 20;
        } else {
            return 10; // Very weak if less than 8 characters
        }
        
        // Award points for complexity
        if (/[a-z]/.test(password)) score += 10; // lowercase
        if (/[A-Z]/.test(password)) score += 20; // uppercase
        if (/[0-9]/.test(password)) score += 20; // numbers
        if (/[^a-zA-Z0-9]/.test(password)) score += 30; // special characters
        
        return score;
    }
    
    
        // Function to verify token validity
        // Complete function to verify token validity with comprehensive error handling
    async function verifyToken(token) {
        const tokenExpiredDiv = document.getElementById('tokenExpired');
        const resetPasswordFormDiv = document.getElementById('resetPasswordForm');
        const expirationTimeElement = document.getElementById('expirationTime');
        
        // Validate token format first (basic validation)
        if (!token || token.length < 10) {
            console.error('Invalid token format:', token);
            showTokenExpired();
            return false;
        }
        
        try {
            console.log('Verifying token:', token);
            
            // Construct API URL
            const apiUrl = `/api/verify-reset-token?token=${encodeURIComponent(token)}`;
            console.log('Making request to:', apiUrl);
            
            // Make the API request with timeout
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout
            
            const response = await fetch(apiUrl, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            
            console.log('Response status:', response.status);
            console.log('Response headers:', response.headers);
            
            // Handle different HTTP status codes
            if (response.status === 404) {
                console.error('Token verification endpoint not found');
                showGenericError('The password reset service is currently unavailable. Please try again later.');
                return false;
            }
            
            if (response.status === 500) {
                console.error('Server error during token verification');
                showGenericError('Server error occurred. Please try again later.');
                return false;
            }
            
            // Parse response
            let data;
            try {
                data = await response.json();
            } catch (parseError) {
                console.error('Error parsing response JSON:', parseError);
                showGenericError('Invalid server response. Please try again.');
                return false;
            }
            
            console.log('Response data:', data);
            
            // Handle successful response
            if (response.ok && response.status === 200) {
                console.log('Token verification successful');
                
                // Show the reset form
                if (tokenExpiredDiv) tokenExpiredDiv.style.display = 'none';
                if (resetPasswordFormDiv) resetPasswordFormDiv.style.display = 'block';
                
                // Handle expiration time display
                if (data.expiration && expirationTimeElement) {
                    try {
                        const expirationDate = new Date(data.expiration);
                        
                        // Validate the date
                        if (isNaN(expirationDate.getTime())) {
                            console.warn('Invalid expiration date format:', data.expiration);
                        } else {
                            // Check if token is expired based on server time
                            const now = new Date();
                            const timeRemaining = expirationDate.getTime() - now.getTime();
                            
                            if (timeRemaining <= 0) {
                                console.log('Token has expired according to expiration time');
                                showTokenExpired();
                                return false;
                            }
                            
                            const expiresAt = expirationDate.toLocaleString();
                            expirationTimeElement.textContent = `Link expires: ${expiresAt}`;
                            
                            // Optional: Show warning if expiring soon (less than 5 minutes)
                            if (timeRemaining < 5 * 60 * 1000) {
                                expirationTimeElement.style.color = '#ff6b6b';
                                expirationTimeElement.textContent += ' (Expires soon!)';
                            }
                        }
                    } catch (dateError) {
                        console.error('Error processing expiration date:', dateError);
                    }
                }
                
                // Additional success data handling
                if (data.user_email) {
                    console.log('Reset request for email:', data.user_email);
                    // You could display this to user for confirmation
                }
                
                return true;
                
            } else {
                // Handle error responses
                console.error('Token verification failed:', data);
                
                // Handle specific error types
                if (data.error) {
                    const errorMsg = data.error.toLowerCase();
                    
                    if (errorMsg.includes('expired') || errorMsg.includes('expire')) {
                        console.log('Token has expired');
                        showTokenExpired();
                    } else if (errorMsg.includes('invalid') || errorMsg.includes('not found')) {
                        console.log('Token is invalid');
                        showTokenExpired();
                    } else if (errorMsg.includes('used') || errorMsg.includes('already')) {
                        console.log('Token already used');
                        showGenericError('This password reset link has already been used. Please request a new one.');
                    } else {
                        console.log('Other token error:', data.error);
                        showGenericError(data.error);
                    }
                } else {
                    // Generic error response
                    showGenericError('Unable to verify password reset link. Please request a new one.');
                }
                
                return false;
            }
            
        } catch (error) {
            console.error('Error during token verification:', error);
            
            // Handle different types of errors
            if (error.name === 'AbortError') {
                console.error('Request timed out');
                showGenericError('Request timed out. Please check your connection and try again.');
            } else if (error.message.includes('Failed to fetch')) {
                console.error('Network error or CORS issue');
                showGenericError('Unable to connect to server. Please check your internet connection.');
            } else {
                console.error('Unexpected error:', error);
                showGenericError('An unexpected error occurred. Please try again.');
            }
            
            // Show token expired as fallback
            showTokenExpired();
            return false;
        }
    }

    // Helper function to show token expired message
    function showTokenExpired() {
        const tokenExpiredDiv = document.getElementById('tokenExpired');
        const resetPasswordFormDiv = document.getElementById('resetPasswordForm');
        
        if (tokenExpiredDiv) {
            tokenExpiredDiv.style.display = 'block';
        }
        if (resetPasswordFormDiv) {
            resetPasswordFormDiv.style.display = 'none';
        }
    }

    // Helper function to show generic error messages
    function showGenericError(message = 'There was a problem processing your request. Please try again.') {
        const errorMessage = document.getElementById('errorMessage');
        const tokenExpiredDiv = document.getElementById('tokenExpired');
        const resetPasswordFormDiv = document.getElementById('resetPasswordForm');
        
        if (errorMessage) {
            errorMessage.textContent = message;
            errorMessage.style.display = 'block';
        }
        
        // Still show the form but with error message
        if (tokenExpiredDiv) tokenExpiredDiv.style.display = 'none';
        if (resetPasswordFormDiv) resetPasswordFormDiv.style.display = 'block';
    }

    // Helper function to check if token is expired based on client time
    function isTokenExpired(expirationTime) {
        try {
            const serverTime = new Date(expirationTime).getTime();
            const clientTime = Date.now();
            return clientTime > serverTime;
        } catch (error) {
            console.error('Error checking token expiration:', error);
            return true; // Assume expired if we can't parse the date
        }
    }

// Optional: Function to periodically check token expiration
function startExpirationTimer(expirationTime) {
    if (!expirationTime) return;
    
    const checkInterval = setInterval(() => {
        if (isTokenExpired(expirationTime)) {
            console.log('Token expired during session');
            clearInterval(checkInterval);
            showTokenExpired();
        }
    }, 30000); // Check every 30 seconds
    
    // Clear interval when page is unloaded
    window.addEventListener('beforeunload', () => {
        clearInterval(checkInterval);
    });
}
    
    function showTokenExpired() {
        tokenExpiredDiv.style.display = 'block';
        resetPasswordFormDiv.style.display = 'none';
    }
    
    function showGenericError() {
        const errorMessage = document.getElementById('errorMessage');
        errorMessage.textContent = 'There was a problem processing your request. Please try again.';
        errorMessage.style.display = 'block';
    }
});