document.addEventListener('DOMContentLoaded', function() {
    const forgotPasswordForm = document.getElementById('forgotPasswordForm');
    
    if (forgotPasswordForm) {
        forgotPasswordForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const email = document.getElementById('email').value.trim();
            const errorMessage = document.getElementById('errorMessage');
            const successMessage = document.getElementById('successMessage');
            const submitButton = this.querySelector('button[type="submit"]');
            const loadingSpinner = document.querySelector('.loading');
            
            // Clear previous messages
            errorMessage.style.display = 'none';
            successMessage.style.display = 'none';
            
            // Basic validation
            if (!email) {
                errorMessage.textContent = 'Please enter your email address';
                errorMessage.style.display = 'block';
                return;
            }
            
            // Email format validation
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                errorMessage.textContent = 'Please enter a valid email address';
                errorMessage.style.display = 'block';
                return;
            }
            
            try {
                // Disable button and show loading spinner
                submitButton.disabled = true;
                loadingSpinner.style.display = 'block';
                
                const response = await fetch('/api/forgot-password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    // Always show success message even if email doesn't exist for security reasons
                    successMessage.textContent = 'Password reset instructions have been sent to your email';
                    successMessage.style.display = 'block';
                    
                    // Clear the form
                    document.getElementById('email').value = '';
                } else {
                    
                    if (data.error && data.error !== 'Email not found') {
                        errorMessage.textContent = data.error || 'An error occurred. Please try again.';
                        errorMessage.style.display = 'block';
                    } else {
                        
                        successMessage.textContent = 'If your email exists in our system, you will receive password reset instructions';
                        successMessage.style.display = 'block';
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
                submitButton.textContent = 'Send Reset Link';
            }
        });
    }
});