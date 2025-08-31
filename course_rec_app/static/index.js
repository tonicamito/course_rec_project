document.addEventListener('DOMContentLoaded', function () {
    // Setup logout when DOM is ready
    setupLogout();
});

function setupLogout() {
    const logoutTrigger = document.querySelector('.avatar');

    if (logoutTrigger) {
        logoutTrigger.addEventListener('click', function () {
            performLogout();
        });
    }
}

function performLogout() {
    // Clear server-side cookie (token)
    fetch('/logout', {
        method: 'GET',
        credentials: 'same-origin'  
    })
    .then(response => {
        if (!response.ok) {
            console.error('Logout failed:', response.statusText);
        }
        window.location.href = '/login';
    })
    .catch(error => {
        console.error('Logout error:', error);
        window.location.href = '/login';
    });
}

