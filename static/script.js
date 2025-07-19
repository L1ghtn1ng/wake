// Copyright year script
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('current-year').textContent = new Date().getFullYear();
    
    // Check status on page load
    checkStatus();
    
    // Auto-refresh status every 30 seconds
    setInterval(checkStatus, 30000);
    
    // Add event listener for refresh button
    const refreshBtn = document.getElementById('refresh-status-btn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', checkStatus);
    }
});

// Function to check computer status
function checkStatus() {
    fetch('/status')
        .then(response => response.json())
        .then(data => {
            for (const [computerName, isOnline] of Object.entries(data)) {
                updateStatusDisplay(computerName, isOnline);
            }
        })
        .catch(error => {
            console.error('Error checking status:', error);
            // Show error state for all computers
            const statusDots = document.querySelectorAll('.status-dot');
            const statusTexts = document.querySelectorAll('.status-text');
            statusDots.forEach(dot => {
                dot.style.color = '#6c757d';
            });
            statusTexts.forEach(text => {
                text.textContent = 'Error';
                text.style.color = '#6c757d';
            });
        });
}

// Function to update status display for a computer
function updateStatusDisplay(computerName, status) {
    const statusDot = document.getElementById(`dot-${computerName}`);
    const statusText = document.getElementById(`text-${computerName}`);
    
    if (statusDot && statusText) {
        if (status === 'UP') {
            statusDot.style.color = '#28a745'; // Green
            statusText.textContent = 'Online';
            statusText.style.color = '#28a745';
        } else {
            statusDot.style.color = '#dc3545'; // Red
            statusText.textContent = 'Offline';
            statusText.style.color = '#dc3545';
        }
    }
}