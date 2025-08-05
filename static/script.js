document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('current-year').textContent = new Date().getFullYear();
    
    checkStatus();
    
    // Auto-refresh status every 15 seconds (reduced from 30)
    setInterval(checkStatus, 15000);
    
    const refreshBtn = document.getElementById('refresh-status-btn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', function() {
            // Disable the button temporarily to prevent spam
            refreshBtn.disabled = true;
            refreshBtn.textContent = 'Refreshing...';
            
            checkStatus().finally(() => {
                refreshBtn.disabled = false;
                refreshBtn.textContent = 'Refresh Status';
            });
        });
    }
});

// Cache for previous status to avoid unnecessary DOM updates
let previousStatus = {};

function checkStatus() {
    return fetch('/status')
        .then(response => response.json())
        .then(data => {
            let hasChanges = false;
            
            for (const [computerName, status] of Object.entries(data)) {
                if (previousStatus[computerName] !== status) {
                    hasChanges = true;
                    updateStatusDisplay(computerName, status);
                    previousStatus[computerName] = status;
                }
            }
            
            if (hasChanges) {
                console.log('Status updated for changed computers');
            } else {
                console.log('No status changes detected, skipping DOM updates');
            }
        })
        .catch(error => {
            console.error('Error checking status:', error);
            // Show error state for all computers only if not already in error state
            if (!previousStatus._error) {
                const statusDots = document.querySelectorAll('.status-dot');
                const statusTexts = document.querySelectorAll('.status-text');
                statusDots.forEach(dot => {
                    dot.style.color = '#6c757d';
                });
                statusTexts.forEach(text => {
                    text.textContent = 'Error';
                    text.style.color = '#6c757d';
                });
                previousStatus._error = true;
            }
        });
}

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