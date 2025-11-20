document.addEventListener('DOMContentLoaded', () => {
    // Use relative URL for SocketIO to work on any domain (Railway, local)
    const socket = io('https://' + document.domain + ':' + location.port, {
        transports: ['websocket', 'polling'],  // Fallback for non-WebSocket environments
        path: '/socket.io/'  // Default path for Flask-SocketIO
    });

    socket.on('connect', () => {
        console.log('SocketIO connected');
        socket.emit('subscribe_notifications', { user: 'web_client' });
    });

    socket.on('connect_error', (error) => {
        console.error('SocketIO connection error:', error);
        // Fallback: Poll for notifications via AJAX every 10s
        setInterval(() => {
            fetch('/api/notifications')
                .then(response => response.json())
                .then(data => {
                    data.notifications.forEach(notification => {
                        showNotification(notification.message, notification.type);
                    });
                })
                .catch(err => console.error('Polling error:', err));
        }, 10000);
    });

    socket.on('notification', (data) => {
        console.log('Received notification:', data);
        showNotification(data.message, data.type || 'info');
    });

    function showNotification(message, type) {
        const notificationArea = document.getElementById('notification-area');
        const recentNotifications = document.getElementById('recent-notifications');
        
        // Toast notification
        const toast = document.createElement('div');
        toast.className = `alert alert-${type} alert-dismissible fade show position-absolute top-0 end-0 m-3`;
        toast.innerHTML = `
            <strong>${type.toUpperCase()}:</strong> ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        notificationArea.appendChild(toast);
        
        // Add to recent notifications (if on dashboard)
        if (recentNotifications) {
            const item = document.createElement('div');
            item.className = 'list-group-item d-flex justify-content-between align-items-center';
            item.innerHTML = `
                <div>
                    <small class="text-muted">${new Date().toLocaleTimeString()}</small>
                    <div>${message}</div>
                </div>
                <span class="badge bg-${type} rounded-pill">${type.toUpperCase()}</span>
            `;
            recentNotifications.insertBefore(item, recentNotifications.firstChild);
            // Limit to 10 notifications
            while (recentNotifications.children.length > 10) {
                recentNotifications.removeChild(recentNotifications.lastChild);
            }
        }

        // Auto-dismiss toast after 5 seconds
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 500);
        }, 5000);
    }
});
