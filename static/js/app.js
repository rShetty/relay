// Application JavaScript for Relay Dashboard

// Auto-hide flash messages after 5 seconds
document.addEventListener('DOMContentLoaded', function() {
    const flashes = document.querySelectorAll('.flash');
    flashes.forEach(function(flash) {
        setTimeout(function() {
            flash.style.transition = 'opacity 0.3s';
            flash.style.opacity = '0';
            setTimeout(function() { flash.remove(); }, 300);
        }, 5000);
    });
});
