/**
 * dashboard.js - UI Interactions for Digital Forensics Toolkit
 * 
 * Handles:
 * - Sidebar toggle for mobile/tablet
 * - Modal interactions
 * - Flash message auto-dismiss
 */

// ============================================
// SIDEBAR TOGGLE (for mobile responsiveness)
// ============================================
document.addEventListener('DOMContentLoaded', function() {
    const sidebarToggle = document.getElementById('sidebarToggle');
    const sidebar = document.getElementById('sidebar');

    if (sidebarToggle && sidebar) {
        sidebarToggle.addEventListener('click', function() {
            sidebar.classList.toggle('open');
        });

        // Close sidebar when clicking outside on mobile
        document.addEventListener('click', function(e) {
            if (window.innerWidth <= 768) {
                if (!sidebar.contains(e.target) && !sidebarToggle.contains(e.target)) {
                    sidebar.classList.remove('open');
                }
            }
        });
    }

    // ============================================
    // AUTO-DISMISS FLASH MESSAGES
    // ============================================
    const flashMessages = document.querySelectorAll('.flash-msg');
    flashMessages.forEach(function(msg) {
        setTimeout(function() {
            msg.style.opacity = '0';
            msg.style.transform = 'translateY(-10px)';
            msg.style.transition = 'all 0.3s';
            setTimeout(function() {
                msg.remove();
            }, 300);
        }, 5000);  // Auto-dismiss after 5 seconds
    });

    // ============================================
    // CLOSE MODALS ON OVERLAY CLICK
    // ============================================
    const modals = document.querySelectorAll('.modal-overlay');
    modals.forEach(function(modal) {
        modal.addEventListener('click', function(e) {
            if (e.target === modal) {
                modal.classList.remove('show');
            }
        });
    });
});
