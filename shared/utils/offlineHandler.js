/**
 * Offline Handler
 * Manages offline/online status and provides UI feedback
 */

const OfflineHandler = {
    offlineIndicator: null,
    isCurrentlyOffline: false,

    /**
     * Initialize offline detection and UI
     */
    initialize() {
        console.log('[OfflineHandler] Initializing offline detection...');

        // Create offline indicator UI
        this.createOfflineIndicator();

        // Set initial state
        this.isCurrentlyOffline = !navigator.onLine;
        if (this.isCurrentlyOffline) {
            this.showOfflineIndicator();
        }

        // Listen for online/offline events
        window.addEventListener('online', () => this.handleOnline());
        window.addEventListener('offline', () => this.handleOffline());

        console.log('[OfflineHandler] Offline detection initialized (currently:', navigator.onLine ? 'online' : 'offline', ')');
    },

    /**
     * Create the offline indicator UI element
     */
    createOfflineIndicator() {
        if (this.offlineIndicator) {
            return; // Already created
        }

        this.offlineIndicator = document.createElement('div');
        this.offlineIndicator.id = 'offline-indicator';
        this.offlineIndicator.innerHTML = `
            <div class="offline-banner" id="offline-banner">
                <i class="fas fa-wifi offline-icon"></i>
                <span id="offline-message">You are currently offline</span>
            </div>
        `;

        // Add CSS styles matching the app's modern design
        const style = document.createElement('style');
        style.textContent = `
            .offline-banner {
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                background: var(--color-warning, #b5a58a);
                color: var(--color-text, #1f1f1f);
                padding: 10px 20px;
                text-align: center;
                z-index: 10000;
                box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                font-size: 0.875rem;
                font-weight: 500;
                display: none;
                align-items: center;
                justify-content: center;
                gap: 8px;
                animation: offlineSlideDown 0.2s ease-out;
            }
            .offline-banner.online {
                background: var(--color-success, #7bab8a);
                color: white;
            }
            .offline-icon {
                font-size: 1rem;
            }
            @keyframes offlineSlideDown {
                from {
                    transform: translateY(-100%);
                    opacity: 0;
                }
                to {
                    transform: translateY(0);
                    opacity: 1;
                }
            }
            @keyframes offlineSlideUp {
                from {
                    transform: translateY(0);
                    opacity: 1;
                }
                to {
                    transform: translateY(-100%);
                    opacity: 0;
                }
            }
        `;
        document.head.appendChild(style);

        // Append to body when DOM is ready
        if (document.body) {
            document.body.appendChild(this.offlineIndicator);
        } else {
            document.addEventListener('DOMContentLoaded', () => {
                document.body.appendChild(this.offlineIndicator);
            });
        }
    },

    /**
     * Show the offline indicator
     */
    showOfflineIndicator() {
        const banner = document.getElementById('offline-banner');
        if (banner) {
            banner.classList.remove('online');
            banner.style.display = 'flex';
            banner.style.animation = 'offlineSlideDown 0.2s ease-out';
        }
    },

    /**
     * Hide the offline indicator
     */
    hideOfflineIndicator() {
        const banner = document.getElementById('offline-banner');
        if (banner) {
            banner.style.animation = 'offlineSlideUp 0.15s ease-out';
            setTimeout(() => {
                banner.style.display = 'none';
                banner.style.animation = 'offlineSlideDown 0.2s ease-out';
                banner.classList.remove('online');
            }, 150);
        }
    },

    /**
     * Handle when device goes offline
     */
    handleOffline() {
        console.warn('[OfflineHandler] Device went offline');
        this.isCurrentlyOffline = true;

        // Reset message and show indicator
        const message = document.getElementById('offline-message');
        const icon = document.querySelector('.offline-icon');
        if (message) {
            message.textContent = 'You are currently offline';
        }
        if (icon) {
            icon.className = 'fas fa-wifi offline-icon';
        }

        this.showOfflineIndicator();

        // Dispatch custom event
        window.dispatchEvent(new CustomEvent('app:offline'));

        // Show user-friendly message if they're in the middle of something
        if (document.activeElement && (
            document.activeElement.tagName === 'INPUT' ||
            document.activeElement.tagName === 'TEXTAREA'
        )) {
            console.warn('[OfflineHandler] User is editing - data may not save');
        }
    },

    /**
     * Handle when device comes back online
     */
    async handleOnline() {
        console.log('[OfflineHandler] Device came back online');
        this.isCurrentlyOffline = false;

        // Update indicator to show online status
        const banner = document.getElementById('offline-banner');
        const message = document.getElementById('offline-message');
        const icon = document.querySelector('.offline-icon');

        if (banner) {
            banner.classList.add('online');
        }
        if (message) {
            message.textContent = 'Back online';
        }
        if (icon) {
            icon.className = 'fas fa-check offline-icon';
        }

        // Dispatch custom event
        window.dispatchEvent(new CustomEvent('app:online'));

        // Revalidate session when coming back online
        if (window.AuthService && window.AuthService.isAuthenticated()) {
            console.log('[OfflineHandler] Revalidating session after coming back online...');
            try {
                await window.AuthService.validateSession(true, true); // autoRedirect=true, bypassCache=true
                console.log('[OfflineHandler] Session revalidation successful');
            } catch (error) {
                console.error('[OfflineHandler] Session revalidation failed:', error);
            }
        }

        // Hide the indicator quickly
        setTimeout(() => {
            this.hideOfflineIndicator();
        }, 800);
    },

    /**
     * Check if currently offline
     * @returns {boolean} True if offline
     */
    isOffline() {
        return this.isCurrentlyOffline;
    }
};

// Auto-initialize when DOM is ready - but defer to avoid blocking page load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        // Defer initialization slightly to ensure other scripts are ready
        setTimeout(() => OfflineHandler.initialize(), 100);
    });
} else {
    setTimeout(() => OfflineHandler.initialize(), 100);
}

// Make OfflineHandler available globally
if (typeof window !== 'undefined') {
    window.OfflineHandler = OfflineHandler;
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = OfflineHandler;
}
