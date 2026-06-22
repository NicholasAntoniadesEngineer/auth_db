/**
 * Pairing Guard
 *
 * Checks if the current device has encryption keys set up.
 * Redirects to pairing page if keys are not found.
 */

const PairingGuard = {
    /**
     * Check if device needs pairing
     * @returns {Promise<boolean>} true if paired, false if needs pairing
     */
    async checkPairingStatus() {
        console.log('[PairingGuard] Checking pairing status...');

        try {
            // Check if user is authenticated
            if (!window.AuthService || !window.AuthService.isAuthenticated()) {
                console.warn('[PairingGuard] User not authenticated');
                return false;
            }

            const currentUser = window.AuthService.getCurrentUser();
            if (!currentUser) {
                console.warn('[PairingGuard] No current user found');
                return false;
            }

            const userId = currentUser.id;

            // Check if KeyStorageService is available
            if (!window.KeyStorageService) {
                console.warn('[PairingGuard] KeyStorageService not available');
                return false;
            }

            // Initialize KeyStorageService if needed
            if (typeof window.KeyStorageService.initialize === 'function') {
                await window.KeyStorageService.initialize();
            }

            // Check for identity keys
            const keys = await window.KeyStorageService.getIdentityKeys(userId);

            if (!keys || !keys.publicKey || !keys.secretKey) {
                console.log('[PairingGuard] No identity keys found - device needs pairing');
                return false;
            }

            console.log('[PairingGuard] Device is paired');
            return true;

        } catch (error) {
            console.error('[PairingGuard] Error checking pairing status:', error);
            return false;
        }
    },

    /**
     * Sign out if device is not paired
     * On next login, keys will be auto-restored from password backup
     */
    async requirePairing() {
        console.log('[PairingGuard] Checking if pairing is required...');

        const isPaired = await this.checkPairingStatus();

        if (!isPaired) {
            console.log('[PairingGuard] Not paired, signing out for clean re-login');
            await window.AuthService?.signOut();
            return false;
        }

        console.log('[PairingGuard] Device is paired, allowing access');
        return true;
    },

    /**
     * Check pairing status without redirecting
     * Useful for conditional UI rendering
     */
    async isPaired() {
        return await this.checkPairingStatus();
    }
};

// Make available globally
window.PairingGuard = PairingGuard;

console.log('[PairingGuard] Pairing guard loaded');
