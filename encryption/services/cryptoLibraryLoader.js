/**
 * Crypto Library Loader
 *
 * Dynamically loads the TweetNaCl.js cryptography library from CDN.
 * TweetNaCl is a port of NaCl (Networking and Cryptography library)
 * providing high-speed, high-security cryptographic operations.
 *
 * Library: https://github.com/dchest/tweetnacl-js
 * Size: ~100KB minified
 * License: Public domain
 */

const CryptoLibraryLoader = {
    /**
     * The loaded nacl library instance
     */
    nacl: null,

    /**
     * Whether the library has been loaded
     */
    loaded: false,

    /**
     * Configuration (set during initialize)
     */
    _config: null,

    /**
     * Initialize with configuration
     * @param {Object} config - Encryption config object
     */
    initialize(config) {
        this._config = config;
    },

    /**
     * Load TweetNaCl.js library and utilities
     * @returns {Promise<Object>} The nacl library object with util
     */
    async load() {
        // Return existing instance if already loaded
        if (this.loaded && this.nacl && this.nacl.util) {
            console.log('[CryptoLibraryLoader] TweetNaCl already loaded');
            return this.nacl;
        }

        // Check if already loaded globally
        if (window.nacl && window.nacl.util) {
            console.log('[CryptoLibraryLoader] Using existing TweetNaCl from window');
            this.nacl = window.nacl;
            this.loaded = true;
            return this.nacl;
        }

        const config = this._config || {};
        const naclUrl = config.crypto?.naclUrl || '../../shared/vendor/crypto/nacl-fast.min.js';
        const naclUtilUrl = config.crypto?.naclUtilUrl || '../../shared/vendor/crypto/nacl-util.min.js';
        const timeout = config.crypto?.loadTimeout || 15000;

        console.log('[CryptoLibraryLoader] Loading TweetNaCl.js from CDN...');

        // Load main library first
        await this._loadScript(naclUrl, 'TweetNaCl main library', timeout);

        // Then load util library (extends nacl object)
        await this._loadScript(naclUtilUrl, 'TweetNaCl util library', timeout);

        // Verify both are available
        if (!window.nacl) {
            throw new Error('TweetNaCl loaded but not available on window object');
        }

        if (!window.nacl.util) {
            throw new Error('TweetNaCl util loaded but not available on nacl object');
        }

        this.nacl = window.nacl;
        this.loaded = true;

        console.log('[CryptoLibraryLoader] TweetNaCl.js loaded successfully');
        this._logLibraryInfo();

        return this.nacl;
    },

    /**
     * Load a single script with timeout
     * @private
     * @param {string} src - Script URL
     * @param {string} name - Script name for logging
     * @param {number} timeout - Timeout in milliseconds
     * @returns {Promise<void>}
     */
    _loadScript(src, name, timeout) {
        return new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = src;
            script.async = true;
            script.defer = true;

            const timeoutId = setTimeout(() => {
                script.onload = null;
                script.onerror = null;
                const error = new Error(`Timeout loading ${name} from CDN (${timeout}ms). Check your internet connection.`);
                console.error('[CryptoLibraryLoader]', error);
                reject(error);
            }, timeout);

            script.onload = () => {
                clearTimeout(timeoutId);
                console.log(`[CryptoLibraryLoader] ${name} loaded`);
                resolve();
            };

            script.onerror = (event) => {
                clearTimeout(timeoutId);
                const error = new Error(`Failed to load ${name} from CDN. Check your internet connection.`);
                console.error('[CryptoLibraryLoader]', error, event);
                reject(error);
            };

            document.head.appendChild(script);
        });
    },

    /**
     * Log library capabilities
     * @private
     */
    _logLibraryInfo() {
        if (!this.nacl) return;

        console.log('[CryptoLibraryLoader] Library capabilities:', {
            box: !!this.nacl.box,
            secretbox: !!this.nacl.secretbox,
            hash: !!this.nacl.hash,
            randomBytes: !!this.nacl.randomBytes,
            util: !!this.nacl.util
        });
    },

    /**
     * Check if TweetNaCl is loaded
     * @returns {boolean} True if loaded with utils
     */
    isLoaded() {
        return this.loaded && !!this.nacl && !!this.nacl.util;
    },

    /**
     * Get the nacl library instance
     * @returns {Object|null} The nacl library or null if not loaded
     */
    getNacl() {
        return this.nacl;
    }
};

if (typeof window !== 'undefined') {
    window.CryptoLibraryLoader = CryptoLibraryLoader;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = CryptoLibraryLoader;
}
