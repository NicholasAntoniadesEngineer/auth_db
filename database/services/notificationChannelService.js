/**
 * Notification Channel Service
 * Handles notification delivery through different channels (in-app, email, push, etc.)
 * Uses strategy pattern for channels, easy to add new delivery methods
 */

const NotificationChannelService = {
    /**
     * Registered notification channels
     * @type {Object<string, Object>}
     */
    _channels: {},

    /**
     * Initialize default channels
     */
    _initialize() {
        if (Object.keys(this._channels).length > 0) {
            return;
        }

        this.registerChannel('in_app', {
            name: 'In-App',
            description: 'Notifications shown in the application',
            send: async (userId, notification) => {
                console.log('[NotificationChannelService] In-app notification sent', { userId, notificationId: notification.id });
                return { success: true };
            }
        });
    },

    /**
     * Register a new notification channel
     * @param {string} name - Channel name/identifier
     * @param {Object} channelHandler - Channel handler object
     * @param {string} channelHandler.name - Human-readable name
     * @param {string} channelHandler.description - Description
     * @param {Function} channelHandler.send - Send function: async (userId, notification) => {success: boolean}
     */
    registerChannel(name, channelHandler) {
        if (!name || typeof name !== 'string') {
            throw new Error('Channel name must be a non-empty string');
        }

        if (!channelHandler || typeof channelHandler !== 'object') {
            throw new Error('Channel handler must be an object');
        }

        if (typeof channelHandler.send !== 'function') {
            throw new Error('Channel handler must have a send function');
        }

        this._channels[name] = {
            name: name,
            displayName: channelHandler.name || name,
            description: channelHandler.description || '',
            send: channelHandler.send
        };

        console.log(`[NotificationChannelService] Registered channel: ${name}`);
    },

    /**
     * Send notification through specified channels
     * @param {string} userId - User ID
     * @param {Object} notification - Notification object
     * @param {Array<string>} channels - Array of channel names to use (default: ['in_app'])
     * @returns {Promise<{success: boolean, results: Object, error: string|null}>}
     */
    async sendNotification(userId, notification, channels = ['in_app']) {
        try {
            this._initialize();

            console.log('[NotificationChannelService] sendNotification() called', { userId, notificationId: notification.id, channels });

            if (!Array.isArray(channels) || channels.length === 0) {
                channels = ['in_app'];
            }

            const results = {};
            let allSuccess = true;

            for (const channelName of channels) {
                const channel = this._channels[channelName];
                if (!channel) {
                    console.warn(`[NotificationChannelService] Channel not found: ${channelName}`);
                    results[channelName] = {
                        success: false,
                        error: `Channel '${channelName}' not registered`
                    };
                    allSuccess = false;
                    continue;
                }

                try {
                    const result = await channel.send(userId, notification);
                    results[channelName] = result;
                    if (!result.success) {
                        allSuccess = false;
                    }
                } catch (error) {
                    console.error(`[NotificationChannelService] Error sending via ${channelName}:`, error);
                    results[channelName] = {
                        success: false,
                        error: error.message || 'An unexpected error occurred'
                    };
                    allSuccess = false;
                }
            }

            return {
                success: allSuccess,
                results: results,
                error: allSuccess ? null : 'One or more channels failed'
            };
        } catch (error) {
            console.error('[NotificationChannelService] Exception sending notification:', error);
            return {
                success: false,
                results: {},
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Get available channels for a user based on preferences
     * @param {string} userId - User ID
     * @returns {Promise<{success: boolean, channels: Array<string>, error: string|null}>}
     */
    async getAvailableChannels(userId) {
        try {
            this._initialize();

            if (typeof window.NotificationPreferenceService === 'undefined') {
                return {
                    success: true,
                    channels: ['in_app'],
                    error: null
                };
            }

            const preferencesResult = await window.NotificationPreferenceService.getPreferences(userId);
            if (!preferencesResult.success || !preferencesResult.preferences) {
                return {
                    success: true,
                    channels: ['in_app'],
                    error: null
                };
            }

            const preferences = preferencesResult.preferences;
            const availableChannels = [];

            if (preferences.in_app_enabled) {
                availableChannels.push('in_app');
            }

            if (preferences.email_enabled && this._channels.email) {
                availableChannels.push('email');
            }

            if (this._channels.push) {
                availableChannels.push('push');
            }

            return {
                success: true,
                channels: availableChannels.length > 0 ? availableChannels : ['in_app'],
                error: null
            };
        } catch (error) {
            console.error('[NotificationChannelService] Exception getting available channels:', error);
            return {
                success: true,
                channels: ['in_app'],
                error: null
            };
        }
    },

    /**
     * Get all registered channels
     * @returns {Object<string, Object>} All registered channels
     */
    getAllChannels() {
        this._initialize();
        return { ...this._channels };
    },

    /**
     * Check if a channel is registered
     * @param {string} channelName - Channel name
     * @returns {boolean} True if registered
     */
    isRegistered(channelName) {
        this._initialize();
        return channelName in this._channels;
    }
};

// Initialize on load
NotificationChannelService._initialize();

if (typeof window !== 'undefined') {
    window.NotificationChannelService = NotificationChannelService;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = NotificationChannelService;
}

