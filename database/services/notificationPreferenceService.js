/**
 * Notification Preference Service
 * Manages user notification preferences, validates preferences, and checks if notifications should be created
 * Encapsulates all preference logic, reusable across services
 */

const NotificationPreferenceService = {
    /**
     * Get database service (requires config)
     * @returns {Object} Database service
     * @throws {Error} If DatabaseConfigHelper is not available or database service is not configured
     */
    _getDatabaseService() {
        if (typeof DatabaseConfigHelper === 'undefined') {
            throw new Error('DatabaseConfigHelper not available. Ensure database-config-helper.js is loaded and DatabaseModule.initialize() has been called.');
        }
        return DatabaseConfigHelper.getDatabaseService(this);
    },

    /**
     * Get default notification preferences structure
     * @returns {Object} Default preferences object
     */
    getDefaultPreferences() {
        return {
            share_requests: true,
            share_responses: true,
            in_app_enabled: true,
            email_enabled: false,
            auto_accept_shares: false,
            auto_decline_shares: false,
            quiet_hours_enabled: false,
            quiet_hours_start: '22:00',
            quiet_hours_end: '08:00',
            payment_notifications: true,
            message_notifications: true
        };
    },

    /**
     * Get user's notification preferences
     * @param {string} userId - User ID
     * @returns {Promise<{success: boolean, preferences: Object|null, error: string|null}>}
     */
    async getPreferences(userId) {
        try {
            console.log('[NotificationPreferenceService] getPreferences() called', { userId });

            const databaseService = this._getDatabaseService();
            if (!databaseService) {
                throw new Error('DatabaseService not available');
            }

            const settings = await databaseService.getSettings();
            if (!settings) {
                console.log('[NotificationPreferenceService] No settings found, returning defaults');
                return {
                    success: true,
                    preferences: this.getDefaultPreferences(),
                    error: null
                };
            }

            let preferences = settings.notification_preferences;

            if (!preferences || typeof preferences !== 'object') {
                console.log('[NotificationPreferenceService] Invalid preferences, returning defaults');
                preferences = this.getDefaultPreferences();
            } else {
                const defaults = this.getDefaultPreferences();
                preferences = { ...defaults, ...preferences };
            }

            return {
                success: true,
                preferences: preferences,
                error: null
            };
        } catch (error) {
            console.error('[NotificationPreferenceService] Exception getting preferences:', error);
            return {
                success: false,
                preferences: null,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Update user's notification preferences
     * @param {string} userId - User ID
     * @param {Object} preferences - Preferences to update (partial or full)
     * @returns {Promise<{success: boolean, preferences: Object|null, error: string|null}>}
     */
    async updatePreferences(userId, preferences) {
        try {
            console.log('[NotificationPreferenceService] updatePreferences() called', { userId, preferences });

            const validationResult = this.validatePreferences(preferences);
            if (!validationResult.valid) {
                return {
                    success: false,
                    preferences: null,
                    error: validationResult.error
                };
            }

            const databaseService = this._getDatabaseService();
            if (!databaseService) {
                throw new Error('DatabaseService not available');
            }

            const currentSettings = await databaseService.getSettings();
            if (!currentSettings) {
                throw new Error('Settings not found for user');
            }

            const currentPreferences = currentSettings.notification_preferences || this.getDefaultPreferences();
            const mergedPreferences = { ...currentPreferences, ...preferences };

            const updateResult = await databaseService.updateSettings({
                notification_preferences: mergedPreferences
            });

            if (!updateResult) {
                throw new Error('Failed to update settings');
            }

            return {
                success: true,
                preferences: mergedPreferences,
                error: null
            };
        } catch (error) {
            console.error('[NotificationPreferenceService] Exception updating preferences:', error);
            return {
                success: false,
                preferences: null,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Validate notification preferences
     * @param {Object} preferences - Preferences to validate
     * @returns {{valid: boolean, error: string|null}}
     */
    validatePreferences(preferences) {
        if (!preferences || typeof preferences !== 'object') {
            return {
                valid: false,
                error: 'Preferences must be an object'
            };
        }

        const validKeys = [
            'share_requests',
            'share_responses',
            'in_app_enabled',
            'email_enabled',
            'auto_accept_shares',
            'auto_decline_shares',
            'quiet_hours_enabled',
            'quiet_hours_start',
            'quiet_hours_end',
            'payment_notifications',
            'message_notifications'
        ];

        for (const key of Object.keys(preferences)) {
            if (!validKeys.includes(key)) {
                return {
                    valid: false,
                    error: `Invalid preference key: ${key}`
                };
            }

            if (key.startsWith('quiet_hours_')) {
                if (key === 'quiet_hours_enabled') {
                    if (typeof preferences[key] !== 'boolean') {
                        return {
                            valid: false,
                            error: `${key} must be a boolean`
                        };
                    }
                } else if (key === 'quiet_hours_start' || key === 'quiet_hours_end') {
                    if (typeof preferences[key] !== 'string') {
                        return {
                            valid: false,
                            error: `${key} must be a string in HH:MM format`
                        };
                    }
                    const timeRegex = /^([0-1][0-9]|2[0-3]):[0-5][0-9]$/;
                    if (!timeRegex.test(preferences[key])) {
                        return {
                            valid: false,
                            error: `${key} must be in HH:MM format (e.g., "22:00")`
                        };
                    }
                }
            } else {
                if (typeof preferences[key] !== 'boolean') {
                    return {
                        valid: false,
                        error: `${key} must be a boolean`
                    };
                }
            }
        }

        return {
            valid: true,
            error: null
        };
    },

    /**
     * Check if user should receive a notification type
     * @param {string} userId - User ID
     * @param {string} notificationType - Notification type (e.g., 'share_request')
     * @returns {Promise<{shouldReceive: boolean, reason: string|null}>}
     */
    async shouldReceiveNotification(userId, notificationType) {
        try {
            const preferencesResult = await this.getPreferences(userId);
            if (!preferencesResult.success || !preferencesResult.preferences) {
                return {
                    shouldReceive: false,
                    reason: 'Failed to get preferences'
                };
            }

            const preferences = preferencesResult.preferences;

            if (!preferences.in_app_enabled) {
                return {
                    shouldReceive: false,
                    reason: 'In-app notifications are disabled'
                };
            }

            if (typeof window.NotificationTypeRegistry === 'undefined') {
                return {
                    shouldReceive: true,
                    reason: null
                };
            }

            const typeConfig = window.NotificationTypeRegistry.getType(notificationType);
            if (!typeConfig) {
                return {
                    shouldReceive: true,
                    reason: null
                };
            }

            const preferenceKey = typeConfig.preferenceKey;
            if (preferenceKey && preferences[preferenceKey] === false) {
                return {
                    shouldReceive: false,
                    reason: `${preferenceKey} notifications are disabled`
                };
            }

            return {
                shouldReceive: true,
                reason: null
            };
        } catch (error) {
            console.error('[NotificationPreferenceService] Exception checking shouldReceiveNotification:', error);
            return {
                shouldReceive: false,
                reason: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Check if current time is within user's quiet hours
     * @param {string} userId - User ID
     * @returns {Promise<{isQuietHours: boolean, reason: string|null}>}
     */
    async isQuietHours(userId) {
        try {
            const preferencesResult = await this.getPreferences(userId);
            if (!preferencesResult.success || !preferencesResult.preferences) {
                return {
                    isQuietHours: false,
                    reason: 'Failed to get preferences'
                };
            }

            const preferences = preferencesResult.preferences;

            if (!preferences.quiet_hours_enabled) {
                return {
                    isQuietHours: false,
                    reason: null
                };
            }

            const now = new Date();
            const currentTime = now.getHours() * 60 + now.getMinutes();

            const parseTime = (timeString) => {
                const [hours, minutes] = timeString.split(':').map(Number);
                return hours * 60 + minutes;
            };

            const startTime = parseTime(preferences.quiet_hours_start);
            const endTime = parseTime(preferences.quiet_hours_end);

            let isQuiet = false;

            if (startTime <= endTime) {
                isQuiet = currentTime >= startTime && currentTime < endTime;
            } else {
                isQuiet = currentTime >= startTime || currentTime < endTime;
            }

            return {
                isQuietHours: isQuiet,
                reason: isQuiet ? 'Current time is within quiet hours' : null
            };
        } catch (error) {
            console.error('[NotificationPreferenceService] Exception checking quiet hours:', error);
            return {
                isQuietHours: false,
                reason: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Comprehensive check if notification should be created
     * Checks preferences and quiet hours
     * @param {string} userId - User ID
     * @param {string} notificationType - Notification type
     * @returns {Promise<{shouldCreate: boolean, reason: string|null}>}
     */
    async shouldCreateNotification(userId, notificationType) {
        try {
            const shouldReceiveResult = await this.shouldReceiveNotification(userId, notificationType);
            if (!shouldReceiveResult.shouldReceive) {
                return {
                    shouldCreate: false,
                    reason: shouldReceiveResult.reason
                };
            }

            const quietHoursResult = await this.isQuietHours(userId);
            if (quietHoursResult.isQuietHours) {
                return {
                    shouldCreate: false,
                    reason: quietHoursResult.reason
                };
            }

            return {
                shouldCreate: true,
                reason: null
            };
        } catch (error) {
            console.error('[NotificationPreferenceService] Exception checking shouldCreateNotification:', error);
            return {
                shouldCreate: false,
                reason: error.message || 'An unexpected error occurred'
            };
        }
    }
};

if (typeof window !== 'undefined') {
    window.NotificationPreferenceService = NotificationPreferenceService;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = NotificationPreferenceService;
}

