/**
 * Notification Service
 * Core notification CRUD operations - pure data access layer
 * No business logic or preference checking - that's handled by NotificationProcessor
 */

const NotificationService = {
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
     * Get table name (requires config)
     * @param {string} tableKey - Table key
     * @returns {string} Table name
     * @throws {Error} If DatabaseConfigHelper is not available or table name is not configured
     */
    _getTableName(tableKey) {
        if (typeof DatabaseConfigHelper === 'undefined') {
            throw new Error('DatabaseConfigHelper not available. Ensure database-config-helper.js is loaded and DatabaseModule.initialize() has been called.');
        }
        return DatabaseConfigHelper.getTableName(this, tableKey);
    },

    /**
     * Create a notification record
     * Low-level method - no business logic or preference checking
     * @param {Object} notificationData - Notification data
     * @param {string} notificationData.user_id - Recipient user ID
     * @param {string} notificationData.type - Notification type
     * @param {number|null} notificationData.share_id - Share ID (optional)
     * @param {string} notificationData.from_user_id - User who triggered the notification
     * @param {string|null} notificationData.message - Optional message
     * @returns {Promise<{success: boolean, notification: Object|null, error: string|null}>}
     */
    async createNotification(notificationData) {
        try {
            console.log('[NotificationService] ========== createNotification() CALLED ==========');
            console.log('[NotificationService] createNotification() - Start time:', new Date().toISOString());
            console.log('[NotificationService] createNotification() - Input data:', {
                type: notificationData.type,
                userId: notificationData.user_id,
                fromUserId: notificationData.from_user_id,
                shareId: notificationData.share_id,
                conversationId: notificationData.conversation_id,
                paymentId: notificationData.payment_id,
                subscriptionId: notificationData.subscription_id,
                invoiceId: notificationData.invoice_id,
                message: notificationData.message
            });

            const databaseService = this._getDatabaseService();
            if (!databaseService) {
                console.error('[NotificationService] DatabaseService not available');
                throw new Error('DatabaseService not available');
            }
            console.log('[NotificationService] DatabaseService obtained');

            // Check if we're creating a notification for the current user
            // If not, use the RPC function to bypass RLS
            console.log('[NotificationService] Getting current user ID...');
            const currentUserId = await databaseService._getCurrentUserId();
            console.log('[NotificationService] Current user ID:', currentUserId);
            console.log('[NotificationService] Target user ID (notification recipient):', notificationData.user_id);
            
            const isForCurrentUser = notificationData.user_id === currentUserId;
            console.log('[NotificationService] Is notification for current user?', isForCurrentUser);
            console.log('[NotificationService] User ID comparison:', {
                targetUserId: notificationData.user_id,
                currentUserId: currentUserId,
                areEqual: notificationData.user_id === currentUserId,
                targetType: typeof notificationData.user_id,
                currentType: typeof currentUserId
            });

            if (isForCurrentUser) {
                // Use regular insert for current user (RLS allows this)
                console.log('[NotificationService] Using direct insert path (notification for current user)');
                const tableName = this._getTableName('notifications');

                const insertData = {
                    user_id: notificationData.user_id,
                    type: notificationData.type,
                    from_user_id: notificationData.from_user_id,
                    read: false
                };

                if (notificationData.share_id !== null && notificationData.share_id !== undefined) {
                    insertData.share_id = notificationData.share_id;
                }

                if (notificationData.conversation_id !== null && notificationData.conversation_id !== undefined) {
                    insertData.conversation_id = notificationData.conversation_id;
                }

                if (notificationData.payment_id !== null && notificationData.payment_id !== undefined) {
                    insertData.payment_id = notificationData.payment_id;
                }

                if (notificationData.subscription_id !== null && notificationData.subscription_id !== undefined) {
                    insertData.subscription_id = notificationData.subscription_id;
                }

                if (notificationData.invoice_id !== null && notificationData.invoice_id !== undefined) {
                    insertData.invoice_id = notificationData.invoice_id;
                }

                if (notificationData.message) {
                    insertData.message = notificationData.message;
                }

                const result = await databaseService.queryInsert(tableName, insertData);

                if (result.error) {
                    console.error('[NotificationService] Error creating notification:', result.error);
                    return {
                        success: false,
                        notification: null,
                        error: result.error.message || 'Failed to create notification'
                    };
                }

                const createdNotification = Array.isArray(result.data) && result.data.length > 0
                    ? result.data[0]
                    : result.data;
                console.log('[NotificationService] Notification created successfully via direct insert:', {
                    notificationId: createdNotification?.id,
                    fullData: createdNotification
                });
                return {
                    success: true,
                    notification: createdNotification,
                    error: null
                };
            } else {
                // Use RPC function to create notification for another user (bypasses RLS)
                console.log('[NotificationService] ========== USING RPC PATH (notification for another user) ==========');
                console.log('[NotificationService] Creating notification for another user, using RPC function', {
                    targetUserId: notificationData.user_id,
                    currentUserId: currentUserId
                });
                
                const rpcParams = {
                    p_user_id: notificationData.user_id,
                    p_type: notificationData.type,
                    p_from_user_id: notificationData.from_user_id,
                    p_share_id: notificationData.share_id || null,
                    p_message: notificationData.message || null,
                    p_conversation_id: notificationData.conversation_id || null,
                    p_payment_id: notificationData.payment_id || null,
                    p_subscription_id: notificationData.subscription_id || null,
                    p_invoice_id: notificationData.invoice_id || null
                };
                
                console.log('[NotificationService] RPC parameters:', JSON.stringify(rpcParams, null, 2));
                console.log('[NotificationService] Calling queryRpc("create_notification", ...)');
                const rpcStartTime = Date.now();
                const result = await databaseService.queryRpc('create_notification', rpcParams);
                const rpcDuration = Date.now() - rpcStartTime;
                console.log(`[NotificationService] RPC call completed in ${rpcDuration}ms`);
                console.log('[NotificationService] RPC result:', {
                    hasError: !!result.error,
                    error: result.error,
                    hasData: result.data !== null && result.data !== undefined,
                    data: result.data,
                    dataType: typeof result.data
                });

                if (result.error) {
                    console.error('[NotificationService] Error creating notification via RPC:', result.error);
                    return {
                        success: false,
                        notification: null,
                        error: result.error.message || 'Failed to create notification'
                    };
                }

                // RPC returns the notification ID (BIGINT), which might be a number or string
                let notificationId = result.data;
                console.log('[NotificationService] Raw RPC return value:', notificationId, 'Type:', typeof notificationId);
                
                // Handle different return formats from Supabase RPC
                if (Array.isArray(notificationId) && notificationId.length > 0) {
                    notificationId = notificationId[0];
                    console.log('[NotificationService] Extracted ID from array:', notificationId);
                } else if (typeof notificationId === 'object' && notificationId !== null && 'id' in notificationId) {
                    notificationId = notificationId.id;
                    console.log('[NotificationService] Extracted ID from object:', notificationId);
                }
                
                // Convert to number if it's a string
                if (typeof notificationId === 'string' && !isNaN(notificationId)) {
                    notificationId = parseInt(notificationId, 10);
                    console.log('[NotificationService] Converted string ID to number:', notificationId);
                }
                
                console.log('[NotificationService] Final notification ID:', notificationId, 'Type:', typeof notificationId);

                // Don't try to fetch the notification - RLS will block it since it belongs to another user
                // We already have the ID from the RPC call, which is sufficient
                console.log('[NotificationService] Skipping notification fetch (RLS would block - notification belongs to another user)');
                console.log('[NotificationService] ========== createNotification() COMPLETE (RPC path) ==========');
                return {
                    success: true,
                    notification: { 
                        id: notificationId,
                        user_id: notificationData.user_id,
                        type: notificationData.type,
                        from_user_id: notificationData.from_user_id,
                        share_id: notificationData.share_id || null,
                        message: notificationData.message || null
                    },
                    error: null
                };
            }
        } catch (error) {
            console.error('[NotificationService] ========== EXCEPTION in createNotification() ==========');
            console.error('[NotificationService] Exception details:', {
                message: error.message,
                stack: error.stack,
                name: error.name
            });
            console.error('[NotificationService] ========== END EXCEPTION ==========');
            return {
                success: false,
                notification: null,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Get user's notifications
     * @param {string} userId - User ID
     * @param {Object} options - Query options
     * @param {boolean} options.unreadOnly - Only return unread notifications
     * @param {number} options.limit - Maximum number of notifications to return
     * @param {number} options.offset - Offset for pagination
     * @param {string} options.orderBy - Column to order by (default: 'created_at')
     * @param {boolean} options.ascending - Order ascending (default: false)
     * @returns {Promise<{success: boolean, notifications: Array, error: string|null}>}
     */
    async getNotifications(userId, options = {}) {
        try {
            console.log('[NotificationService] ========== getNotifications() CALLED ==========');
            console.log('[NotificationService] getNotifications() - Start time:', new Date().toISOString());
            console.log('[NotificationService] getNotifications() - Parameters:', { 
                userId, 
                options,
                unreadOnly: options.unreadOnly,
                limit: options.limit,
                offset: options.offset
            });

            const databaseService = this._getDatabaseService();
            if (!databaseService) {
                console.error('[NotificationService] DatabaseService not available');
                throw new Error('DatabaseService not available');
            }

            // Get current user ID to verify we're querying for the right user
            const currentUserId = await databaseService._getCurrentUserId();
            console.log('[NotificationService] Current user ID:', currentUserId);
            console.log('[NotificationService] Querying notifications for user ID:', userId);
            console.log('[NotificationService] User ID match:', currentUserId === userId);

            const tableName = this._getTableName('notifications');
            console.log('[NotificationService] Notifications table name:', tableName);

            const filter = {
                user_id: userId
            };

            if (options.unreadOnly) {
                filter.read = false;
                console.log('[NotificationService] Filtering for unread notifications only');
            }

            const queryOptions = {
                filter: filter,
                order: [{
                    column: options.orderBy || 'created_at',
                    ascending: options.ascending !== undefined ? options.ascending : false
                }]
            };

            if (options.limit) {
                queryOptions.limit = options.limit;
            }

            if (options.offset) {
                queryOptions.offset = options.offset;
            }

            console.log('[NotificationService] Query options:', JSON.stringify(queryOptions, null, 2));
            const result = await databaseService.querySelect(tableName, queryOptions);

            console.log('[NotificationService] Query result:', {
                hasError: !!result.error,
                error: result.error,
                hasData: !!result.data,
                dataLength: result.data?.length || 0,
                dataType: Array.isArray(result.data) ? 'array' : typeof result.data,
                sampleNotifications: result.data?.slice(0, 3).map(n => ({
                    id: n.id,
                    type: n.type,
                    user_id: n.user_id,
                    from_user_id: n.from_user_id,
                    share_id: n.share_id,
                    read: n.read,
                    created_at: n.created_at
                }))
            });

            if (result.error) {
                console.error('[NotificationService] Error getting notifications:', result.error);
                return {
                    success: false,
                    notifications: [],
                    error: result.error.message || 'Failed to get notifications'
                };
            }

            const notifications = result.data || [];
            console.log(`[NotificationService] Returning ${notifications.length} notifications`);
            console.log('[NotificationService] ========== getNotifications() COMPLETE ==========');
            return {
                success: true,
                notifications: notifications,
                error: null
            };
        } catch (error) {
            console.error('[NotificationService] ========== EXCEPTION in getNotifications() ==========');
            console.error('[NotificationService] Exception details:', {
                message: error.message,
                stack: error.stack,
                name: error.name
            });
            console.error('[NotificationService] ========== END EXCEPTION ==========');
            return {
                success: false,
                notifications: [],
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Mark notification as read
     * @param {number} notificationId - Notification ID
     * @returns {Promise<{success: boolean, error: string|null}>}
     */
    async markAsRead(notificationId) {
        try {
            console.log('[NotificationService] markAsRead() called', { notificationId });

            const databaseService = this._getDatabaseService();
            if (!databaseService) {
                throw new Error('DatabaseService not available');
            }

            const tableName = this._getTableName('notifications');

            const result = await databaseService.queryUpdate(tableName, notificationId, {
                read: true
            });

            if (result.error) {
                console.error('[NotificationService] Error marking notification as read:', result.error);
                return {
                    success: false,
                    error: result.error.message || 'Failed to mark notification as read'
                };
            }

            return {
                success: true,
                error: null
            };
        } catch (error) {
            console.error('[NotificationService] Exception marking notification as read:', error);
            return {
                success: false,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Mark all notifications as read for a user
     * @param {string} userId - User ID
     * @returns {Promise<{success: boolean, count: number, error: string|null}>}
     */
    async markAllAsRead(userId) {
        try {
            console.log('[NotificationService] markAllAsRead() called', { userId });

            const databaseService = this._getDatabaseService();
            if (!databaseService) {
                throw new Error('DatabaseService not available');
            }

            const tableName = this._getTableName('notifications');

            const unreadResult = await this.getNotifications(userId, { unreadOnly: true });
            if (!unreadResult.success) {
                return unreadResult;
            }

            const unreadNotifications = unreadResult.notifications;
            let updatedCount = 0;

            for (const notification of unreadNotifications) {
                const result = await this.markAsRead(notification.id);
                if (result.success) {
                    updatedCount++;
                }
            }

            return {
                success: true,
                count: updatedCount,
                error: null
            };
        } catch (error) {
            console.error('[NotificationService] Exception marking all notifications as read:', error);
            return {
                success: false,
                count: 0,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Mark all notifications as read for a conversation
     * @param {string} userId - User ID
     * @param {number} conversationId - Conversation ID
     * @param {string|null} fromUserId - Optional: User ID of the conversation partner (to mark their message notifications even without conversation_id)
     * @returns {Promise<{success: boolean, count: number, error: string|null}>}
     */
    async markConversationNotificationsAsRead(userId, conversationId, fromUserId = null) {
        try {
            console.log('[NotificationService] markConversationNotificationsAsRead() called', { userId, conversationId, fromUserId });

            const databaseService = this._getDatabaseService();
            if (!databaseService) {
                throw new Error('DatabaseService not available');
            }

            const tableName = this._getTableName('notifications');
            let totalCount = 0;

            // First, mark notifications with conversation_id matching
            console.log('[NotificationService] Marking notifications with conversation_id:', conversationId);
            const updateResult1 = await databaseService.queryUpdate(tableName, null, {
                read: true
            }, {
                user_id: userId,
                conversation_id: conversationId,
                read: false
            });

            if (updateResult1.error) {
                console.error('[NotificationService] Error marking conversation notifications as read (by conversation_id):', updateResult1.error);
            } else {
                const count1 = updateResult1.count || 0;
                totalCount += count1;
                console.log('[NotificationService] Marked', count1, 'notifications as read (by conversation_id)');
            }

            // Also mark message_received notifications from the conversation partner (even if they don't have conversation_id)
            if (fromUserId) {
                console.log('[NotificationService] Marking message_received notifications from user:', fromUserId);
                const updateResult2 = await databaseService.queryUpdate(tableName, null, {
                    read: true
                }, {
                    user_id: userId,
                    from_user_id: fromUserId,
                    type: 'message_received',
                    read: false
                });

                if (updateResult2.error) {
                    console.error('[NotificationService] Error marking message notifications as read (by from_user_id):', updateResult2.error);
                } else {
                    const count2 = updateResult2.count || 0;
                    totalCount += count2;
                    console.log('[NotificationService] Marked', count2, 'message notifications as read (by from_user_id)');
                }
            }

            console.log('[NotificationService] Total marked', totalCount, 'conversation notifications as read');
            return {
                success: true,
                count: totalCount,
                error: null
            };
        } catch (error) {
            console.error('[NotificationService] Exception marking conversation notifications as read:', error);
            return {
                success: false,
                count: 0,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Mark all notifications as read for a share
     * @param {string} userId - User ID
     * @param {number} shareId - Share ID
     * @returns {Promise<{success: boolean, count: number, error: string|null}>}
     */
    async markShareNotificationsAsRead(userId, shareId) {
        try {
            console.log('[NotificationService] markShareNotificationsAsRead() called', { userId, shareId });

            const databaseService = this._getDatabaseService();
            if (!databaseService) {
                throw new Error('DatabaseService not available');
            }

            const tableName = this._getTableName('notifications');

            const updateResult = await databaseService.queryUpdate(tableName, null, {
                read: true
            }, {
                user_id: userId,
                share_id: shareId,
                read: false
            });

            if (updateResult.error) {
                console.error('[NotificationService] Error marking share notifications as read:', updateResult.error);
                return {
                    success: false,
                    count: 0,
                    error: updateResult.error.message || 'Failed to mark share notifications as read'
                };
            }

            const count = updateResult.count || 0;
            console.log('[NotificationService] Marked', count, 'share notifications as read');
            return {
                success: true,
                count: count,
                error: null
            };
        } catch (error) {
            console.error('[NotificationService] Exception marking share notifications as read:', error);
            return {
                success: false,
                count: 0,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Delete a notification
     * @param {number} notificationId - Notification ID
     * @returns {Promise<{success: boolean, error: string|null}>}
     */
    async deleteNotification(notificationId) {
        try {
            console.log('[NotificationService] deleteNotification() called', { notificationId });

            const databaseService = this._getDatabaseService();
            if (!databaseService) {
                throw new Error('DatabaseService not available');
            }

            const tableName = this._getTableName('notifications');

            // queryDelete expects a filter object, not just the ID
            const result = await databaseService.queryDelete(tableName, { id: notificationId });

            if (result.error) {
                console.error('[NotificationService] Error deleting notification:', result.error);
                return {
                    success: false,
                    error: result.error.message || 'Failed to delete notification'
                };
            }

            return {
                success: true,
                error: null
            };
        } catch (error) {
            console.error('[NotificationService] Exception deleting notification:', error);
            return {
                success: false,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Get count of unread notifications for a user
     * @param {string} userId - User ID
     * @returns {Promise<{success: boolean, count: number, error: string|null}>}
     */
    async getUnreadCount(userId) {
        try {
            console.log('[NotificationService] ========== getUnreadCount() CALLED ==========');
            console.log('[NotificationService] getUnreadCount() - Start time:', new Date().toISOString());
            console.log('[NotificationService] getUnreadCount() - Parameters:', { userId });

            const result = await this.getNotifications(userId, { unreadOnly: true });

            console.log('[NotificationService] getUnreadCount() - getNotifications result:', {
                success: result.success,
                notificationsCount: result.notifications?.length || 0,
                error: result.error,
                notificationTypes: result.notifications?.map(n => n.type) || [],
                shareRequestCount: result.notifications?.filter(n => n.type === 'share_request').length || 0
            });

            if (!result.success) {
                console.warn('[NotificationService] getUnreadCount() - getNotifications failed:', result.error);
                return {
                    success: false,
                    count: 0,
                    error: result.error
                };
            }

            const count = result.notifications.length;
            console.log('[NotificationService] getUnreadCount() - Returning count:', count);
            console.log('[NotificationService] ========== getUnreadCount() COMPLETE ==========');
            return {
                success: true,
                count: count,
                error: null
            };
        } catch (error) {
            console.error('[NotificationService] ========== EXCEPTION in getUnreadCount() ==========');
            console.error('[NotificationService] Exception getting unread count:', error);
            console.error('[NotificationService] ========== END EXCEPTION ==========');
            return {
                success: false,
                count: 0,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Get a single notification by ID
     * @param {number} notificationId - Notification ID
     * @returns {Promise<{success: boolean, notification: Object|null, error: string|null}>}
     */
    async getNotificationById(notificationId) {
        try {
            console.log('[NotificationService] getNotificationById() called', { notificationId });

            const databaseService = this._getDatabaseService();
            if (!databaseService) {
                throw new Error('DatabaseService not available');
            }

            const tableName = this._getTableName('notifications');

            const result = await databaseService.querySelect(tableName, {
                filter: {
                    id: notificationId
                },
                limit: 1
            });

            if (result.error) {
                console.error('[NotificationService] Error getting notification:', result.error);
                return {
                    success: false,
                    notification: null,
                    error: result.error.message || 'Failed to get notification'
                };
            }

            const notification = result.data && result.data.length > 0 ? result.data[0] : null;

            return {
                success: true,
                notification: notification,
                error: null
            };
        } catch (error) {
            console.error('[NotificationService] Exception getting notification:', error);
            return {
                success: false,
                notification: null,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Subscribe to real-time notification updates
     * @param {string} userId - User ID
     * @param {Function} callback - Callback function to call when notifications change
     * @returns {Promise<{success: boolean, subscription: Object|null, error: string|null}>}
     */
    async subscribeToNotifications(userId, callback) {
        try {
            console.log('[NotificationService] subscribeToNotifications() called', { userId });

            const databaseService = this._getDatabaseService();
            if (!databaseService || !databaseService.client) {
                throw new Error('DatabaseService or client not available');
            }

            const tableName = this._getTableName('notifications');

            if (!databaseService.client.channel || typeof databaseService.client.channel !== 'function') {
                console.warn('[NotificationService] Real-time not available, skipping subscription');
                return {
                    success: false,
                    subscription: null,
                    error: 'Real-time subscriptions not available'
                };
            }

            const channel = databaseService.client.channel(`notifications:${userId}`)
                .on('postgres_changes', {
                    event: '*',
                    schema: 'public',
                    table: tableName,
                    filter: `user_id=eq.${userId}`
                }, (payload) => {
                    console.log('[NotificationService] Real-time notification update:', payload);
                    if (callback) {
                        callback(payload);
                    }
                })
                .subscribe();

            return {
                success: true,
                subscription: channel,
                error: null
            };
        } catch (error) {
            console.error('[NotificationService] Exception subscribing to notifications:', error);
            return {
                success: false,
                subscription: null,
                error: error.message || 'An unexpected error occurred'
            };
        }
    }
};

if (typeof window !== 'undefined') {
    window.NotificationService = NotificationService;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = NotificationService;
}

