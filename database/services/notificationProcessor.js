/**
 * Notification Processor
 * Orchestrates notification creation, preference checking, and delivery
 * Facade pattern - coordinates between services, single entry point for notification creation
 */

const NotificationProcessor = {
    /**
     * Process notification - main entry point
     * Validates, checks preferences, creates notification, and delivers it
     * @param {string} userId - Recipient user ID
     * @param {string} type - Notification type
     * @param {Object} data - Notification data
     * @param {number|null} data.shareId - Share ID (optional)
     * @param {string} data.fromUserId - User who triggered the notification
     * @param {string|null} data.message - Optional message
     * @returns {Promise<{success: boolean, notification: Object|null, error: string|null}>}
     */
    async processNotification(userId, type, data) {
        try {
            console.log('[NotificationProcessor] processNotification() called', { userId, type, data });

            if (!userId || typeof userId !== 'string') {
                throw new Error('userId is required and must be a string');
            }

            if (!type || typeof type !== 'string') {
                throw new Error('type is required and must be a string');
            }

            if (!data || typeof data !== 'object') {
                throw new Error('data is required and must be an object');
            }

            if (!data.fromUserId || typeof data.fromUserId !== 'string') {
                throw new Error('data.fromUserId is required and must be a string');
            }

            if (typeof window.NotificationTypeRegistry === 'undefined') {
                throw new Error('NotificationTypeRegistry not available');
            }

            const typeConfig = window.NotificationTypeRegistry.getType(type);
            if (!typeConfig) {
                throw new Error(`Notification type '${type}' is not registered`);
            }

            if (typeof window.NotificationPreferenceService === 'undefined') {
                throw new Error('NotificationPreferenceService not available');
            }

            const shouldCreateResult = await window.NotificationPreferenceService.shouldCreateNotification(userId, type);
            if (!shouldCreateResult.shouldCreate) {
                console.log('[NotificationProcessor] Notification not created due to preferences:', shouldCreateResult.reason);
                return {
                    success: false,
                    notification: null,
                    error: shouldCreateResult.reason || 'Notification creation blocked by preferences'
                };
            }

            if (typeof window.NotificationService === 'undefined') {
                throw new Error('NotificationService not available');
            }

            const notificationData = {
                user_id: userId,
                type: type,
                share_id: data.shareId || null,
                from_user_id: data.fromUserId,
                message: data.message || null
            };

            const createResult = await window.NotificationService.createNotification(notificationData);
            if (!createResult.success || !createResult.notification) {
                return {
                    success: false,
                    notification: null,
                    error: createResult.error || 'Failed to create notification'
                };
            }

            if (typeof window.NotificationChannelService === 'undefined') {
                console.warn('[NotificationProcessor] NotificationChannelService not available, skipping delivery');
                return {
                    success: true,
                    notification: createResult.notification,
                    error: null
                };
            }

            const availableChannelsResult = await window.NotificationChannelService.getAvailableChannels(userId);
            const channels = availableChannelsResult.channels || ['in_app'];

            const deliveryResult = await window.NotificationChannelService.sendNotification(
                userId,
                createResult.notification,
                channels
            );

            if (!deliveryResult.success) {
                console.warn('[NotificationProcessor] Notification created but delivery failed:', deliveryResult.error);
            }

            return {
                success: true,
                notification: createResult.notification,
                error: null
            };
        } catch (error) {
            console.error('[NotificationProcessor] Exception processing notification:', error);
            return {
                success: false,
                notification: null,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Create and deliver notification - high-level method
     * Convenience method that handles full flow for all notification types
     * @param {string} userId - Recipient user ID
     * @param {string} type - Notification type
     * @param {number|null} shareId - Share ID (optional, for share notifications)
     * @param {string} fromUserId - User who triggered the notification (or system for payment notifications)
     * @param {string|null} message - Optional message (if not provided, will use template)
     * @param {Object} messageData - Data for message template (e.g., { fromUserEmail, toUserEmail, amount, planName, etc. })
     * @param {number|null} conversationId - Conversation ID (optional, for message notifications)
     * @param {number|null} paymentId - Payment ID (optional, for payment notifications)
     * @param {string|null} subscriptionId - Subscription ID (optional, for subscription notifications)
     * @param {string|null} invoiceId - Invoice ID (optional, for invoice notifications)
     * @returns {Promise<{success: boolean, notification: Object|null, error: string|null}>}
     */
    async createAndDeliver(userId, type, shareId, fromUserId, message = null, messageData = {}, conversationId = null, paymentId = null, subscriptionId = null, invoiceId = null) {
        console.log('[NotificationProcessor] createAndDeliver() called', { userId, type, shareId, fromUserId, conversationId, paymentId, subscriptionId, invoiceId });
        
        try {
            // Check if notification should be created based on preferences
            if (typeof window.NotificationPreferenceService === 'undefined') {
                throw new Error('NotificationPreferenceService not available');
            }

            const shouldReceiveResult = await window.NotificationPreferenceService.shouldReceiveNotification(userId, type);
            if (!shouldReceiveResult || !shouldReceiveResult.shouldReceive) {
                console.log(`[NotificationProcessor] Notification type ${type} suppressed for user ${userId} due to preferences or quiet hours. Reason: ${shouldReceiveResult?.reason || 'Unknown'}`);
                return {
                    success: true,
                    notification: null,
                    error: shouldReceiveResult?.reason || 'Notification suppressed by preferences'
                };
            }

            // Get notification type configuration
            if (typeof window.NotificationTypeRegistry === 'undefined') {
                throw new Error('NotificationTypeRegistry not available');
            }

            const typeConfig = window.NotificationTypeRegistry.getType(type);
            if (!typeConfig) {
                console.error(`[NotificationProcessor] Unknown notification type: ${type}`);
                return {
                    success: false,
                    notification: null,
                    error: `Unknown notification type: ${type}`
                };
            }

            // Generate message if not provided
            let finalMessage = message;
            if (!finalMessage) {
                console.log('[NotificationProcessor] Generating message from template for type:', type);
                finalMessage = this._generateMessage(type, typeConfig, messageData, userId, fromUserId);
                console.log('[NotificationProcessor] Generated message:', finalMessage);
            } else {
                console.log('[NotificationProcessor] Using provided message:', finalMessage);
            }

            // Prepare notification data
            const notificationData = {
                user_id: userId,
                type: type,
                from_user_id: fromUserId,
                message: finalMessage,
                read: false
            };

            if (shareId !== null && shareId !== undefined) {
                notificationData.share_id = shareId;
                console.log('[NotificationProcessor] Adding share_id to notification:', shareId);
            }

            if (conversationId !== null && conversationId !== undefined) {
                notificationData.conversation_id = conversationId;
                console.log('[NotificationProcessor] Adding conversation_id to notification:', conversationId);
            }

            if (paymentId !== null && paymentId !== undefined) {
                notificationData.payment_id = paymentId;
                console.log('[NotificationProcessor] Adding payment_id to notification:', paymentId);
            }

            if (subscriptionId !== null && subscriptionId !== undefined) {
                notificationData.subscription_id = subscriptionId;
                console.log('[NotificationProcessor] Adding subscription_id to notification:', subscriptionId);
            }

            if (invoiceId !== null && invoiceId !== undefined) {
                notificationData.invoice_id = invoiceId;
                console.log('[NotificationProcessor] Adding invoice_id to notification:', invoiceId);
            }

            console.log('[NotificationProcessor] Prepared notification data:', {
                user_id: notificationData.user_id,
                type: notificationData.type,
                from_user_id: notificationData.from_user_id,
                has_share_id: !!notificationData.share_id,
                has_conversation_id: !!notificationData.conversation_id,
                has_payment_id: !!notificationData.payment_id,
                has_subscription_id: !!notificationData.subscription_id,
                has_invoice_id: !!notificationData.invoice_id,
                message_length: notificationData.message?.length
            });

            // Create notification record
            if (typeof window.NotificationService === 'undefined') {
                throw new Error('NotificationService not available');
            }

            const createResult = await window.NotificationService.createNotification(notificationData);
            if (!createResult.success) {
                console.error('[NotificationProcessor] Failed to create notification record:', createResult.error);
                return {
                    success: false,
                    notification: null,
                    error: createResult.error
                };
            }

            const newNotification = createResult.notification;
            console.log('[NotificationProcessor] Notification record created:', newNotification);

            // Deliver notification via enabled channels
            if (typeof window.NotificationChannelService !== 'undefined') {
                const deliveryResults = await window.NotificationChannelService.sendNotification(userId, newNotification);
                console.log('[NotificationProcessor] Notification delivery results:', deliveryResults);
            }

            return {
                success: true,
                notification: newNotification,
                error: null
            };
        } catch (error) {
            console.error('[NotificationProcessor] Exception in createAndDeliver:', error);
            return {
                success: false,
                notification: null,
                error: error.message || 'An unexpected error occurred'
            };
        }
    },

    /**
     * Generate message for notification based on type and data
     * @param {string} type - Notification type
     * @param {Object} typeConfig - Type configuration from registry
     * @param {Object} messageData - Data for message template
     * @param {string} userId - Recipient user ID
     * @param {string} fromUserId - Sender/system user ID
     * @returns {string} Generated message
     * @private
     */
    _generateMessage(type, typeConfig, messageData, userId, fromUserId) {
        console.log('[NotificationProcessor] _generateMessage() called', { 
            type, 
            messageDataKeys: Object.keys(messageData || {}),
            userId,
            fromUserId,
            typeConfigName: typeConfig?.name
        });

        // Payment notification messages
        if (type === 'subscription_created') {
            return `Your subscription has been created${messageData.planName ? `: ${messageData.planName}` : ''}.`;
        }
        if (type === 'subscription_updated') {
            return `Your subscription has been updated${messageData.planName ? `: ${messageData.planName}` : ''}.`;
        }
        if (type === 'subscription_cancelled') {
            return `Your subscription has been cancelled.`;
        }
        if (type === 'subscription_expired') {
            return `Your subscription has expired. Please renew to continue using premium features.`;
        }
        if (type === 'payment_succeeded') {
            const amount = messageData.amount ? `$${messageData.amount.toFixed(2)}` : '';
            return `Your payment was successful${amount ? `: ${amount}` : ''}.`;
        }
        if (type === 'payment_failed') {
            return `Your payment failed. Please update your payment method to continue your subscription.`;
        }
        if (type === 'invoice_paid') {
            const amount = messageData.amount ? `$${messageData.amount.toFixed(2)}` : '';
            return `Your invoice has been paid${amount ? `: ${amount}` : ''}.`;
        }
        if (type === 'checkout_completed') {
            return `Your checkout has been completed successfully.`;
        }

        // Messaging notification messages
        if (type === 'message_received') {
            const fromEmail = messageData.fromUserEmail || 'Someone';
            const preview = messageData.messagePreview ? `: "${messageData.messagePreview}${messageData.messagePreview.length >= 100 ? '...' : ''}"` : '';
            return `${fromEmail} sent you a message${preview}`;
        }

        // Share notification messages (existing)
        if (type === 'share_request') {
            const fromEmail = messageData.fromUserEmail || 'Someone';
            return `${fromEmail} wants to share data with you.`;
        }
        if (type === 'share_accepted') {
            const toEmail = messageData.toUserEmail || 'User';
            return `${toEmail} accepted your data share request.`;
        }
        if (type === 'share_declined') {
            const toEmail = messageData.toUserEmail || 'User';
            return `${toEmail} declined your data share request.`;
        }
        if (type === 'share_blocked') {
            const toEmail = messageData.toUserEmail || 'User';
            return `${toEmail} blocked you from sharing data.`;
        }

        // Default fallback
        const fallbackMessage = typeConfig.description || `You have a new ${typeConfig.name || type} notification.`;
        console.log('[NotificationProcessor] Using fallback message template for type:', type, 'Message:', fallbackMessage);
        return fallbackMessage;
    }
};

if (typeof window !== 'undefined') {
    window.NotificationProcessor = NotificationProcessor;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = NotificationProcessor;
}

