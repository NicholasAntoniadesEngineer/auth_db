/**
 * Shared Header Component
 * Renders consistent navigation header across all pages
 */

class Header {
    static updateInProgress = false;
    static notificationCountUpdateInProgress = false;
    static notificationCountUpdateTimeout = null;
    static notificationSubscriptionSetup = false;
    static messageSubscriptionSetup = false;
    static lastUpdateState = null;
    static initialized = false;
    
    /**
     * Check if we're on the auth page
     * @returns {boolean} True if on auth page
     */
    static isAuthPage() {
        const path = window.location.pathname;
        const filename = path.split('/').pop() || '';
        return filename.includes('auth.html') || path.includes('/auth.html');
    }

    /**
     * Get the current page name from the current URL
     */
    static getCurrentPage() {
        const path = window.location.pathname;
        const filename = path.split('/').pop() || '';

        if (filename.includes('messenger')) {
            return 'Messenger';
        }
        return 'Secure Messenger';
    }

    /**
     * Get path to a specific module's views folder
     * @param {string} moduleName - Name of the module (e.g., 'auth', 'monthlyBudget', 'settings')
     * @returns {string} Path to the module's views folder
     */
    static getModulePath(moduleName) {
        const path = window.location.pathname;

        // Get all module names from registry
        const modules = window.ModuleRegistry?.getAllModuleNames() || [];

        // Check if we're in any module's views/ folder
        const inModuleViews = modules.some(mod => path.includes(`/${mod}/views/`));
        if (inModuleViews) {
            return `../../${moduleName}/views/`;
        }

        // If we're in ui/views/ (shouldn't exist anymore, but for compatibility)
        if (path.includes('/ui/views/')) {
            return `../../${moduleName}/views/`;
        }

        // Check if we're in any module folder but not in views/
        const inModule = modules.some(mod => path.includes(`/${mod}/`));
        if (inModule) {
            return `../${moduleName}/views/`;
        }

        // If we're in ui/ folder
        if (path.includes('/ui/')) {
            return `../${moduleName}/views/`;
        }

        // Default: assume we're at root level
        return `${moduleName}/views/`;
    }


    /**
     * Get user initials from email
     */
    static getUserInitials(email) {
        if (!email || typeof email !== 'string') {
            return 'U';
        }
        const emailParts = email.trim().split('@');
        const namePart = emailParts[0] || '';
        if (namePart.length === 0) {
            return 'U';
        }
        if (namePart.length === 1) {
            return namePart.toUpperCase();
        }
        return namePart.substring(0, 2).toUpperCase();
    }

    /**
     * Render the header HTML
     */
    static render() {
        // Don't render navigation on auth page
        if (this.isAuthPage()) {
            return '';
        }
        
        // Get user info if authenticated
        // Be resilient to session check timeouts - check both method and direct state
        let userInfoHtml = '';
        if (window.AuthService) {
            const methodCheck = window.AuthService.isAuthenticated();
            const directCheck = window.AuthService.currentUser !== null && window.AuthService.session !== null;
            const isAuthenticated = methodCheck || directCheck;

            if (isAuthenticated) {
                const user = window.AuthService.getCurrentUser() || window.AuthService.currentUser;
                const userEmail = user?.email || 'User';
                const userInitials = this.getUserInitials(userEmail);
                userInfoHtml = this._renderUserMenu(userEmail, userInitials);
            }
        }

        return `
    <header class="main-header">
        <nav class="main-navigation" role="navigation" aria-label="Main navigation">
            <div class="header-title-group">
                <h1 class="site-title" id="header-app-title" role="button" tabindex="0" aria-label="Go to messenger">Secure Messenger</h1>
            </div>
            ${userInfoHtml}
        </nav>
    </header>`;
    }

    /**
     * Render the authenticated user menu (avatar + dropdown).
     * Standalone messenger: only the user identity + Sign Out. No dead-page links.
     * @private
     */
    static _renderUserMenu(userEmail, userInitials) {
        return `
                <div class="header-user-menu">
                    <button class="user-avatar-button" id="user-avatar-button" aria-label="User menu" aria-expanded="false">
                        <span class="user-initials">${userInitials}</span>
                        <span class="avatar-notification-badge" id="avatar-notification-badge" style="display: none;">0</span>
                    </button>
                    <div class="user-dropdown-menu" id="user-dropdown-menu">
                        <div class="user-dropdown-item user-dropdown-username">
                            <i class="fa-regular fa-user user-dropdown-icon"></i>
                            <span>${userEmail}</span>
                            <span class="notification-count-badge" id="header-notification-count" style="display: none;">0</span>
                        </div>
                        <a href="${this.getModulePath('payments')}subscription.html" class="user-dropdown-item user-dropdown-subscription">
                            <i class="fa-solid fa-crown user-dropdown-icon"></i>
                            <span>Subscription</span>
                        </a>
                        <button class="user-dropdown-item user-dropdown-signout" id="header-signout-button" aria-label="Sign out">
                            <i class="fa-solid fa-right-from-bracket user-dropdown-icon"></i>
                            <span>Sign Out</span>
                        </button>
                    </div>
                </div>`;
    }

    /**
     * Initialize and inject header into the page
     */
    static async init() {
        console.log('[Header] ========== HEADER INIT STARTED ==========');
        console.log('[Header] init() called');
        
        // Prevent multiple initializations
        if (this.initialized) {
            console.log('[Header] Already initialized, skipping duplicate init');
            return;
        }
        
        // Don't initialize header on auth page
        if (this.isAuthPage()) {
            console.log('[Header] On auth page, skipping header initialization');
            return;
        }
        
        // Wait for SupabaseConfig to be available before initializing AuthService
        if (window.AuthService && !window.AuthService.client) {
            console.log('[Header] AuthService available but client not initialized, waiting for SupabaseConfig...');
            
            // Wait for SupabaseConfig to be available (with timeout)
            let waitCount = 0;
            const maxWait = 50; // Wait up to 5 seconds (50 * 100ms)
            while (!window.SupabaseConfig && waitCount < maxWait) {
                await new Promise(resolve => setTimeout(resolve, 100));
                waitCount++;
            }
            
            if (!window.SupabaseConfig) {
                console.warn('[Header] SupabaseConfig not available after waiting, skipping AuthService initialization');
            } else {
                console.log('[Header] SupabaseConfig available, initializing AuthService...');
            try {
                await window.AuthService.initialize();
                console.log('[Header] AuthService initialized');
            } catch (error) {
                console.warn('[Header] AuthService initialization failed:', error);
                }
            }
        } else {
            console.log('[Header] AuthService status:', {
                hasAuthService: !!window.AuthService,
                hasClient: !!window.AuthService?.client,
                hasSupabaseConfig: !!window.SupabaseConfig
            });
        }
        
        // Find where to insert the header (before main or body's first child)
        const main = document.querySelector('main');
        const body = document.body;
        
        console.log('[Header] Finding insertion point:', {
            hasMain: !!main,
            hasBody: !!body
        });
        
        const headerHtml = this.render();
        if (!headerHtml) {
            console.log('[Header] No header to render, skipping');
            return;
        }
        
        if (main) {
            // Insert before main element
            console.log('[Header] Inserting header before main element');
            main.insertAdjacentHTML('beforebegin', headerHtml);
        } else if (body) {
            // Insert as first child of body
            console.log('[Header] Inserting header as first child of body');
            body.insertAdjacentHTML('afterbegin', headerHtml);
        } else {
            console.error('[Header] ERROR: Could not find insertion point');
            return;
        }

        console.log('[Header] Header rendered, initializing components...');

        // Initialize app title click handler
        this.initAppTitleClick();
        
        // Initialize user menu dropdown
        this.initUserMenu();
        
        // Initialize sign out button
        this.initSignOutButton();
        
        // Note: Notification bell is initialized in updateHeader() after HTML is rendered
        
        // Listen for auth state changes to update header
        this.setupAuthStateListener();
        
        // Update header immediately to show user menu if already authenticated
        console.log('[Header] Updating header with current auth state...');
        this.updateHeader();
        
        // Update notification count after a delay to ensure services are loaded
        setTimeout(() => {
            this.updateNotificationCount().catch(err => {
                console.warn('[Header] Failed to update notification count on init:', err);
            });
            this.setupNotificationSubscription().catch(err => {
                console.warn('[Header] Failed to setup notification subscription:', err);
            });
            this.setupMessageSubscription().catch(err => {
                console.warn('[Header] Failed to setup message subscription:', err);
            });
        }, 1000);

        // Update notification count when page becomes visible (user switches back to tab)
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden && window.AuthService) {
                console.log('[Header] Page became visible, checking auth state and updating...');
                // Refresh header to ensure user icon is still visible
                this.updateHeader();
                this.updateNotificationCount().catch(err => {
                    console.warn('[Header] Failed to update notification count on visibility change:', err);
                });
            }
        });
        
        // Periodic session check to prevent user icon from disappearing
        // Check every 30 seconds if user appears to be authenticated
        setInterval(() => {
            if (window.AuthService && window.AuthService.currentUser && window.AuthService.session) {
                // User appears authenticated, verify and refresh header if needed
                const nav = document.querySelector('.main-navigation');
                const userMenu = nav?.querySelector('.header-user-menu');
                if (!userMenu) {
                    console.log('[Header] User menu missing but user appears authenticated, refreshing header...');
                    this.updateHeader(true);
                }
                // Also update notification count periodically to ensure it stays current
                this.updateNotificationCount().catch(err => {
                    console.warn('[Header] Failed to update notification count in periodic check:', err);
                });
            }
        }, 30000); // Check every 30 seconds
        
        this.initialized = true;
        console.log('[Header] ========== HEADER INIT COMPLETE ==========');
    }


    /**
     * Initialize app title click handler
     * Brand is the "home" of the standalone app: go to the messenger when
     * authenticated, otherwise to the sign-in page. Never to a dead landing page.
     */
    static initAppTitleClick() {
        const appTitle = document.getElementById('header-app-title');
        if (!appTitle) return;

        const handleClick = (e) => {
            e.preventDefault();
            e.stopPropagation();

            const isAuthenticated = window.AuthService && window.AuthService.isAuthenticated();

            if (isAuthenticated) {
                window.location.href = this.getModulePath('messaging') + 'messenger.html';
            } else {
                window.location.href = this.getModulePath('auth') + 'auth.html';
            }
        };

        appTitle.addEventListener('click', handleClick);
        appTitle.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                handleClick(e);
            }
        });
    }

    /**
     * Initialize user menu dropdown
     */
    static positionDropdown(avatarButton, dropdownMenu) {
        const buttonRect = avatarButton.getBoundingClientRect();
        const dropdownWidth = dropdownMenu.offsetWidth;
        const top = buttonRect.bottom + 8;
        let left = buttonRect.right - dropdownWidth;

        // Clamp to viewport so dropdown never goes off-screen
        if (left < 8) left = 8;
        if (left + dropdownWidth > window.innerWidth - 8) {
            left = window.innerWidth - dropdownWidth - 8;
        }

        dropdownMenu.style.top = `${top}px`;
        dropdownMenu.style.left = `${left}px`;
        console.log('[Header] Dropdown positioned:', { top, left, dropdownWidth, buttonRight: buttonRect.right });
    }

    static closeDropdown(avatarButton, dropdownMenu) {
        avatarButton.setAttribute('aria-expanded', 'false');
        dropdownMenu.classList.remove('user-dropdown-open');
    }

    static initUserMenu() {
        const avatarButton = document.getElementById('user-avatar-button');
        const dropdownMenu = document.getElementById('user-dropdown-menu');

        if (!avatarButton || !dropdownMenu) {
            console.log('[Header] User menu elements not found, skipping init');
            return;
        }

        console.log('[Header] Initializing user menu');

        avatarButton.addEventListener('click', (e) => {
            e.stopPropagation();
            const opening = avatarButton.getAttribute('aria-expanded') !== 'true';
            avatarButton.setAttribute('aria-expanded', String(opening));

            if (opening) {
                dropdownMenu.classList.add('user-dropdown-open');
                this.positionDropdown(avatarButton, dropdownMenu);
            } else {
                this.closeDropdown(avatarButton, dropdownMenu);
            }
        });

        window.addEventListener('resize', () => {
            if (dropdownMenu.classList.contains('user-dropdown-open')) {
                this.positionDropdown(avatarButton, dropdownMenu);
            }
        });

        window.addEventListener('scroll', () => {
            if (dropdownMenu.classList.contains('user-dropdown-open')) {
                this.closeDropdown(avatarButton, dropdownMenu);
            }
        });

        document.addEventListener('click', (e) => {
            if (!avatarButton.contains(e.target) && !dropdownMenu.contains(e.target)) {
                this.closeDropdown(avatarButton, dropdownMenu);
            }
        });

        dropdownMenu.addEventListener('click', (e) => {
            if (e.target.closest('.user-dropdown-item')) {
                this.closeDropdown(avatarButton, dropdownMenu);
            }
        });
    }

    /**
     * Initialize notification bell
     */
    static initNotificationBell() {
        try {
            const notificationsButton = document.getElementById('header-notifications-button');

            if (notificationsButton) {
                notificationsButton.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    this.handleNotificationBellClick();
                });
            }

            setTimeout(() => {
                this.updateNotificationCount().catch(err => {
                    console.warn('[Header] Failed to update notification count:', err);
                });
            }, 100);
        } catch (error) {
            console.error('[Header] Error initializing notification features:', error);
        }
    }

    /**
     * Handle notification bell click.
     * Standalone messenger has no separate notifications page, so this is a
     * safe no-op (kept for any external reference). Never navigates.
     */
    static handleNotificationBellClick() {
        // No dedicated notifications page in the standalone messenger app.
    }

    /**
     * Initialize messenger button.
     * The brand/title already links to the messenger, so there is no longer a
     * dedicated messenger button in the rendered nav. Kept as a defensive,
     * null-checked no-op so any external reference still resolves.
     */
    static initMessengerButton() {
        try {
            const messengerButton = document.getElementById('header-messenger-button');

            if (messengerButton) {
                messengerButton.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    this.handleMessengerButtonClick();
                });
            }
        } catch (error) {
            console.error('[Header] Error initializing messenger button:', error);
        }
    }

    /**
     * Handle messenger button click
     */
    static handleMessengerButtonClick() {
        const messengerUrl = this.getModulePath('messaging') + 'messenger.html';
        window.location.href = messengerUrl;
    }

    /**
     * Update notification count in header
     * Checks both notifications and unread messages
     */
    static async updateNotificationCount() {
        // Clear any pending debounced call
        if (this.notificationCountUpdateTimeout) {
            clearTimeout(this.notificationCountUpdateTimeout);
            this.notificationCountUpdateTimeout = null;
        }

        // If an update is already in progress, debounce this call
        if (this.notificationCountUpdateInProgress) {
            this.notificationCountUpdateTimeout = setTimeout(() => {
                this.updateNotificationCount();
            }, 500);
            return;
        }

        // Mark as in progress
        this.notificationCountUpdateInProgress = true;

        try {
            console.log('[Header] ========== updateNotificationCount() CALLED ==========');
            console.log('[Header] updateNotificationCount() - Start time:', new Date().toISOString());
            console.log('[Header] Checking authentication status...');
            if (!window.AuthService || !window.AuthService.isAuthenticated()) {
                console.log('[Header] User not authenticated, skipping notification count update');
                return;
            }
            console.log('[Header] User is authenticated');

            console.log('[Header] Getting current user ID...');
            const currentUserId = await window.DatabaseService?._getCurrentUserId();
            console.log('[Header] Current user ID:', currentUserId);
            if (!currentUserId) {
                console.log('[Header] No user ID found, skipping notification count update');
                return;
            }

            let totalUnreadCount = 0;

            // Get unread notification count
            console.log('[Header] Checking for NotificationService...');
            if (typeof window.NotificationService !== 'undefined') {
                console.log('[Header] NotificationService is available, calling getUnreadCount()...');
                try {
                    const notificationStartTime = Date.now();
                    const notificationResult = await window.NotificationService.getUnreadCount(currentUserId);
                    const notificationDuration = Date.now() - notificationStartTime;
                    console.log('[Header] NotificationService.getUnreadCount() completed in', notificationDuration, 'ms');
                    console.log('[Header] NotificationService.getUnreadCount() result:', {
                        success: notificationResult.success,
                        count: notificationResult.count,
                        error: notificationResult.error
                    });
                    
                    if (notificationResult.success) {
                        totalUnreadCount += notificationResult.count || 0;
                        console.log('[Header] Unread notifications:', notificationResult.count || 0);
                    } else {
                        console.warn('[Header] NotificationService.getUnreadCount() failed:', notificationResult.error);
                    }
                } catch (notifError) {
                    console.error('[Header] Exception getting notification count:', {
                        error: notifError.message,
                        stack: notifError.stack
                    });
                }
            } else {
                console.warn('[Header] NotificationService is not available');
            }

            // Also check for unread messages (in case notifications weren't created)
            console.log('[Header] Checking for MessagingService...');
            if (typeof window.MessagingService !== 'undefined') {
                console.log('[Header] MessagingService is available, calling getUnreadCount()...');
                try {
                    const messageStartTime = Date.now();
                    const messageResult = await window.MessagingService.getUnreadCount(currentUserId);
                    const messageDuration = Date.now() - messageStartTime;
                    console.log('[Header] MessagingService.getUnreadCount() completed in', messageDuration, 'ms');
                    console.log('[Header] MessagingService.getUnreadCount() result:', {
                        success: messageResult.success,
                        count: messageResult.count,
                        error: messageResult.error
                    });
                    
                    if (messageResult.success) {
                        const unreadMessages = messageResult.count || 0;
                        console.log('[Header] Unread messages count:', unreadMessages);
                        console.log('[Header] Current total unread count before adding messages:', totalUnreadCount);
                        
                        // Only add message count if there's no notification for it
                        // This prevents double counting, but ensures we catch messages even if notifications fail
                        if (unreadMessages > 0) {
                            console.log('[Header] Found unread messages:', unreadMessages);
                            // Check if we already have notifications for these messages
                            // If notification count is 0 but we have unread messages, add them
                            if (totalUnreadCount === 0 && unreadMessages > 0) {
                                console.log('[Header] Adding unread messages to total count (no notifications found)');
                                totalUnreadCount += unreadMessages;
                            } else {
                                console.log('[Header] Not adding unread messages to total (already have notifications or no unread messages)');
                            }
                        } else {
                            console.log('[Header] No unread messages found');
                        }
                    } else {
                        console.warn('[Header] MessagingService.getUnreadCount() failed:', messageResult.error);
                    }
                } catch (messageError) {
                    console.error('[Header] Exception getting message count:', {
                        error: messageError.message,
                        stack: messageError.stack
                    });
                }
            } else {
                console.warn('[Header] MessagingService is not available');
            }

            console.log('[Header] Total unread count (notifications + messages):', totalUnreadCount);

            const countBadge = document.getElementById('header-notification-count');
            const avatarBadge = document.getElementById('avatar-notification-badge');

            // Update badge in the user menu dropdown
            if (countBadge) {
                if (totalUnreadCount > 0) {
                    countBadge.textContent = totalUnreadCount > 99 ? '99+' : totalUnreadCount.toString();
                    countBadge.style.display = 'inline-block';
                } else {
                    countBadge.style.display = 'none';
                }
            }

            // Update badge on avatar icon
            if (avatarBadge) {
                if (totalUnreadCount > 0) {
                    avatarBadge.textContent = totalUnreadCount > 99 ? '99+' : totalUnreadCount.toString();
                    avatarBadge.style.display = 'inline-block';
                } else {
                    avatarBadge.style.display = 'none';
                }
            }
        } catch (error) {
            console.error('[Header] Error updating notification count:', error);
        } finally {
            // Mark as complete
            this.notificationCountUpdateInProgress = false;
        }
    }

    /**
     * Setup real-time notification subscription
     */
    static async setupNotificationSubscription() {
        // Prevent duplicate subscriptions
        if (this.notificationSubscriptionSetup) {
            return;
        }

        try {
            if (typeof window.NotificationService === 'undefined' || !window.AuthService || !window.AuthService.isAuthenticated()) {
                return;
            }

            const currentUserId = await window.DatabaseService?._getCurrentUserId();
            if (!currentUserId) {
                return;
            }

            const result = await window.NotificationService.subscribeToNotifications(currentUserId, (payload) => {
                console.log('[Header] Notification update received:', payload);
                this.updateNotificationCount();
            });

            if (result.success) {
                console.log('[Header] Real-time notification subscription established');
                this.notificationSubscriptionSetup = true;
            } else {
                console.warn('[Header] Real-time subscription not available, will poll instead');
                if (!this._notificationPollInterval) {
                    this._notificationPollInterval = setInterval(() => this.updateNotificationCount(), 30000);
                }
            }
        } catch (error) {
            console.error('[Header] Error setting up notification subscription:', error);
            if (!this._notificationPollInterval) {
                this._notificationPollInterval = setInterval(() => this.updateNotificationCount(), 30000);
            }
        }
    }

    /**
     * Setup real-time message subscription to update notification count when new messages arrive
     */
    static async setupMessageSubscription() {
        // Prevent duplicate subscriptions
        if (this.messageSubscriptionSetup) {
            return;
        }

        try {
            if (typeof window.MessagingService === 'undefined' || !window.AuthService || !window.AuthService.isAuthenticated()) {
                return;
            }

            const currentUserId = await window.DatabaseService?._getCurrentUserId();
            if (!currentUserId) {
                return;
            }

            console.log('[Header] Setting up message subscription for user:', currentUserId);
            const result = await window.MessagingService.subscribeToMessages(currentUserId, (payload) => {
                console.log('[Header] Message update received:', payload);
                // When a new message arrives, update notification count
                // This ensures the badge updates even if notification creation is delayed
                setTimeout(() => {
                    this.updateNotificationCount();
                }, 500); // Small delay to allow notification to be created
            });

            if (result.success) {
                console.log('[Header] Real-time message subscription established');
                this.messageSubscriptionSetup = true;
            } else {
                console.warn('[Header] Real-time message subscription not available');
            }
        } catch (error) {
            console.error('[Header] Error setting up message subscription:', error);
        }
    }

    /**
     * Initialize sign out button
     */
    static initSignOutButton() {
        const signOutButton = document.getElementById('header-signout-button');
        if (signOutButton) {
            signOutButton.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                
                // Disable button immediately to prevent multiple clicks
                signOutButton.disabled = true;
                signOutButton.textContent = 'Signing out...';
                
                // Call signOut - it handles everything including redirect
                // Don't await - signOut will redirect immediately
                if (window.AuthService) {
                    window.AuthService.signOut().catch(error => {
                        // If signOut fails, force redirect anyway
                        console.error('[Header] Sign out error, forcing redirect:', error);
                        // Use absolute URL to avoid path resolution issues
                        const baseUrl = window.location.origin;
                        const currentPath = window.location.pathname;
                        const pathParts = currentPath.split('/').filter(p => p && p !== 'index.html');

                        // Get all module names from registry
                        const modules = window.ModuleRegistry?.getAllModuleNames() || [];

                        // Find the base path (everything before any known module or 'ui')
                        let basePathParts = [];
                        for (let i = 0; i < pathParts.length; i++) {
                            if (pathParts[i] === 'ui' || modules.includes(pathParts[i])) {
                                break;
                            }
                            basePathParts.push(pathParts[i]);
                        }

                        const basePath = basePathParts.length > 0 ? basePathParts.join('/') + '/' : '';
                        const authUrl = `${baseUrl}/${basePath}auth/views/auth.html`;
                        console.log('[Header] Redirecting to auth:', authUrl);
                        window.location.href = authUrl;
                    });
                } else {
                    // Fallback if AuthService not available - use absolute URL
                    const baseUrl = window.location.origin;
                    const currentPath = window.location.pathname;
                    const pathParts = currentPath.split('/').filter(p => p && p !== 'index.html');

                    // Get all module names from registry
                    const modules = window.ModuleRegistry?.getAllModuleNames() || [];

                    let basePathParts = [];
                    for (let i = 0; i < pathParts.length; i++) {
                        if (pathParts[i] === 'ui' || modules.includes(pathParts[i])) {
                            break;
                        }
                        basePathParts.push(pathParts[i]);
                    }

                    const basePath = basePathParts.length > 0 ? basePathParts.join('/') + '/' : '';
                    const authUrl = `${baseUrl}/${basePath}auth/views/auth.html`;
                    console.log('[Header] Fallback redirect to auth:', authUrl);
                    window.location.href = authUrl;
                }
            });
        }
    }

    /**
     * Setup auth state listener to update header when auth state changes
     */
    static setupAuthStateListener() {
        console.log('[Header] Setting up auth state listener...');
        
        // Remove existing listeners to prevent duplicates
        if (this._authSignInHandler) {
            window.removeEventListener('auth:signin', this._authSignInHandler);
        }
        if (this._authSignOutHandler) {
            window.removeEventListener('auth:signout', this._authSignOutHandler);
        }
        if (this._authInitialSessionHandler) {
            window.removeEventListener('auth:initial_session', this._authInitialSessionHandler);
        }
        
        // Create handler functions
        this._authSignInHandler = () => {
            console.log('[Header] auth:signin event received, updating header...');
            // Clear last update state to force update
            this.lastUpdateState = null;
            // Longer delay to ensure AuthService state is fully updated
            setTimeout(() => {
                this.updateHeader(true); // Force update on sign-in
            }, 300);
        };
        
        this._authSignOutHandler = () => {
            console.log('[Header] auth:signout event received, updating header...');
            this.updateHeader();
        };
        
        // Listen for initial session event (only once, with debounce)
        this._authInitialSessionHandler = () => {
            console.log('[Header] auth:initial_session event received');
            // Only update if we haven't updated recently (debounce)
            if (!this.updateInProgress) {
                setTimeout(() => {
                    if (!this.updateInProgress) {
                        console.log('[Header] Executing header update after initial_session event (200ms delay)...');
                        this.updateHeader();
                    }
                }, 200);
            }
        };
        
        // Listen for auth state changes
        window.addEventListener('auth:signin', this._authSignInHandler);
        window.addEventListener('auth:signout', this._authSignOutHandler);
        window.addEventListener('auth:initial_session', this._authInitialSessionHandler);
        
        console.log('[Header] Auth state listener set up successfully');
    }

    /**
     * Update header to reflect current auth state
     * @param {boolean} force - Force update even if state appears unchanged
     */
    static async updateHeader(force = false) {
        console.log('[Header] ========== UPDATE HEADER CALLED ==========', { force });
        
        if (this.updateInProgress && !force) {
            console.log('[Header] Update already in progress, skipping duplicate call');
            return;
        }
        
        this.updateInProgress = true;
        console.log('[Header] updateHeader() called', { force });
        
        try {
            const header = document.querySelector('.main-header');
            console.log('[Header] Header element found:', !!header);
            
            if (!header) {
                console.warn('[Header] Header element not found in DOM');
                this.updateInProgress = false;
                return;
            }
            
            const nav = header.querySelector('.main-navigation');
            console.log('[Header] Navigation element found:', !!nav);
            
            if (!nav) {
                console.warn('[Header] Navigation element not found in header');
                this.updateInProgress = false;
                return;
            }
            
            // Check authentication status
            // Be more resilient - check both isAuthenticated() and direct session/user state
            let isAuthenticated = false;
            let currentUserEmail = null;
            if (window.AuthService) {
                try {
                    // Check both the method and direct state to handle timeout scenarios
                    const methodCheck = window.AuthService.isAuthenticated();
                    const directCheck = window.AuthService.currentUser !== null && window.AuthService.session !== null;
                    
                    // If method check fails but direct check passes, try refreshing session
                    if (!methodCheck && directCheck) {
                        console.log('[Header] Method check failed but session exists, attempting session refresh...');
                        try {
                            // Try to refresh the session check
                            const sessionResult = await window.AuthService.client?.auth?.getSession();
                            if (sessionResult?.data?.session) {
                                console.log('[Header] Session refresh successful, user is authenticated');
                                isAuthenticated = true;
                            } else {
                                console.log('[Header] Session refresh found no session');
                                isAuthenticated = false;
                            }
                        } catch (sessionError) {
                            console.warn('[Header] Session refresh failed, using direct check:', sessionError);
                            // Fall back to direct check if session refresh fails
                            isAuthenticated = directCheck;
                        }
                    } else {
                        isAuthenticated = methodCheck || directCheck;
                    }
                    
                    const user = window.AuthService.getCurrentUser() || window.AuthService.currentUser;
                    currentUserEmail = user?.email || null;
                    
                    // If still not authenticated on force update, wait a bit and retry (for sign-in timing issues)
                    if (!isAuthenticated && force) {
                        console.log('[Header] Auth check failed on force update, retrying after delay...');
                        this.updateInProgress = false; // Reset to allow retry
                        setTimeout(() => {
                            // Recursively call updateHeader with force to retry
                            this.updateHeader(true);
                        }, 300);
                        return;
                    }
                } catch (authError) {
                    console.error('[Header] Error checking authentication state:', authError);
                    // On error, try to use cached state or direct check as fallback
                    const directCheck = window.AuthService.currentUser !== null && window.AuthService.session !== null;
                    isAuthenticated = directCheck;
                    const user = window.AuthService.currentUser;
                    currentUserEmail = user?.email || null;
                }
            }
            
            this._performHeaderUpdate(nav, isAuthenticated, currentUserEmail, force);
        } catch (error) {
            console.error('[Header] Error in updateHeader:', error);
            this.updateInProgress = false;
        }
    }
    
    /**
     * Perform the actual header update
     * @private
     */
    static _performHeaderUpdate(nav, isAuthenticated, currentUserEmail, force) {
        try {
            const currentState = {
                isAuthenticated: isAuthenticated,
                userEmail: currentUserEmail
            };
            
            // Check if state has actually changed (unless forced)
            if (!force && this.lastUpdateState && 
                this.lastUpdateState.isAuthenticated === currentState.isAuthenticated &&
                this.lastUpdateState.userEmail === currentState.userEmail) {
                console.log('[Header] Auth state unchanged, skipping update');
                this.updateInProgress = false;
                return;
            }
            
            console.log('[Header] Authentication status:', {
                hasAuthService: !!window.AuthService,
                isAuthenticated: isAuthenticated,
                methodCheck: window.AuthService?.isAuthenticated(),
                directCheck: window.AuthService?.currentUser !== null && window.AuthService?.session !== null,
                hasCurrentUser: !!window.AuthService?.getCurrentUser(),
                userEmail: currentUserEmail
            });
            
            const oldUserMenu = nav.querySelector('.header-user-menu');
            if (oldUserMenu) {
                console.log('[Header] Removing existing user menu');
                oldUserMenu.remove();
            }
            
            // Add user menu if authenticated
            if (isAuthenticated) {
                // Get user info with fallback to direct access
                const user = window.AuthService.getCurrentUser() || window.AuthService.currentUser;
                if (!user) {
                    console.warn('[Header] User appears authenticated but user object is null, skipping user menu');
                    this.updateInProgress = false;
                    return;
                }
                
                const userEmail = user?.email || 'User';
                const userInitials = this.getUserInitials(userEmail);

                console.log('[Header] Adding user menu:', {
                    userEmail: userEmail,
                    userInitials: userInitials
                });

                const userInfoHtml = this._renderUserMenu(userEmail, userInitials);
                nav.insertAdjacentHTML('beforeend', userInfoHtml);
                this.initUserMenu();
                this.initSignOutButton();
                this.initNotificationBell(); // Wire (safe) message-count badge refresh
                this.initMessengerButton(); // Kept as a defensive no-op (button absent)

                // Note: updateNotificationCount and subscriptions are already set up in init()
                // Only set up subscriptions if they haven't been set up yet
                try {
                    this.setupNotificationSubscription().catch(err => {
                        console.warn('[Header] Failed to setup notification subscription in updateHeader:', err);
                    });
                    this.setupMessageSubscription().catch(err => {
                        console.warn('[Header] Failed to setup message subscription in updateHeader:', err);
                    });
                } catch (error) {
                    console.error('[Header] Error initializing notification features in updateHeader:', error);
                }
                
                console.log('[Header] User menu added successfully');
            } else {
                console.log('[Header] User not authenticated, not adding user menu');
            }
            
            this.lastUpdateState = currentState;
            console.log('[Header] ========== UPDATE HEADER COMPLETE ==========');
            this.updateInProgress = false;
        } catch (error) {
            console.error('[Header] Error in _performHeaderUpdate:', error);
            this.updateInProgress = false;
        }
    }
}

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => Header.init());
} else {
    Header.init();
}

// Export to window for global access
if (typeof window !== 'undefined') {
    window.Header = Header;
    console.log('[Header] Header class assigned to window.Header');
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = Header;
}

