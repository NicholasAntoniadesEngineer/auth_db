/**
 * Module Registry
 * Central registry of all application modules with their capabilities
 * @module ui/config/module-registry
 */

const ModuleRegistry = {
    /**
     * List of all application modules
     * @type {Array<{name: string, hasController: boolean, hasService: boolean, hasViews: boolean}>}
     */
    modules: [
        { name: 'auth', hasController: false, hasService: false, hasViews: true },
        { name: 'landing', hasController: true, hasService: false, hasViews: false },
        { name: 'monthlyBudget', hasController: true, hasService: false, hasViews: true },
        { name: 'notifications', hasController: true, hasService: false, hasViews: true },
        { name: 'pots', hasController: true, hasService: false, hasViews: true },
        { name: 'settings', hasController: true, hasService: false, hasViews: true },
        { name: 'payments', hasController: true, hasService: true, hasViews: true },
        { name: 'messaging', hasController: true, hasService: true, hasViews: true }
    ],

    /**
     * Get all module names
     * @returns {string[]} Array of module names
     */
    getAllModuleNames() {
        return this.modules.map(m => m.name);
    },

    /**
     * Check if a module name is valid
     * @param {string} name - Module name to check
     * @returns {boolean} True if module exists
     */
    isValidModule(name) {
        return this.modules.some(m => m.name === name);
    },

    /**
     * Get module info by name
     * @param {string} name - Module name
     * @returns {Object|null} Module info or null if not found
     */
    getModule(name) {
        return this.modules.find(m => m.name === name) || null;
    },

    /**
     * Get all modules with controllers
     * @returns {string[]} Array of module names with controllers
     */
    getModulesWithControllers() {
        return this.modules.filter(m => m.hasController).map(m => m.name);
    },

    /**
     * Get all modules with services
     * @returns {string[]} Array of module names with services
     */
    getModulesWithServices() {
        return this.modules.filter(m => m.hasService).map(m => m.name);
    }
};

// Make available globally
if (typeof window !== 'undefined') {
    window.ModuleRegistry = ModuleRegistry;
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ModuleRegistry;
}
