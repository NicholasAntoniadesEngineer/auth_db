/**
 * Validators Utility
 * Reusable validation functions
 * @module ui/utils/validators
 */

const Validators = {
    /**
     * Validate email format
     * @param {string} email - Email to validate
     * @returns {boolean} True if valid email format
     */
    email(email) {
        if (!email) return false;
        const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return regex.test(email);
    },

    /**
     * Check if value is not empty
     * @param {any} value - Value to check
     * @returns {boolean} True if value exists
     */
    required(value) {
        return value !== null && value !== undefined && value !== '';
    },

    /**
     * Check if string meets minimum length
     * @param {string} value - String to check
     * @param {number} length - Minimum length required
     * @returns {boolean} True if meets minimum length
     */
    minLength(value, length) {
        return value && value.length >= length;
    },

    /**
     * Validate password strength
     * @param {string} password - Password to validate
     * @returns {boolean} True if meets minimum requirements
     */
    password(password) {
        if (!password) return false;
        const minLength = window.Constants?.VALIDATION?.MIN_PASSWORD_LENGTH || 6;
        return password.length >= minLength;
    },

    /**
     * Validate year is in acceptable range
     * @param {number|string} year - Year to validate
     * @returns {boolean} True if valid year
     */
    year(year) {
        const y = parseInt(year, 10);
        const minYear = window.Constants?.VALIDATION?.MIN_YEAR || 2000;
        const maxYear = window.Constants?.VALIDATION?.MAX_YEAR || 2100;
        return !isNaN(y) && y >= minYear && y <= maxYear;
    },

    /**
     * Validate month is between 1-12
     * @param {number|string} month - Month to validate
     * @returns {boolean} True if valid month
     */
    month(month) {
        const m = parseInt(month, 10);
        const minMonth = window.Constants?.VALIDATION?.MIN_MONTH || 1;
        const maxMonth = window.Constants?.VALIDATION?.MAX_MONTH || 12;
        return !isNaN(m) && m >= minMonth && m <= maxMonth;
    },

    /**
     * Validate number is positive
     * @param {number|string} value - Value to validate
     * @returns {boolean} True if positive number
     */
    positiveNumber(value) {
        const num = parseFloat(value);
        return !isNaN(num) && num > 0;
    },

    /**
     * Validate number is non-negative (0 or positive)
     * @param {number|string} value - Value to validate
     * @returns {boolean} True if non-negative number
     */
    nonNegativeNumber(value) {
        const num = parseFloat(value);
        return !isNaN(num) && num >= 0;
    },

    /**
     * Sanitize HTML to prevent XSS
     * @param {string} html - HTML string to sanitize
     * @returns {string} Sanitized HTML
     */
    sanitizeHtml(html) {
        if (!html) return '';
        const div = document.createElement('div');
        div.textContent = html;
        return div.innerHTML;
    },

    /**
     * Validate date string format (YYYY-MM-DD)
     * @param {string} dateString - Date string to validate
     * @returns {boolean} True if valid date format
     */
    dateFormat(dateString) {
        if (!dateString) return false;
        const regex = /^\d{4}-\d{2}-\d{2}$/;
        if (!regex.test(dateString)) return false;

        const date = new Date(dateString);
        return date instanceof Date && !isNaN(date);
    },

    /**
     * Validate URL format
     * @param {string} url - URL to validate
     * @returns {boolean} True if valid URL format
     */
    url(url) {
        if (!url) return false;
        try {
            new URL(url);
            return true;
        } catch {
            return false;
        }
    },

    /**
     * Run multiple validators on a value
     * @param {any} value - Value to validate
     * @param {Array<Function>} validators - Array of validator functions
     * @returns {boolean} True if all validators pass
     */
    all(value, validators) {
        return validators.every(validator => validator(value));
    },

    /**
     * Create a validation result object
     * @param {boolean} isValid - Whether validation passed
     * @param {string} message - Error message if validation failed
     * @returns {Object} Validation result {isValid, message}
     */
    result(isValid, message = '') {
        return { isValid, message };
    }
};

// Make available globally
if (typeof window !== 'undefined') {
    window.Validators = Validators;
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = Validators;
}
