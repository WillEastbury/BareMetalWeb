// Calculated fields client-side evaluation
// Handles real-time recalculation of calculated fields based on expression dependencies

(function() {
    'use strict';

    // Track field dependencies (which fields depend on which inputs)
    const dependencies = new Map();
    
    // Track calculated field expressions
    const expressions = new Map();

    // Cache parsed AST per field to avoid JSON.parse on every recalculation (bounded)
    const _astCache = new Map();
    const AST_CACHE_MAX = 200;

    // Debounce timer
    let debounceTimer = null;
    const DEBOUNCE_MS = 150;

    /**
     * CSP-safe JSON AST evaluator. Walks the expression tree produced by
     * ExpressionNode.ToJsonAst() without using eval() or new Function().
     * @param {object} ast - The parsed AST node
     * @param {function} getField - Function(fieldName) => numeric value
     * @returns {*} The evaluated result
     */
    window.bmwEvalAst = function bmwEvalAst(ast, getField) {
        if (!ast) return 0;
        switch (ast.t) {
            case 'lit': return ast.v != null ? ast.v : 0;
            case 'field': return getField(ast.n);
            case 'bin': {
                var l = bmwEvalAst(ast.l, getField), r = bmwEvalAst(ast.r, getField);
                var ln = parseFloat(l) || 0, rn = parseFloat(r) || 0;
                switch (ast.op) {
                    case '+': return (typeof l === 'string' || typeof r === 'string') ? '' + l + r : ln + rn;
                    case '-': return ln - rn;
                    case '*': return ln * rn;
                    case '/': return rn !== 0 ? ln / rn : 0;
                    case '%': return rn !== 0 ? ln % rn : 0;
                    case '>': return ln > rn;
                    case '<': return ln < rn;
                    case '>=': return ln >= rn;
                    case '<=': return ln <= rn;
                    case '==': return ln === rn;
                    case '!=': return ln !== rn;
                }
                return 0;
            }
            case 'unary': {
                var x = parseFloat(bmwEvalAst(ast.x, getField)) || 0;
                return ast.op === '-' ? -x : x;
            }
            case 'fn': {
                var args = ast.args.map(function(a) { return bmwEvalAst(a, getField); });
                switch (ast.fn) {
                    case 'round': return args.length >= 2
                        ? Math.round(args[0] * Math.pow(10, args[1])) / Math.pow(10, args[1])
                        : Math.round(args[0]);
                    case 'min': return Math.min.apply(null, args);
                    case 'max': return Math.max.apply(null, args);
                    case 'abs': return Math.abs(args[0]);
                    case 'if': return args[0] ? args[1] : args[2];
                }
                return 0;
            }
            default: return 0;
        }
    };

    /**
     * Parses a numeric field value from the DOM.
     * Handles various input types including text, number, select, etc.
     */
    window.parseFieldValue = function(fieldName) {
        // Try to find the input element
        const input = document.querySelector(`[name="${fieldName}"]`);
        if (!input) {
            console.warn(`Field not found: ${fieldName}`);
            return 0;
        }

        let value = input.value;
        
        // Handle select elements
        if (input.tagName === 'SELECT') {
            value = input.value;
        }

        // Strip out non-numeric characters for money/number fields
        if (input.type === 'text' || input.classList.contains('money-input')) {
            // Remove currency symbols, commas, spaces
            value = value.replace(/[$,\s]/g, '');
        }

        // Parse as number
        const parsed = parseFloat(value);
        return isNaN(parsed) ? 0 : parsed;
    };

    /**
     * Rounds a number to specified decimal places.
     */
    window.roundNumber = function(value, decimals = 0) {
        const multiplier = Math.pow(10, decimals);
        return Math.round(value * multiplier) / multiplier;
    };

    /**
     * Updates a calculated field with the result of evaluating its expression.
     */
    window.updateCalculatedField = function(fieldName, value) {
        const input = document.querySelector(`[name="${fieldName}"]`);
        if (!input) {
            console.warn(`Calculated field not found: ${fieldName}`);
            return;
        }

        // Format the value appropriately
        let formattedValue = value;
        
        // Check if this is a money field
        if (input.classList.contains('money-input') || input.dataset.format === 'money') {
            formattedValue = formatMoney(value);
        } else if (typeof value === 'number') {
            // Check for decimal places in data attribute
            const decimals = parseInt(input.dataset.decimals || '2');
            formattedValue = value.toFixed(decimals);
        }

        input.value = formattedValue;

        // Trigger change event for any dependencies
        input.dispatchEvent(new Event('change', { bubbles: true }));
    };

    /**
     * Formats a number as money (e.g., 1234.56).
     */
    function formatMoney(value) {
        if (value === null || value === undefined || isNaN(value)) {
            return '0.00';
        }
        return parseFloat(value).toFixed(2);
    }

    /**
     * Recalculates all calculated fields using the CSP-safe JSON AST evaluator.
     */
    function recalculateFields() {
        // Get all calculated fields from data attributes
        const calculatedFields = document.querySelectorAll('[data-calculated="true"]');
        
        calculatedFields.forEach(field => {
            const expressionJson = field.dataset.expression;
            if (!expressionJson) return;

            try {
                // Use cached AST to avoid JSON.parse on every recalculation
                var ast = _astCache.get(field);
                if (!ast) {
                    ast = JSON.parse(expressionJson);
                    // Evict oldest if cache is full
                    if (_astCache.size >= AST_CACHE_MAX) {
                        _astCache.delete(_astCache.keys().next().value);
                    }
                    _astCache.set(field, ast);
                }
                var result = window.bmwEvalAst(ast, window.parseFieldValue);
                
                // Update the field
                const fieldName = field.name;
                updateCalculatedField(fieldName, result);
            } catch (error) {
                console.error(`Error evaluating calculated field ${field.name}:`, error);
            }
        });
    }

    /**
     * Debounced recalculation.
     */
    function debouncedRecalculate() {
        if (debounceTimer) {
            clearTimeout(debounceTimer);
        }
        debounceTimer = setTimeout(recalculateFields, DEBOUNCE_MS);
    }

    /**
     * Sets up event listeners for input changes using event delegation
     * to avoid per-element listener accumulation.
     */
    function setupEventListeners() {
        document.addEventListener('input', function(e) {
            var input = e.target;
            if ((input.tagName === 'INPUT' || input.tagName === 'SELECT' || input.tagName === 'TEXTAREA')
                && input.dataset.calculated !== 'true') {
                debouncedRecalculate();
            }
        });
        document.addEventListener('change', function(e) {
            var input = e.target;
            if ((input.tagName === 'INPUT' || input.tagName === 'SELECT' || input.tagName === 'TEXTAREA')
                && input.dataset.calculated !== 'true') {
                debouncedRecalculate();
            }
        });
    }

    /**
     * Initialize calculated fields on page load.
     */
    function initialize() {
        setupEventListeners();
        
        // Initial calculation
        recalculateFields();
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize);
    } else {
        initialize();
    }

    // Re-initialize when content is dynamically loaded (e.g., modals, AJAX)
    window.initializeCalculatedFields = initialize;

})();
