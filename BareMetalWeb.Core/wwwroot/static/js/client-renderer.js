// BareMetalWeb Client-Side Template Engine
// Minimal implementation matching server {{token}} and {{Loop%%key}} syntax
// ~2-3KB uncompressed, zero dependencies
(function(window) {
    'use strict';

    /**
     * Simple template engine that matches BareMetalWeb server-side syntax
     * Supports: {{token}}, {{Loop%%key}}...{{EndLoop}}, {{For%%i|from|to|increment}}...{{EndFor}}
     */
    const TemplateEngine = {
        /**
         * Render a template with data
         * @param {string} template - Template string with {{tokens}}
         * @param {Object} data - Data object with key-value pairs
         * @param {Object} loops - Optional loop data (key -> array of objects)
         * @returns {string} Rendered HTML
         */
        render: function(template, data, loops) {
            if (!template) return '';
            
            let result = template;
            data = data || {};
            loops = loops || {};
            
            // Process loops first ({{Loop%%key}}...{{EndLoop}})
            result = this._processLoops(result, loops, data);
            
            // Process for loops ({{For%%i|from|to|increment}}...{{EndFor}})
            result = this._processForLoops(result, data);
            
            // Replace simple tokens ({{key}})
            result = this._replaceTokens(result, data);
            
            return result;
        },

        /**
         * Process {{Loop%%key}}...{{EndLoop}} blocks
         */
        _processLoops: function(template, loops, data) {
            const loopRegex = /\{\{Loop%%([^}]+)\}\}([\s\S]*?)\{\{EndLoop\}\}/g;
            
            return template.replace(loopRegex, (match, loopKey, loopContent) => {
                const loopData = loops[loopKey];
                if (!Array.isArray(loopData)) return '';
                
                return loopData.map(item => {
                    // Merge loop item data with global data (item takes precedence)
                    const mergedData = Object.assign({}, data, item);
                    return this._replaceTokens(loopContent, mergedData);
                }).join('');
            });
        },

        /**
         * Process {{For%%variable|from|to|increment}}...{{EndFor}} blocks
         */
        _processForLoops: function(template, data) {
            const forRegex = /\{\{For%%([^|]+)\|([^|]+)\|([^|]+)\|([^}]+)\}\}([\s\S]*?)\{\{EndFor\}\}/g;
            
            return template.replace(forRegex, (match, variable, from, to, increment, forContent) => {
                const start = this._parseValue(from, data);
                const end = this._parseValue(to, data);
                const step = this._parseValue(increment, data);
                
                let result = '';
                for (let i = start; i <= end; i += step) {
                    const loopData = Object.assign({}, data, { [variable]: i });
                    result += this._replaceTokens(forContent, loopData);
                }
                return result;
            });
        },

        /**
         * Replace {{token}} with values from data
         */
        _replaceTokens: function(template, data) {
            return template.replace(/\{\{([^}]+)\}\}/g, (match, key) => {
                const value = data[key];
                if (value === undefined || value === null) return '';
                return this._escapeHtml(String(value));
            });
        },

        /**
         * Parse a value that might be a number or a reference to data
         */
        _parseValue: function(value, data) {
            const num = parseFloat(value);
            if (!isNaN(num)) return num;
            return parseFloat(data[value]) || 0;
        },

        /**
         * HTML escape to prevent XSS
         */
        _escapeHtml: function(str) {
            const div = document.createElement('div');
            div.textContent = str;
            return div.innerHTML;
        },

        /**
         * Compile a template for reuse (currently just returns template, can optimize later)
         */
        compile: function(template) {
            return {
                render: (data, loops) => this.render(template, data, loops)
            };
        }
    };

    /**
     * Client-side form renderer
     */
    const FormRenderer = {
        /**
         * Render a form from JSON schema
         * @param {Object} schema - Form schema with fields array
         * @param {Object} data - Optional initial data
         * @returns {string} Rendered form HTML
         */
        render: function(schema, data) {
            if (!schema || !schema.fields) return '';
            
            data = data || {};
            let html = '<form>';
            
            schema.fields.forEach(field => {
                html += this._renderField(field, data[field.name]);
            });
            
            html += '<div class="form-group mt-3">';
            html += '<button type="submit" class="btn btn-primary">Submit</button>';
            html += '</div></form>';
            
            return html;
        },

        _renderField: function(field, value) {
            value = value || field.defaultValue || '';
            const required = field.required ? 'required' : '';
            const readonly = field.readonly ? 'readonly' : '';
            const label = this._escapeHtml(field.label || field.name);
            
            let html = '<div class="form-group mb-3">';
            html += `<label for="${field.name}" class="form-label">${label}`;
            if (field.required) html += ' <span class="text-danger">*</span>';
            html += '</label>';
            
            switch (field.type) {
                case 'textarea':
                    html += `<textarea id="${field.name}" name="${field.name}" class="form-control" ${required} ${readonly}>${this._escapeHtml(value)}</textarea>`;
                    break;
                case 'select':
                case 'lookup':
                    html += `<select id="${field.name}" name="${field.name}" class="form-select" ${required} ${readonly}>`;
                    if (field.options) {
                        field.options.forEach(opt => {
                            const selected = opt.value == value ? 'selected' : '';
                            html += `<option value="${this._escapeHtml(opt.value)}" ${selected}>${this._escapeHtml(opt.label)}</option>`;
                        });
                    }
                    html += '</select>';
                    break;
                case 'checkbox':
                case 'yesno':
                    const checked = value === true || value === 'true' || value === '1' ? 'checked' : '';
                    html += `<input type="checkbox" id="${field.name}" name="${field.name}" class="form-check-input" ${checked} ${readonly}>`;
                    break;
                case 'number':
                case 'integer':
                case 'decimal':
                case 'money':
                    html += `<input type="number" id="${field.name}" name="${field.name}" class="form-control" value="${this._escapeHtml(value)}" ${required} ${readonly}>`;
                    break;
                case 'email':
                    html += `<input type="email" id="${field.name}" name="${field.name}" class="form-control" value="${this._escapeHtml(value)}" ${required} ${readonly}>`;
                    break;
                case 'date':
                    html += `<input type="date" id="${field.name}" name="${field.name}" class="form-control" value="${this._escapeHtml(value)}" ${required} ${readonly}>`;
                    break;
                case 'time':
                    html += `<input type="time" id="${field.name}" name="${field.name}" class="form-control" value="${this._escapeHtml(value)}" ${required} ${readonly}>`;
                    break;
                case 'datetime':
                    html += `<input type="datetime-local" id="${field.name}" name="${field.name}" class="form-control" value="${this._escapeHtml(value)}" ${required} ${readonly}>`;
                    break;
                case 'password':
                    html += `<input type="password" id="${field.name}" name="${field.name}" class="form-control" ${required} ${readonly}>`;
                    break;
                default:
                    html += `<input type="text" id="${field.name}" name="${field.name}" class="form-control" value="${this._escapeHtml(value)}" ${required} ${readonly}>`;
            }
            
            if (field.help) {
                html += `<small class="form-text text-muted">${this._escapeHtml(field.help)}</small>`;
            }
            
            html += '</div>';
            return html;
        },

        _escapeHtml: function(str) {
            if (!str) return '';
            const div = document.createElement('div');
            div.textContent = String(str);
            return div.innerHTML;
        }
    };

    /**
     * Client-side table renderer with sorting/filtering
     */
    const TableRenderer = {
        /**
         * Render a table from data array
         * @param {Array} data - Array of row objects
         * @param {Array} columns - Column definitions [{key, label, sortable}]
         * @param {Object} options - Rendering options {sortable, filterable}
         * @returns {string} Rendered table HTML
         */
        render: function(data, columns, options) {
            if (!data || !columns) return '';
            
            options = options || {};
            let html = '<table class="table table-striped table-hover">';
            
            // Header
            html += '<thead><tr>';
            columns.forEach(col => {
                const sortable = options.sortable && col.sortable !== false;
                if (sortable) {
                    html += `<th data-sortable="${col.key}" style="cursor:pointer">${this._escapeHtml(col.label || col.key)} <i class="bi bi-arrow-down-up"></i></th>`;
                } else {
                    html += `<th>${this._escapeHtml(col.label || col.key)}</th>`;
                }
            });
            html += '</tr></thead>';
            
            // Body
            html += '<tbody>';
            data.forEach(row => {
                html += '<tr>';
                columns.forEach(col => {
                    const value = row[col.key];
                    html += `<td>${this._escapeHtml(value)}</td>`;
                });
                html += '</tr>';
            });
            html += '</tbody>';
            
            html += '</table>';
            return html;
        },

        /**
         * Add client-side sorting to a rendered table
         */
        enableSorting: function(tableElement) {
            const headers = tableElement.querySelectorAll('th[data-sortable]');
            let currentSort = { column: null, direction: 'asc' };
            
            headers.forEach(header => {
                header.addEventListener('click', () => {
                    const column = header.getAttribute('data-sortable');
                    const tbody = tableElement.querySelector('tbody');
                    const rows = Array.from(tbody.querySelectorAll('tr'));
                    const columnIndex = Array.from(header.parentNode.children).indexOf(header);
                    
                    // Toggle direction if same column
                    if (currentSort.column === column) {
                        currentSort.direction = currentSort.direction === 'asc' ? 'desc' : 'asc';
                    } else {
                        currentSort.column = column;
                        currentSort.direction = 'asc';
                    }
                    
                    // Sort rows
                    rows.sort((a, b) => {
                        const aVal = a.cells[columnIndex].textContent.trim();
                        const bVal = b.cells[columnIndex].textContent.trim();
                        
                        // Try numeric comparison first
                        const aNum = parseFloat(aVal);
                        const bNum = parseFloat(bVal);
                        if (!isNaN(aNum) && !isNaN(bNum)) {
                            return currentSort.direction === 'asc' ? aNum - bNum : bNum - aNum;
                        }
                        
                        // String comparison
                        return currentSort.direction === 'asc' 
                            ? aVal.localeCompare(bVal) 
                            : bVal.localeCompare(aVal);
                    });
                    
                    // Re-append rows in new order
                    rows.forEach(row => tbody.appendChild(row));
                    
                    // Update header indicators
                    headers.forEach(h => {
                        h.querySelector('i').className = 'bi bi-arrow-down-up';
                    });
                    const icon = currentSort.direction === 'asc' ? 'bi-sort-alpha-down' : 'bi-sort-alpha-up';
                    header.querySelector('i').className = `bi ${icon}`;
                });
            });
        },

        _escapeHtml: function(value) {
            if (value === undefined || value === null) return '';
            const div = document.createElement('div');
            div.textContent = String(value);
            return div.innerHTML;
        }
    };

    /**
     * Template cache for client-side templates
     */
    const TemplateCache = {
        _cache: {},
        
        /**
         * Load and cache a template from URL
         */
        load: async function(url) {
            if (this._cache[url]) {
                return this._cache[url];
            }
            
            try {
                const response = await fetch(url);
                if (!response.ok) throw new Error(`Failed to load template: ${url}`);
                const template = await response.text();
                this._cache[url] = template;
                return template;
            } catch (err) {
                console.error('Template load error:', err);
                return '';
            }
        },

        /**
         * Clear cache (useful for development)
         */
        clear: function() {
            this._cache = {};
        }
    };

    // Export to global namespace
    window.BareMetalWeb = window.BareMetalWeb || {};
    window.BareMetalWeb.TemplateEngine = TemplateEngine;
    window.BareMetalWeb.FormRenderer = FormRenderer;
    window.BareMetalWeb.TableRenderer = TableRenderer;
    window.BareMetalWeb.TemplateCache = TemplateCache;

})(window);
