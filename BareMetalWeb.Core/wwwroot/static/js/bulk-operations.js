// Bulk operations for entity list views
(function() {
    'use strict';

    var selectedIds = new Set();
    var currentEntitySlug = null;
    var currentReturnUrl = null;

    function initializeBulkOperations() {
        var bulkContainer = document.querySelector('[data-bulk-container]');
        if (!bulkContainer) return;

        currentEntitySlug = bulkContainer.getAttribute('data-entity-slug');
        currentReturnUrl = bulkContainer.getAttribute('data-return-url') || window.location.pathname + window.location.search;
        
        // Restore selection from sessionStorage if available
        var storageKey = 'bulk_selection_' + currentEntitySlug;
        var stored = sessionStorage.getItem(storageKey);
        if (stored) {
            try {
                var ids = JSON.parse(stored);
                ids.forEach(function(id) { selectedIds.add(id); });
            } catch (e) {
                sessionStorage.removeItem(storageKey);
            }
        }
        
        updateCheckboxStates();
        updateBulkActionsBar();
    }

    function updateCheckboxStates() {
        var checkboxes = document.querySelectorAll('[data-row-checkbox]');
        checkboxes.forEach(function(cb) {
            var id = cb.getAttribute('data-row-id');
            cb.checked = selectedIds.has(id);
        });
        
        var selectAllCheckbox = document.querySelector('[data-select-all-checkbox]');
        if (selectAllCheckbox) {
            var allCheckboxes = document.querySelectorAll('[data-row-checkbox]');
            var checkedCount = Array.from(allCheckboxes).filter(function(cb) { return cb.checked; }).length;
            selectAllCheckbox.checked = allCheckboxes.length > 0 && checkedCount === allCheckboxes.length;
            selectAllCheckbox.indeterminate = checkedCount > 0 && checkedCount < allCheckboxes.length;
        }
    }

    function saveSelection() {
        if (!currentEntitySlug) return;
        var storageKey = 'bulk_selection_' + currentEntitySlug;
        sessionStorage.setItem(storageKey, JSON.stringify(Array.from(selectedIds)));
    }

    function clearSelection() {
        selectedIds.clear();
        if (currentEntitySlug) {
            var storageKey = 'bulk_selection_' + currentEntitySlug;
            sessionStorage.removeItem(storageKey);
        }
        updateCheckboxStates();
        updateBulkActionsBar();
    }

    function updateBulkActionsBar() {
        var actionsBar = document.querySelector('[data-bulk-actions-bar]');
        var countSpan = document.querySelector('[data-selected-count]');
        var totalSpan = document.querySelector('[data-total-count]');
        
        if (!actionsBar) return;
        
        var count = selectedIds.size;
        if (count === 0) {
            actionsBar.style.display = 'none';
        } else {
            actionsBar.style.display = 'block';
            if (countSpan) {
                countSpan.textContent = count;
            }
        }
    }

    function toggleRowSelection(checkbox) {
        var id = checkbox.getAttribute('data-row-id');
        if (checkbox.checked) {
            selectedIds.add(id);
        } else {
            selectedIds.delete(id);
        }
        saveSelection();
        updateCheckboxStates();
        updateBulkActionsBar();
    }

    function toggleSelectAll(checkbox) {
        var rowCheckboxes = document.querySelectorAll('[data-row-checkbox]');
        if (checkbox.checked) {
            rowCheckboxes.forEach(function(cb) {
                var id = cb.getAttribute('data-row-id');
                selectedIds.add(id);
            });
        } else {
            rowCheckboxes.forEach(function(cb) {
                var id = cb.getAttribute('data-row-id');
                selectedIds.delete(id);
            });
        }
        saveSelection();
        updateCheckboxStates();
        updateBulkActionsBar();
    }

    function executeBulkAction(actionType) {
        if (selectedIds.size === 0) {
            showToast(false, 'No records selected');
            return;
        }

        var ids = Array.from(selectedIds);
        
        if (actionType === 'delete') {
            executeBulkDelete(ids);
        } else if (actionType === 'export-csv') {
            executeBulkExport(ids, 'csv');
        } else if (actionType === 'export-json') {
            executeBulkExport(ids, 'json');
        } else if (actionType === 'export-html') {
            executeBulkExport(ids, 'html');
        }
    }

    function executeBulkDelete(ids) {
        var confirmMsg = 'Are you sure you want to delete ' + ids.length + ' record(s)? This action cannot be undone.';
        if (!confirm(confirmMsg)) return;

        var csrfToken = document.querySelector('[name="csrf_token"]');
        if (!csrfToken) {
            showToast(false, 'CSRF token not found');
            return;
        }

        var button = document.querySelector('[data-bulk-action="delete"]');
        if (button) {
            button.disabled = true;
            var originalHtml = button.innerHTML;
            button.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Deleting…';
        }

        var formData = new FormData();
        formData.append('csrf_token', csrfToken.value);
        formData.append('returnUrl', currentReturnUrl);
        ids.forEach(function(id) {
            formData.append('ids', id);
        });

        fetch('/admin/data/' + currentEntitySlug + '/bulk-delete', {
            method: 'POST',
            body: formData
        })
        .then(function(response) { return response.json(); })
        .then(function(data) {
            if (button) {
                button.disabled = false;
                button.innerHTML = originalHtml;
            }
            
            if (data.success) {
                showToast(true, data.message || (data.successCount + ' record(s) deleted successfully'));
                clearSelection();
                
                // Reload page to show updated list
                setTimeout(function() {
                    window.location.reload();
                }, 1500);
            } else {
                showToast(false, data.message || 'Bulk delete failed');
            }
        })
        .catch(function(err) {
            if (button) {
                button.disabled = false;
                button.innerHTML = originalHtml;
            }
            showToast(false, 'Request failed: ' + err.message);
        });
    }

    function executeBulkExport(ids, format) {
        var url = '/admin/data/' + currentEntitySlug + '/bulk-export?format=' + format + '&ids=' + ids.join(',');
        window.location.href = url;
        showToast(true, 'Exporting ' + ids.length + ' record(s)...');
    }

    function showToast(success, message) {
        var container = document.getElementById('bm-toast-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'bm-toast-container';
            container.className = 'position-fixed top-0 end-0 p-3';
            container.style.zIndex = '1080';
            document.body.appendChild(container);
        }
        
        var cls = success ? 'bg-success' : 'bg-danger';
        var toast = document.createElement('div');
        toast.className = 'toast align-items-center text-white ' + cls + ' border-0 show';
        toast.setAttribute('role', 'alert');
        
        var body = document.createElement('div');
        body.className = 'd-flex';
        
        var text = document.createElement('div');
        text.className = 'toast-body';
        text.textContent = message;
        
        var closeBtn = document.createElement('button');
        closeBtn.type = 'button';
        closeBtn.className = 'btn-close btn-close-white me-2 m-auto';
        closeBtn.addEventListener('click', function() { toast.remove(); });
        
        body.appendChild(text);
        body.appendChild(closeBtn);
        toast.appendChild(body);
        container.appendChild(toast);
        
        setTimeout(function() { toast.remove(); }, 5000);
    }

    // Event delegation for checkbox changes
    document.addEventListener('change', function(e) {
        if (e.target.hasAttribute('data-row-checkbox')) {
            toggleRowSelection(e.target);
        } else if (e.target.hasAttribute('data-select-all-checkbox')) {
            toggleSelectAll(e.target);
        }
    });

    // Event delegation for bulk action buttons
    document.addEventListener('click', function(e) {
        var actionBtn = e.target.closest('[data-bulk-action]');
        if (actionBtn) {
            e.preventDefault();
            var action = actionBtn.getAttribute('data-bulk-action');
            executeBulkAction(action);
        }
        
        var clearBtn = e.target.closest('[data-bulk-clear]');
        if (clearBtn) {
            e.preventDefault();
            clearSelection();
        }
    });

    // Initialize on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializeBulkOperations);
    } else {
        initializeBulkOperations();
    }
})();
