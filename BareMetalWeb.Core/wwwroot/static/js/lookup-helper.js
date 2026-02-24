// Lookup field refresh, add, and high-cardinality search dialog functionality
(function() {
    'use strict';

    // Clean up cache-busting params from the URL after page load
    if (window.location.search.includes('_refresh')) {
        var cleanUrl = new URL(window.location.href);
        cleanUrl.searchParams.delete('_refresh');
        cleanUrl.searchParams.delete('_field');
        window.history.replaceState(null, '', cleanUrl.toString());
    }

    function refreshLookup(fieldName) {
        var selectElement = document.getElementById(fieldName);
        if (!selectElement) return;
        selectElement.disabled = true;
        var url = new URL(window.location.href);
        url.searchParams.set('_refresh', Date.now());
        url.searchParams.set('_field', fieldName);
        window.location.href = url.toString();
    }

    function addLookupItem(targetSlug, fieldName) {
        if (!targetSlug) return;
        var createUrl = '/admin/data/' + targetSlug + '/create?popup=1';
        var newWindow = window.open(createUrl, '_blank', 'width=800,height=600');
        if (!newWindow) {
            alert('Please allow popups for this site, or the create form will open in the same window.');
            window.location.href = createUrl;
        } else {
            var checkWindow = setInterval(function() {
                if (newWindow.closed) {
                    clearInterval(checkWindow);
                    refreshLookup(fieldName);
                }
            }, 500);
        }
    }

    // --- High-cardinality search dialog ---

    var _searchModal = null;
    var _searchDebounce = null;

    function getOrCreateSearchModal() {
        if (_searchModal) return _searchModal;
        var el = document.createElement('div');
        el.className = 'modal fade';
        el.id = 'bm-lookup-search-modal';
        el.setAttribute('tabindex', '-1');
        el.setAttribute('aria-hidden', 'true');
        el.innerHTML =
            '<div class="modal-dialog modal-lg modal-dialog-scrollable">' +
              '<div class="modal-content">' +
                '<div class="modal-header">' +
                  '<h5 class="modal-title" id="bm-lookup-search-title">Search</h5>' +
                  '<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>' +
                '</div>' +
                '<div class="modal-body">' +
                  '<div class="mb-3">' +
                    '<input type="text" class="form-control" id="bm-lookup-search-input" placeholder="Type to search..." autocomplete="off" />' +
                  '</div>' +
                  '<div id="bm-lookup-search-results"><p class="text-muted small">Enter search terms above to find matching records.</p></div>' +
                '</div>' +
                '<div class="modal-footer">' +
                  '<button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>' +
                '</div>' +
              '</div>' +
            '</div>';
        document.body.appendChild(el);
        _searchModal = el;

        // Wire up the search input
        document.getElementById('bm-lookup-search-input').addEventListener('input', function() {
            clearTimeout(_searchDebounce);
            _searchDebounce = setTimeout(function() {
                doLookupSearch();
            }, 300);
        });

        return _searchModal;
    }

    function openLookupSearch(targetSlug, fieldId, displayFieldId, displayField, valueField, targetTypeName) {
        var modal = getOrCreateSearchModal();
        modal.dataset.targetSlug = targetSlug;
        modal.dataset.fieldId = fieldId;
        modal.dataset.displayFieldId = displayFieldId;
        modal.dataset.displayField = displayField;
        modal.dataset.valueField = valueField || 'id';

        var title = document.getElementById('bm-lookup-search-title');
        if (title) title.textContent = 'Search ' + (targetTypeName || '');

        var input = document.getElementById('bm-lookup-search-input');
        if (input) input.value = '';
        var results = document.getElementById('bm-lookup-search-results');
        if (results) results.innerHTML = '<p class="text-muted small">Enter search terms above to find matching records.</p>';

        var bsModal = new bootstrap.Modal(modal);
        bsModal.show();
        if (input) setTimeout(function() { input.focus(); }, 300);
    }

    function doLookupSearch() {
        var modal = document.getElementById('bm-lookup-search-modal');
        if (!modal) return;
        var targetSlug = modal.dataset.targetSlug;
        var displayField = modal.dataset.displayField;
        var searchInput = document.getElementById('bm-lookup-search-input');
        var resultsEl = document.getElementById('bm-lookup-search-results');
        if (!targetSlug || !resultsEl) return;

        var term = searchInput ? searchInput.value.trim() : '';
        if (term.length === 0) {
            resultsEl.innerHTML = '<p class="text-muted small">Enter search terms above to find matching records.</p>';
            return;
        }

        resultsEl.innerHTML = '<p class="text-muted small">Searching...</p>';

        var url = '/api/_lookup/' + encodeURIComponent(targetSlug) +
            '?search=' + encodeURIComponent(term) +
            '&searchField=' + encodeURIComponent(displayField) +
            '&top=30';

        fetch(url, { credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                var rows = (data && data.data) ? data.data : [];
                if (rows.length === 0) {
                    resultsEl.innerHTML = '<p class="text-muted small">No results found.</p>';
                    return;
                }
                // Build a simple table from the results
                var keys = Object.keys(rows[0]);
                var html = '<table class="table table-sm table-hover table-striped bm-table"><thead><tr>';
                keys.forEach(function(k) {
                    html += '<th>' + escapeHtml(k) + '</th>';
                });
                html += '</tr></thead><tbody>';
                rows.forEach(function(row) {
                    html += '<tr style="cursor:pointer" data-bm-select-row>';
                    keys.forEach(function(k) {
                        html += '<td data-field="' + escapeHtml(k) + '">' + escapeHtml(row[k] != null ? String(row[k]) : '') + '</td>';
                    });
                    html += '</tr>';
                });
                html += '</tbody></table>';
                resultsEl.innerHTML = html;
            })
            .catch(function() {
                resultsEl.innerHTML = '<p class="text-danger small">Error fetching results.</p>';
            });
    }

    function escapeHtml(str) {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    // Handle row selection in the search modal
    document.addEventListener('click', function(e) {
        var row = e.target.closest('[data-bm-select-row]');
        if (row) {
            var modal = document.getElementById('bm-lookup-search-modal');
            if (!modal) return;
            var fieldId = modal.dataset.fieldId;
            var displayFieldId = modal.dataset.displayFieldId;
            // displayField may be PascalCase (e.g. "Name"); JSON keys in the table are camelCase
            var displayField = modal.dataset.displayField || '';
            var displayFieldKey = displayField.length > 0
                ? displayField.charAt(0).toLowerCase() + displayField.slice(1)
                : displayField;
            var valueField = modal.dataset.valueField || 'id';

            // Get value and display value from the selected row cells
            var valueCell = row.querySelector('td[data-field="' + valueField + '"]');
            var displayCell = row.querySelector('td[data-field="' + displayFieldKey + '"]');

            var idValue = valueCell ? valueCell.textContent : '';
            var displayValue = displayCell ? displayCell.textContent : idValue;

            // Set the hidden field value
            var hiddenInput = document.getElementById(fieldId);
            if (hiddenInput) hiddenInput.value = idValue;

            // Set the display text
            var displayInput = document.getElementById(displayFieldId);
            if (displayInput) displayInput.value = displayValue;

            // Close modal
            var bsModal = bootstrap.Modal.getInstance(modal);
            if (bsModal) bsModal.hide();
            return;
        }
    });

    // Bind via event delegation — no inline onclick needed
    document.addEventListener('click', function(e) {
        var refreshBtn = e.target.closest('[data-lookup-refresh]');
        if (refreshBtn) {
            e.preventDefault();
            refreshLookup(refreshBtn.getAttribute('data-lookup-refresh'));
            return;
        }
        var addBtn = e.target.closest('[data-lookup-add]');
        if (addBtn) {
            e.preventDefault();
            addLookupItem(addBtn.getAttribute('data-lookup-add'), addBtn.getAttribute('data-lookup-field'));
            return;
        }
        var searchBtn = e.target.closest('[data-lookup-search]');
        if (searchBtn) {
            e.preventDefault();
            var slug = searchBtn.getAttribute('data-lookup-search');
            var fieldId = searchBtn.getAttribute('data-lookup-field');
            var displayFieldId = searchBtn.getAttribute('data-lookup-display');
            var displayField = searchBtn.getAttribute('data-lookup-display-field');
            var valueField = searchBtn.getAttribute('data-lookup-value-field') || 'id';
            var targetType = searchBtn.getAttribute('title') || '';
            openLookupSearch(slug, fieldId, displayFieldId, displayField, valueField, targetType.replace('Search ', ''));
        }
    });
})();
