// Lookup field refresh and add functionality
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
        var createUrl = '/admin/data/' + targetSlug + '/create';
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

    // Bind via event delegation — no inline onclick needed
    document.addEventListener('click', function(e) {
        var refreshBtn = e.target.closest('[data-lookup-refresh]');
        if (refreshBtn) {
            refreshLookup(refreshBtn.getAttribute('data-lookup-refresh'));
            return;
        }
        var addBtn = e.target.closest('[data-lookup-add]');
        if (addBtn) {
            addLookupItem(addBtn.getAttribute('data-lookup-add'), addBtn.getAttribute('data-lookup-field'));
        }
    });
})();
