// Lookup field refresh and add functionality
(function() {
    'use strict';

    // Clean up cache-busting params from the URL after page load
    if (window.location.search.includes('_refresh')) {
        const cleanUrl = new URL(window.location.href);
        cleanUrl.searchParams.delete('_refresh');
        cleanUrl.searchParams.delete('_field');
        window.history.replaceState(null, '', cleanUrl.toString());
    }

    // Refresh lookup field values
    window.refreshLookup = function(fieldName) {
        const selectElement = document.getElementById(fieldName);
        if (!selectElement) {
            console.error('Select element not found:', fieldName);
            return;
        }

        const currentValue = selectElement.value;
        const form = selectElement.closest('form');
        if (!form) {
            console.error('Form not found for field:', fieldName);
            return;
        }

        // Get the form action URL to determine entity type
        const formAction = form.getAttribute('action');
        if (!formAction) {
            console.error('Form action not found');
            return;
        }

        // Disable the select while refreshing
        selectElement.disabled = true;
        
        // Create a timestamp to bust cache
        const timestamp = Date.now();
        
        // Reload the current page with a cache-busting parameter
        // This will force the server to regenerate the form with fresh lookup values
        const url = new URL(window.location.href);
        url.searchParams.set('_refresh', timestamp);
        url.searchParams.set('_field', fieldName);
        
        window.location.href = url.toString();
    };

    // Add new lookup item
    window.addLookupItem = function(targetSlug, fieldName) {
        if (!targetSlug) {
            console.error('Target slug not provided');
            return;
        }

        // Open the create page for the target entity in a new window
        const createUrl = `/admin/data/${targetSlug}/create`;
        const newWindow = window.open(createUrl, '_blank', 'width=800,height=600');
        
        if (!newWindow) {
            // Popup blocked, fall back to same-window navigation
            // Store the current form state before navigating
            alert('Please allow popups for this site, or the create form will open in the same window.');
            window.location.href = createUrl;
        } else {
            // Listen for the window to close and refresh the lookup
            const checkWindow = setInterval(function() {
                if (newWindow.closed) {
                    clearInterval(checkWindow);
                    // Refresh the lookup after the window closes
                    window.refreshLookup(fieldName);
                }
            }, 500);
        }
    };
})();
