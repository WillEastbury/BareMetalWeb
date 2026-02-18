// Theme switcher
(function() {
    'use strict';

    const LOCAL_THEME_PATH = '/static/css/bootstrap.min.css';
    const STORAGE_KEY = 'bm-selected-theme';
    const DEFAULT_THEME = 'vapor';

    // Get or create the theme stylesheet link element
    function getThemeLink() {
        let link = document.getElementById('bootswatch-theme');
        if (!link) {
            link = document.createElement('link');
            link.id = 'bootswatch-theme';
            link.rel = 'stylesheet';
            // Insert before site.css to allow site.css to override
            const siteCSS = document.querySelector('link[href*="site.css"]');
            if (siteCSS) {
                siteCSS.parentNode.insertBefore(link, siteCSS);
            } else {
                document.head.appendChild(link);
            }
        }
        return link;
    }

    // Apply a theme
    function applyTheme(themeName) {
        const themeLink = getThemeLink();

        document.body.removeAttribute('data-bs-theme');
        themeLink.href = LOCAL_THEME_PATH;

        localStorage.setItem(STORAGE_KEY, themeName);
    }

    // Initialize theme switcher
    function init() {
        const select = document.getElementById('bm-theme-select');
        if (!select) return;

        const savedTheme = localStorage.getItem(STORAGE_KEY) || DEFAULT_THEME;
        select.value = savedTheme;
        applyTheme(savedTheme);

        select.addEventListener('change', function() {
            applyTheme(this.value);
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
