// Theme switcher for Bootswatch CDN themes
(function() {
    'use strict';

    const BOOTSWATCH_VERSION = '5.3.3';
    const BOOTSWATCH_CDN_BASE = `https://cdn.jsdelivr.net/npm/bootswatch@${BOOTSWATCH_VERSION}/dist`;
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

        // Remove custom theme classes from body
        document.body.classList.remove('bm-theme-contrast', 'bm-theme-muted');

        if (themeName === 'contrast') {
            themeLink.href = '';
            document.body.classList.add('bm-theme-contrast');
        } else if (themeName === 'muted') {
            themeLink.href = '';
            document.body.classList.add('bm-theme-muted');
        } else {
            themeLink.href = `${BOOTSWATCH_CDN_BASE}/${themeName}/bootstrap.min.css`;
        }

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
