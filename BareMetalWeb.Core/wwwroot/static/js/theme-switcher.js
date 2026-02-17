// Theme switcher for Bootswatch CDN themes
(function() {
    'use strict';

    const BOOTSWATCH_VERSION = '5.3.3';
    const BOOTSWATCH_CDN_BASE = `https://cdn.jsdelivr.net/npm/bootswatch@${BOOTSWATCH_VERSION}/dist`;
    const STORAGE_KEY = 'bm-selected-theme';

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
        
        if (themeName === 'contrast' || themeName === 'muted') {
            // Use built-in CSS custom properties for HC and Muted (defined in site.css)
            // The :has() selectors automatically apply when radio buttons are checked
            themeLink.href = '';
        } else {
            // Use Bootswatch CDN for other themes
            themeLink.href = `${BOOTSWATCH_CDN_BASE}/${themeName}/bootstrap.min.css`;
        }
        
        // Clear any body classes that might interfere
        document.body.className = '';
        
        // Save preference
        localStorage.setItem(STORAGE_KEY, themeName);
    }

    // Initialize theme switcher
    function init() {
        const switcher = document.querySelector('.bm-theme-switcher');
        if (!switcher) return;

        // Load saved theme or default to 'darkly'
        const savedTheme = localStorage.getItem(STORAGE_KEY) || 'darkly';
        const savedInput = document.getElementById(`theme-${savedTheme}`);
        if (savedInput) {
            savedInput.checked = true;
            applyTheme(savedTheme);
        }

        // Listen for theme changes
        switcher.addEventListener('change', function(e) {
            if (e.target.name === 'bm-theme') {
                applyTheme(e.target.value);
            }
        });
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
