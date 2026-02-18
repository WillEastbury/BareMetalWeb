// Theme switcher
(function() {
    'use strict';

    const LOCAL_THEME_PATH = '/static/css/bootstrap.min.css';
    const STORAGE_KEY = 'bm-selected-theme';
    const DEFAULT_THEME = 'vapor';

    function setStoredTheme(themeName) {
        document.cookie = `${STORAGE_KEY}=${encodeURIComponent(themeName)}; path=/; max-age=31536000; samesite=lax`;
    }

    function getStoredTheme() {
        const cookies = document.cookie ? document.cookie.split(';') : [];
        const key = `${STORAGE_KEY}=`;

        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.startsWith(key)) {
                return decodeURIComponent(cookie.substring(key.length)) || DEFAULT_THEME;
            }
        }

        return DEFAULT_THEME;
    }

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

    // Allowed Bootswatch theme names
    const ALLOWED_THEMES = new Set([
        'cerulean', 'cosmo', 'cyborg', 'darkly', 'flatly', 'journal',
        'litera', 'lumen', 'lux', 'materia', 'minty', 'morph',
        'pulse', 'quartz', 'sandstone', 'simplex', 'sketchy', 'slate',
        'solar', 'spacelab', 'superhero', 'united', 'vapor', 'yeti', 'zephyr'
    ]);

    // Apply a theme
    function applyTheme(themeName) {
        if (!ALLOWED_THEMES.has(themeName)) {
            themeName = DEFAULT_THEME;
        }
        const themeLink = getThemeLink();

        document.body.removeAttribute('data-bs-theme');
        themeLink.href = LOCAL_THEME_PATH;

        setStoredTheme(themeName);
    }

    // Initialize theme switcher
    function init() {
        const select = document.getElementById('bm-theme-select');
        if (!select) return;

        const savedTheme = getStoredTheme();
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
