// Theme switcher
(function() {
    'use strict';

    const LOCAL_THEME_PATH = '/static/css/themes/vapor.min.css';
    const THEME_PATH_PREFIX = '/static/css/themes/';
    const THEME_PATH_SUFFIX = '.min.css';
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
        themeLink.href = `${THEME_PATH_PREFIX}${themeName}${THEME_PATH_SUFFIX}`;

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

        // Skin switcher
        const SKIN_KEY = 'bm-selected-skin';
        const ALLOWED_SKINS = new Set(['default', 'sidebar', 'compact', 'focus']);

        function getStoredSkin() {
            const cookies = document.cookie ? document.cookie.split(';') : [];
            const key = `${SKIN_KEY}=`;
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.startsWith(key)) {
                    return decodeURIComponent(cookie.substring(key.length)) || 'default';
                }
            }
            return 'default';
        }

        function applySkin(name) {
            if (!ALLOWED_SKINS.has(name)) name = 'default';
            if (name === 'default') document.body.removeAttribute('data-bm-skin');
            else document.body.setAttribute('data-bm-skin', name);
            document.cookie = `${SKIN_KEY}=${encodeURIComponent(name)}; path=/; max-age=31536000; samesite=lax`;
        }

        const skinSelect = document.getElementById('bm-skin-select');
        if (skinSelect) {
            const savedSkin = getStoredSkin();
            skinSelect.value = savedSkin;
            applySkin(savedSkin);
            skinSelect.addEventListener('change', function() { applySkin(this.value); });
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
