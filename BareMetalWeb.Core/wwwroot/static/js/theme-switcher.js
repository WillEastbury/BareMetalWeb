// Theme switcher — BMW skin is permanent; 5 colour themes + 2 layout modes
(function() {
    'use strict';

    // BMW skin is always active — set server-side and reinforced here
    document.body.setAttribute('data-bm-skin', 'bmw');

    const THEME_PATH_PREFIX = '/static/css/themes/';
    const THEME_PATH_SUFFIX = '.min.css';
    const THEME_STORAGE_KEY = 'bm-selected-theme';
    const DEFAULT_THEME     = 'light';

    const LAYOUT_STORAGE_KEY = 'bm-selected-layout';
    const DEFAULT_LAYOUT     = 'top';

    // Allowed BMW theme names
    const ALLOWED_THEMES = new Set(['light', 'dark', 'colourful', 'muted', 'highviz',
        'ocean', 'forest', 'sunset', 'midnight', 'rose']);

    // Allowed layout names: top (horizontal navbar) or sidebar (left vertical navbar)
    const ALLOWED_LAYOUTS = new Set(['top', 'sidebar']);

    function getStoredValue(key, defaultVal) {
        const cookies = document.cookie ? document.cookie.split(';') : [];
        const prefix  = key + '=';
        for (let i = 0; i < cookies.length; i++) {
            const c = cookies[i].trim();
            if (c.startsWith(prefix)) {
                return decodeURIComponent(c.substring(prefix.length)) || defaultVal;
            }
        }
        return defaultVal;
    }

    function setStoredValue(key, val) {
        document.cookie = `${key}=${encodeURIComponent(val)}; path=/; max-age=31536000; samesite=lax`;
    }

    // Get or create the BMW theme stylesheet link element,
    // inserted after site.css so theme variables override site.css defaults.
    function getThemeLink() {
        let link = document.getElementById('bm-theme');
        if (!link) {
            link = document.createElement('link');
            link.id  = 'bm-theme';
            link.rel = 'stylesheet';
            const siteCSS = document.querySelector('link[href*="site.css"]');
            if (siteCSS) {
                // insertBefore(node, null) is equivalent to appendChild — handles last-child case
                siteCSS.parentNode.insertBefore(link, siteCSS.nextSibling);
            } else {
                document.head.appendChild(link);
            }
        }
        return link;
    }

    // Apply a colour theme by loading its minimal CSS variable file
    function applyTheme(name) {
        if (!ALLOWED_THEMES.has(name)) name = DEFAULT_THEME;
        getThemeLink().href = THEME_PATH_PREFIX + name + THEME_PATH_SUFFIX;
        setStoredValue(THEME_STORAGE_KEY, name);
    }

    // Apply a layout mode: 'top' = horizontal navbar, 'sidebar' = left vertical navbar
    function applyLayout(name) {
        if (!ALLOWED_LAYOUTS.has(name)) name = DEFAULT_LAYOUT;
        document.body.setAttribute('data-bm-layout', name);
        setStoredValue(LAYOUT_STORAGE_KEY, name);
    }

    // Initialize theme and layout switchers
    function init() {
        const themeSelect = document.getElementById('bm-theme-select');
        if (!themeSelect) return;

        const savedTheme = getStoredValue(THEME_STORAGE_KEY, DEFAULT_THEME);
        themeSelect.value = savedTheme;
        applyTheme(savedTheme);

        themeSelect.addEventListener('change', function() {
            applyTheme(this.value);
        });

        const layoutSelect = document.getElementById('bm-layout-select');
        if (layoutSelect) {
            const savedLayout = getStoredValue(LAYOUT_STORAGE_KEY, DEFAULT_LAYOUT);
            layoutSelect.value = savedLayout;
            applyLayout(savedLayout);
            layoutSelect.addEventListener('change', function() { applyLayout(this.value); });
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
