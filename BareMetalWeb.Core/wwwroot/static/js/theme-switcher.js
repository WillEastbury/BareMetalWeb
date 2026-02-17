// Theme switcher - supports both Bootswatch CDN themes and custom CSS variable themes
(function() {
    const STORAGE_KEY = 'bm-selected-theme';
    const BOOTSWATCH_VERSION = '5.3.3';
    const BOOTSWATCH_CDN = `https://cdn.jsdelivr.net/npm/bootswatch@${BOOTSWATCH_VERSION}/dist/`;
    const DEFAULT_THEME = 'cosmo';
    
    // Bootswatch CDN themes (colorful options)
    const BOOTSWATCH_THEMES = ['cosmo', 'flatly', 'superhero', 'darkly', 'cyborg'];
    
    // Custom CSS variable themes (HC and Muted)
    const CUSTOM_THEMES = ['contrast', 'muted'];
    
    // Get or create the bootswatch link element
    function getBootswatchLink() {
        let link = document.getElementById('bootswatch-theme');
        if (!link) {
            link = document.createElement('link');
            link.id = 'bootswatch-theme';
            link.rel = 'stylesheet';
            const siteLink = document.querySelector('link[href*="site.css"]');
            if (siteLink) {
                siteLink.parentNode.insertBefore(link, siteLink);
            } else {
                document.head.appendChild(link);
            }
        }
        return link;
    }
    
    // Apply a Bootswatch CDN theme
    function applyBootswatchTheme(themeName) {
        const link = getBootswatchLink();
        link.href = `${BOOTSWATCH_CDN}${themeName}/bootstrap.min.css`;
        // Uncheck all custom theme radios
        CUSTOM_THEMES.forEach(name => {
            const radio = document.getElementById(`theme-${name}`);
            if (radio) radio.checked = false;
        });
    }
    
    // Apply a custom CSS variable theme
    function applyCustomTheme(themeName) {
        // Remove Bootswatch link element
        const link = document.getElementById('bootswatch-theme');
        if (link) {
            link.remove();
        }
        // Uncheck all Bootswatch radios
        BOOTSWATCH_THEMES.forEach(name => {
            const radio = document.getElementById(`theme-${name}`);
            if (radio) radio.checked = false;
        });
    }
    
    // Apply theme based on name
    function applyTheme(themeName) {
        if (BOOTSWATCH_THEMES.includes(themeName)) {
            applyBootswatchTheme(themeName);
        } else if (CUSTOM_THEMES.includes(themeName)) {
            applyCustomTheme(themeName);
        }
        
        // Update localStorage
        try {
            localStorage.setItem(STORAGE_KEY, themeName);
        } catch (e) {
            // localStorage may be unavailable (private browsing, etc.)
            if (console && console.warn) {
                console.warn('Failed to save theme preference:', e);
            }
        }
    }
    
    // Load saved theme on page load
    function loadSavedTheme() {
        let savedTheme = null;
        try {
            savedTheme = localStorage.getItem(STORAGE_KEY);
        } catch (e) {
            // localStorage may be unavailable (private browsing, etc.)
            if (console && console.warn) {
                console.warn('Failed to load saved theme preference:', e);
            }
        }
        
        if (savedTheme) {
            const radio = document.getElementById(`theme-${savedTheme}`);
            if (radio) {
                radio.checked = true;
                applyTheme(savedTheme);
                return;
            }
        }
        
        // Default to DEFAULT_THEME if no saved theme
        const defaultRadio = document.getElementById(`theme-${DEFAULT_THEME}`);
        if (defaultRadio) {
            defaultRadio.checked = true;
            applyTheme(DEFAULT_THEME);
        }
    }
    
    // Set up event listeners
    function setupEventListeners() {
        const allThemes = [...BOOTSWATCH_THEMES, ...CUSTOM_THEMES];
        allThemes.forEach(themeName => {
            const radio = document.getElementById(`theme-${themeName}`);
            if (radio) {
                radio.addEventListener('change', function() {
                    if (this.checked) {
                        applyTheme(themeName);
                    }
                });
            }
        });
    }
    
    // Initialize theme switcher
    function initialize() {
        setupEventListeners();
        loadSavedTheme();
    }
    
    // Initialize on DOMContentLoaded or immediately if DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize);
    } else {
        initialize();
    }
})();
