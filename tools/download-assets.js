#!/usr/bin/env node
/**
 * tools/download-assets.js
 *
 * Downloads and localises all external CSS / font / JS assets used by BareMetalWeb.
 * Run this tool to update the static assets committed to the repository.
 * The app serves these committed files directly — no CDN access is required at runtime.
 *
 * Outputs to:
 *   BareMetalWeb.Core/wwwroot/static/css/themes/{theme}.min.css  – per-theme bundle (25 Bootswatch + 4 custom)
 *   BareMetalWeb.Core/wwwroot/static/fonts/                      – woff2 font files
 *   BareMetalWeb.Core/wwwroot/static/js/bootstrap.bundle.min.js  – bootstrap JS
 *
 * Each per-theme CSS bundle contains:
 *   1. Bootstrap-icons @font-face block (font paths rewritten to /static/fonts/)
 *   2. The Bootswatch theme (Google Fonts @import replaced by inlined @font-face)
 *   3. (Custom themes only) CSS overrides appended on top of the base Bootswatch theme
 *
 * Usage:  node tools/download-assets.js
 *
 * To force re-download of all files (including already-existing ones), delete the
 * relevant files first or use the 'Download Static Assets' GitHub Actions workflow
 * with 'force_refresh' enabled.
 */

'use strict';

const https  = require('https');
const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const { URL } = require('url');

// ── Paths ────────────────────────────────────────────────────────────────────

const REPO_ROOT   = path.join(__dirname, '..');
const STATIC_ROOT = path.join(REPO_ROOT, 'BareMetalWeb.Core', 'wwwroot', 'static');
const CSS_DIR     = path.join(STATIC_ROOT, 'css');
const THEMES_DIR  = path.join(CSS_DIR, 'themes');
const FONTS_DIR   = path.join(STATIC_ROOT, 'fonts');
const JS_DIR      = path.join(STATIC_ROOT, 'js');

for (const d of [THEMES_DIR, FONTS_DIR]) {
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
}

// ── Versions / themes ────────────────────────────────────────────────────────

const BOOTSWATCH_VER    = '5.3.3';
const BS_ICONS_VER      = '1.11.3';
const BOOTSTRAP_JS_VER  = '5.3.3';

const THEMES = [
    'cerulean', 'cosmo',    'cyborg',   'darkly',  'flatly',
    'journal',  'litera',   'lumen',    'lux',     'materia',
    'minty',    'morph',    'pulse',    'quartz',  'sandstone',
    'simplex',  'sketchy',  'slate',    'solar',   'spacelab',
    'superhero','united',   'vapor',    'yeti',    'zephyr',
];

/**
 * Custom exclusive themes — each is built from a base Bootswatch theme
 * plus CSS overrides appended on top. Mirrors CssBundleService.CustomThemeDefinitions.
 */
const CUSTOM_THEMES = {
    jigsaw: {
        base: 'lumen',
        css: `/* ── Jigsaw theme — muted, sensory-friendly ── */
body{background-color:#F6F5F1!important;color:#3D4A52!important;line-height:1.75!important}
a{color:#5C7A8E!important}a:hover{color:#3D5E70!important}
.navbar,.navbar-dark,.navbar-light{background-color:#3D4A52!important;border-bottom:1px solid #2E3840!important}
.navbar .navbar-brand,.navbar-dark .navbar-brand{color:#D8E4EA!important}
.navbar .nav-link,.navbar-dark .nav-link{color:rgba(216,228,234,.85)!important}
.btn-primary{background-color:#6B8D9E!important;border-color:#5A7A8A!important;color:#fff!important}
.btn-primary:hover,.btn-primary:focus{background-color:#5A7A8A!important;border-color:#4A6878!important}
.btn-secondary{background-color:#8B9BA8!important;border-color:#7A8A96!important;color:#fff!important}
.btn-success{background-color:#78976B!important;border-color:#6A8660!important;color:#fff!important}
.btn-danger{background-color:#9E6B6B!important;border-color:#8A5C5C!important;color:#fff!important}
.btn-warning{background-color:#A8985E!important;border-color:#907E50!important;color:#fff!important}
.btn-info{background-color:#6B9EA8!important;border-color:#5A8A93!important;color:#fff!important}
.card{border-color:#D8D5D0!important;box-shadow:none!important}
.card-header{background-color:#EDECE8!important;border-bottom-color:#D8D5D0!important}
.form-control:focus{border-color:#8AAAB8!important;box-shadow:0 0 0 .25rem rgba(107,141,158,.25)!important}
.badge.bg-primary{background-color:#6B8D9E!important}
.alert-primary{background-color:#E4ECF0!important;border-color:#B8CEDC!important;color:#2C4A58!important}
*,*::before,*::after{transition-duration:50ms!important;animation-duration:50ms!important}`,
    },
    rave: {
        base: 'cyborg',
        css: `/* ── Rave theme — neon 80s dance culture ── */
body{background-color:#06000E!important;color:#F0E8FF!important}
.navbar,.navbar-dark{background:linear-gradient(90deg,#1A0030,#001A30)!important;border-bottom:2px solid #FF00CC!important}
.navbar .navbar-brand,.navbar-dark .navbar-brand{color:#FF00CC!important;text-shadow:0 0 10px #FF00CC!important}
.navbar .nav-link,.navbar-dark .nav-link{color:#00FFFF!important}
.navbar .nav-link:hover,.navbar-dark .nav-link:hover{color:#FF00CC!important;text-shadow:0 0 8px #FF00CC!important}
.btn-primary{background-color:#FF00CC!important;border-color:#FF00CC!important;color:#000!important;box-shadow:0 0 12px #FF00CC,0 0 30px rgba(255,0,204,.35)!important}
.btn-primary:hover,.btn-primary:focus{background-color:#FF33DD!important;box-shadow:0 0 18px #FF00CC,0 0 45px rgba(255,0,204,.55)!important}
.btn-secondary{background-color:#00FFFF!important;border-color:#00FFFF!important;color:#000!important;box-shadow:0 0 10px #00FFFF!important}
.btn-success{background-color:#00FF66!important;border-color:#00FF66!important;color:#000!important;box-shadow:0 0 10px #00FF66!important}
.btn-warning{background-color:#FFFF00!important;border-color:#FFFF00!important;color:#000!important}
.btn-danger{background-color:#FF0040!important;border-color:#FF0040!important;color:#fff!important;box-shadow:0 0 12px #FF0040!important}
.card{background-color:#0D001A!important;border:1px solid #FF00CC!important;box-shadow:0 0 15px rgba(255,0,204,.2)!important}
.card-header{background-color:#1A0030!important;color:#FF00CC!important;border-bottom:1px solid #FF00CC!important}
h1,h2,h3{color:#FF00CC!important;text-shadow:0 0 8px rgba(255,0,204,.55)!important}
a{color:#00FFFF!important}a:hover{color:#FF00CC!important;text-shadow:0 0 8px #FF00CC!important}
.form-control{background-color:#0D001A!important;color:#F0E8FF!important;border-color:#FF00CC!important}
.form-control:focus{border-color:#00FFFF!important;box-shadow:0 0 0 .25rem rgba(0,255,255,.3)!important}
.table{color:#F0E8FF!important}
.table>:not(caption)>*>*{background-color:transparent!important;border-color:rgba(255,0,204,.3)!important}
.badge.bg-primary{background-color:#FF00CC!important;color:#000!important}`,
    },
    luminescent: {
        base: 'darkly',
        css: `/* ── Luminescent theme — glowing, illuminated ── */
body{background-color:#04060F!important;color:#B8F0FF!important}
.navbar,.navbar-dark{background-color:#070A18!important;border-bottom:1px solid #00F0FF!important;box-shadow:0 2px 20px rgba(0,240,255,.3)!important}
.navbar .navbar-brand,.navbar-dark .navbar-brand{color:#00F0FF!important;text-shadow:0 0 12px #00F0FF,0 0 25px rgba(0,240,255,.5)!important}
.navbar .nav-link,.navbar-dark .nav-link{color:#B8F0FF!important}
.navbar .nav-link:hover,.navbar-dark .nav-link:hover{color:#00F0FF!important;text-shadow:0 0 8px #00F0FF!important}
.btn-primary{background-color:#00C8E0!important;border-color:#00B0C8!important;color:#000!important;box-shadow:0 0 12px #00C8E0,0 0 30px rgba(0,200,224,.4)!important}
.btn-primary:hover,.btn-primary:focus{background-color:#00E8FF!important;box-shadow:0 0 20px #00E8FF,0 0 50px rgba(0,232,255,.5)!important}
.btn-secondary{background-color:#7B00FF!important;border-color:#6A00E0!important;color:#fff!important;box-shadow:0 0 10px #7B00FF,0 0 25px rgba(123,0,255,.4)!important}
.btn-success{background-color:#00FF88!important;border-color:#00E07A!important;color:#000!important;box-shadow:0 0 10px #00FF88!important}
.btn-danger{background-color:#FF3060!important;border-color:#E02050!important;color:#fff!important;box-shadow:0 0 10px #FF3060!important}
.btn-warning{background-color:#FFD700!important;border-color:#E8C000!important;color:#000!important;box-shadow:0 0 10px #FFD700!important}
.btn-info{background-color:#00F0FF!important;border-color:#00D0E0!important;color:#000!important;box-shadow:0 0 10px #00F0FF!important}
.card{background-color:#080B18!important;border:1px solid rgba(0,240,255,.35)!important;box-shadow:0 0 20px rgba(0,240,255,.15),inset 0 0 30px rgba(0,240,255,.05)!important}
.card-header{background-color:#0D1228!important;color:#00F0FF!important;border-bottom:1px solid rgba(0,240,255,.35)!important;text-shadow:0 0 8px rgba(0,240,255,.6)!important}
h1,h2,h3{color:#00F0FF!important;text-shadow:0 0 10px rgba(0,240,255,.6),0 0 25px rgba(0,240,255,.3)!important}
a{color:#00C8E0!important}a:hover{color:#00F0FF!important;text-shadow:0 0 8px #00F0FF!important}
.form-control{background-color:#080B18!important;color:#B8F0FF!important;border-color:rgba(0,240,255,.4)!important}
.form-control:focus{border-color:#00F0FF!important;box-shadow:0 0 0 .25rem rgba(0,240,255,.3),0 0 15px rgba(0,240,255,.2)!important}
.table{color:#B8F0FF!important}
.table>:not(caption)>*>*{background-color:transparent!important;border-color:rgba(0,240,255,.2)!important}
.badge.bg-primary{background-color:#00C8E0!important;color:#000!important}`,
    },
    geography: {
        base: 'sandstone',
        css: `/* ── Geography theme — beige, stone and cartographic greys ── */
body{background-color:#F2EDD8!important;color:#3A3328!important}
.navbar,.navbar-dark,.navbar-light{background-color:#5C5545!important;border-bottom:1px solid #3A3328!important}
.navbar .navbar-brand,.navbar-dark .navbar-brand{color:#F2EDD8!important}
.navbar .nav-link,.navbar-dark .nav-link{color:rgba(242,237,216,.85)!important}
.btn-primary{background-color:#6B7A5E!important;border-color:#5A6850!important;color:#fff!important}
.btn-primary:hover,.btn-primary:focus{background-color:#5A6850!important;border-color:#4A5842!important}
.btn-secondary{background-color:#8A7E6A!important;border-color:#7A6E5C!important;color:#fff!important}
.btn-success{background-color:#5E7A5A!important;border-color:#507050!important;color:#fff!important}
.btn-danger{background-color:#8A4A3A!important;border-color:#7A3A2C!important;color:#fff!important}
.btn-warning{background-color:#9A7A3A!important;border-color:#886A30!important;color:#fff!important}
.btn-info{background-color:#4A6A7A!important;border-color:#3C5C6A!important;color:#fff!important}
.card{background-color:#F8F4E8!important;border:1px solid #C8C0A8!important;box-shadow:1px 1px 4px rgba(58,51,40,.15)!important}
.card-header{background-color:#E8E0C8!important;border-bottom-color:#C8C0A8!important;color:#3A3328!important}
a{color:#4A6070!important}a:hover{color:#2E4050!important}
.form-control:focus{border-color:#8A9A7A!important;box-shadow:0 0 0 .25rem rgba(107,122,94,.25)!important}
.table{color:#3A3328!important}
.table>:not(caption)>*>*{border-color:#C8C0A8!important}
.table-striped>tbody>tr:nth-of-type(odd)>*{background-color:rgba(107,122,94,.07)!important}
.badge.bg-primary{background-color:#6B7A5E!important}
.alert-primary{background-color:#DDE5D8!important;border-color:#A8B8A0!important;color:#2A3824!important}`,
    },
};

// ── HTTP helpers ─────────────────────────────────────────────────────────────

function fetch(rawUrl, asBinary = false) {
    return new Promise((resolve, reject) => {
        const parsedUrl = new URL(rawUrl);
        const lib = parsedUrl.protocol === 'https:' ? https : http;
        const options = {
            hostname: parsedUrl.hostname,
            port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
            path: parsedUrl.pathname + parsedUrl.search,
            method: 'GET',
            headers: {
                'User-Agent': 'Mozilla/5.0 (compatible; BareMetalWeb-AssetDownloader/1.0)',
                'Accept': asBinary ? '*/*' : 'text/css,*/*;q=0.8',
            },
        };

        const req = lib.request(options, (res) => {
            // Follow up to 5 redirects
            if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                const nextUrl = new URL(res.headers.location, rawUrl).href;
                resolve(fetch(nextUrl, asBinary));
                return;
            }
            if (res.statusCode !== 200) {
                reject(new Error(`HTTP ${res.statusCode} for ${rawUrl}`));
                return;
            }

            const chunks = [];
            res.on('data', c => chunks.push(c));
            res.on('end', () => {
                const buf = Buffer.concat(chunks);
                resolve(asBinary ? buf : buf.toString('utf8'));
            });
        });

        req.on('error', reject);
        req.end();
    });
}

// ── Font handling ─────────────────────────────────────────────────────────────

/** Parse url(...) references out of a CSS string (handles quotes / no-quotes). */
function extractCssUrls(css) {
    const re = /url\(\s*["']?([^"')]+?)["']?\s*\)/gi;
    const out = [];
    let m;
    while ((m = re.exec(css)) !== null) {
        out.push(m[1]);
    }
    return out;
}

/**
 * Download a Google Fonts CSS stylesheet and convert all referenced .woff2
 * files into local copies stored in FONTS_DIR.
 *
 * Returns the full @font-face CSS block with rewritten src: url(...) paths
 * pointing to /static/fonts/<safe-name>.woff2.
 */
async function localiseGoogleFonts(googleFontsCssUrl) {
    console.log(`  Fetching Google Fonts CSS: ${googleFontsCssUrl}`);

    // Use a modern User-Agent so Google Fonts serves woff2
    const fontCss = await new Promise((resolve, reject) => {
        const parsedUrl = new URL(googleFontsCssUrl);
        const options = {
            hostname: parsedUrl.hostname,
            port: 443,
            path: parsedUrl.pathname + parsedUrl.search,
            method: 'GET',
            headers: {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
                'Accept': 'text/css,*/*;q=0.8',
            },
        };
        https.request(options, (res) => {
            if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                resolve(localiseGoogleFonts(new URL(res.headers.location, googleFontsCssUrl).href));
                return;
            }
            const chunks = [];
            res.on('data', c => chunks.push(c));
            res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        }).on('error', reject).end();
    });

    // Download each .woff2 referenced in the CSS
    // Only allow URLs from trusted Google Fonts hostnames to prevent SSRF via crafted CSS
    const TRUSTED_FONT_HOSTS = new Set(['fonts.gstatic.com', 'fonts.googleapis.com']);
    let localCss = fontCss;
    const woff2Urls = extractCssUrls(fontCss).filter(u => {
        try {
            const parsed = new URL(u, googleFontsCssUrl);
            return parsed.pathname.endsWith('.woff2') || TRUSTED_FONT_HOSTS.has(parsed.hostname);
        } catch {
            return false;
        }
    });

    for (const woff2Url of woff2Urls) {
        const absUrl = new URL(woff2Url, googleFontsCssUrl).href;
        // Create a safe local filename from the URL path
        const urlPath = new URL(absUrl).pathname;
        // Use last 2 path segments for uniqueness: e.g. lato/v25/abc123.woff2
        const segments = urlPath.split('/').filter(Boolean);
        const safeName = segments.slice(-3).join('-').replace(/[^a-zA-Z0-9.\-_]/g, '_');
        const localPath = path.join(FONTS_DIR, safeName);
        const staticRef  = `/static/fonts/${safeName}`;

        if (!fs.existsSync(localPath)) {
            console.log(`    Downloading font: ${absUrl}`);
            const fontData = await fetch(absUrl, true);
            fs.writeFileSync(localPath, fontData);
        } else {
            console.log(`    Font already exists: ${safeName}`);
        }

        // Replace all occurrences of this URL in the CSS (quoted and unquoted)
        localCss = localCss.split(woff2Url).join(staticRef);
        // Also replace the abs URL in case it appears differently
        localCss = localCss.split(absUrl).join(staticRef);
    }

    return localCss;
}

// ── Bootstrap-icons ───────────────────────────────────────────────────────────

async function downloadBootstrapIcons() {
    const cssUrl  = `https://cdn.jsdelivr.net/npm/bootstrap-icons@${BS_ICONS_VER}/font/bootstrap-icons.min.css`;
    const fontUrl = `https://cdn.jsdelivr.net/npm/bootstrap-icons@${BS_ICONS_VER}/font/fonts/bootstrap-icons.woff2`;
    const fontDest = path.join(FONTS_DIR, 'bootstrap-icons.woff2');
    const fontStaticRef = '/static/fonts/bootstrap-icons.woff2';

    console.log(`Downloading bootstrap-icons@${BS_ICONS_VER} CSS...`);
    let css = await fetch(cssUrl);

    // Rewrite the relative font paths inside the icons CSS to absolute /static/fonts/ paths
    css = css.replace(/url\(\s*["']?\.\/fonts\/bootstrap-icons\.woff2[^"')]*["']?\s*\)/gi,
        `url('${fontStaticRef}')`);
    // Also handle paths without leading ./
    css = css.replace(/url\(\s*["']?fonts\/bootstrap-icons\.woff2[^"')]*["']?\s*\)/gi,
        `url('${fontStaticRef}')`);

    if (!fs.existsSync(fontDest)) {
        console.log(`  Downloading bootstrap-icons.woff2...`);
        const fontData = await fetch(fontUrl, true);
        fs.writeFileSync(fontDest, fontData);
    } else {
        console.log(`  bootstrap-icons.woff2 already exists`);
    }

    return css; // cleaned CSS ready to prepend to each theme bundle
}

// ── Theme CSS ─────────────────────────────────────────────────────────────────

/**
 * Download and localise one Bootswatch theme.
 * Returns the CSS string with Google Fonts imports replaced by inline @font-face.
 */
async function downloadTheme(theme) {
    const cssUrl = `https://cdn.jsdelivr.net/npm/bootswatch@${BOOTSWATCH_VER}/dist/${theme}/bootstrap.min.css`;
    console.log(`Downloading theme: ${theme}`);
    let css = await fetch(cssUrl);

    // Extract all @import url("https://fonts.googleapis.com/...") lines
    const importRe = /@import\s+url\(\s*["']?(https:\/\/fonts\.googleapis\.com[^"')]+)["']?\s*\)\s*;?/gi;
    const imports = [];
    let m;
    while ((m = importRe.exec(css)) !== null) {
        imports.push({ full: m[0], url: m[1] });
    }

    // Download and inline each Google Fonts import
    for (const imp of imports) {
        const localFontCss = await localiseGoogleFonts(imp.url);
        css = css.replace(imp.full, localFontCss);
    }

    return css;
}

// ── Bootstrap JS ──────────────────────────────────────────────────────────────

async function downloadBootstrapJs() {
    const jsUrl  = `https://cdn.jsdelivr.net/npm/bootstrap@${BOOTSTRAP_JS_VER}/dist/js/bootstrap.bundle.min.js`;
    const jsDest = path.join(JS_DIR, 'bootstrap.bundle.min.js');

    if (fs.existsSync(jsDest)) {
        console.log('bootstrap.bundle.min.js already exists, skipping download');
        return;
    }

    console.log(`Downloading bootstrap@${BOOTSTRAP_JS_VER} bundle JS...`);
    const data = await fetch(jsUrl);
    fs.writeFileSync(jsDest, data, 'utf8');
    console.log(`  Saved to ${jsDest}`);
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
    console.log('=== BareMetalWeb asset downloader ===\n');

    // 1. Bootstrap JS
    await downloadBootstrapJs();

    // 2. Bootstrap-icons CSS (shared across all themes)
    const iconsCss = await downloadBootstrapIcons();

    // 3. Standard per-theme bundles (all 25 Bootswatch themes)
    for (const theme of THEMES) {
        const destFile = path.join(THEMES_DIR, `${theme}.min.css`);
        if (fs.existsSync(destFile)) {
            console.log(`Theme bundle ${theme}.min.css already exists, skipping`);
            continue;
        }

        const themeCss = await downloadTheme(theme);

        // Bundle = icons CSS + theme CSS
        const bundle = `/* bootstrap-icons@${BS_ICONS_VER} */\n${iconsCss}\n\n/* bootswatch@${BOOTSWATCH_VER} theme: ${theme} */\n${themeCss}`;
        fs.writeFileSync(destFile, bundle, 'utf8');
        console.log(`  Saved theme bundle: ${path.relative(REPO_ROOT, destFile)}`);
    }

    // 4. Custom exclusive themes (base Bootswatch theme + CSS overrides)
    console.log('\nBuilding custom themes...');
    for (const [themeName, def] of Object.entries(CUSTOM_THEMES)) {
        const destFile = path.join(THEMES_DIR, `${themeName}.min.css`);
        if (fs.existsSync(destFile)) {
            console.log(`Custom theme ${themeName}.min.css already exists, skipping`);
            continue;
        }

        console.log(`Building custom theme: ${themeName} (base: ${def.base})`);
        const baseThemeCss = await downloadTheme(def.base);

        const bundle = `/* bootstrap-icons@${BS_ICONS_VER} */\n${iconsCss}\n\n/* bootswatch@${BOOTSWATCH_VER} base theme: ${def.base} */\n${baseThemeCss}\n\n/* bmw custom theme: ${themeName} */\n${def.css}`;
        fs.writeFileSync(destFile, bundle, 'utf8');
        console.log(`  Saved custom theme bundle: ${path.relative(REPO_ROOT, destFile)}`);
    }

    console.log('\n=== Done ===');
}

main().catch(err => {
    console.error('Fatal error:', err);
    process.exit(1);
});
