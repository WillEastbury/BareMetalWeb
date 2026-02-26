#!/usr/bin/env node
/**
 * tools/download-assets.js
 *
 * Downloads and localises all external CSS / font / JS assets used by BareMetalWeb.
 *
 * Outputs to:
 *   BareMetalWeb.Core/wwwroot/static/css/themes/{theme}.min.css  – per-theme bundle
 *   BareMetalWeb.Core/wwwroot/static/fonts/                      – woff2 font files
 *   BareMetalWeb.Core/wwwroot/static/js/bootstrap.bundle.min.js  – bootstrap JS
 *
 * Each per-theme CSS bundle contains:
 *   1. Bootstrap-icons @font-face block (font paths rewritten to /static/fonts/)
 *   2. The Bootswatch theme (Google Fonts @import replaced by inlined @font-face)
 *
 * Usage:  node tools/download-assets.js
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

const THEMES = ['vapor', 'darkly', 'cyborg', 'slate', 'superhero', 'flatly', 'lux'];

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
    let localCss = fontCss;
    const woff2Urls = extractCssUrls(fontCss).filter(u => u.includes('.woff2') || u.includes('gstatic.com'));

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

    // 3. Per-theme bundles
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

    console.log('\n=== Done ===');
}

main().catch(err => {
    console.error('Fatal error:', err);
    process.exit(1);
});
