#!/usr/bin/env node
/**
 * tools/download-assets.js
 *
 * Downloads and localises all external CSS / font / JS assets used by BareMetalWeb.
 * Run this tool to update the static assets committed to the repository.
 * The app serves these committed files directly — no CDN access is required at runtime.
 *
 * Outputs to:
 *   BareMetalWeb.Core/wwwroot/static/css/themes/base.min.css     – Bootstrap + Bootstrap Icons (shared base)
 *   BareMetalWeb.Core/wwwroot/static/css/themes/{theme}.min.css  – BMW minimal CSS-variable theme overrides
 *   BareMetalWeb.Core/wwwroot/static/fonts/                      – woff2 font files
 *   BareMetalWeb.Core/wwwroot/static/js/bootstrap.bundle.min.js  – Bootstrap JS
 *
 * base.min.css structure:
 *   1. Bootstrap Icons @font-face block (font paths rewritten to /static/fonts/)
 *   2. Bootstrap CSS base (no Bootswatch colour overrides)
 *
 * Per-theme CSS bundles contain only BMW CSS custom-property overrides:
 *   :root { --bmw-bg: ...; --bmw-fg: ...; --bmw-p: ...; --bmw-b: ...; --bmw-a: ...; --bmw-g: 12px }
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

// ── Versions ────────────────────────────────────────────────────────────────

const BS_ICONS_VER      = '1.11.3';
const BOOTSTRAP_CSS_VER = '5.3.3';
const BOOTSTRAP_JS_VER  = '5.3.3';

// ── BMW theme definitions ────────────────────────────────────────────────────
//
// Five minimal CSS-variable-only theme files.
// The base.min.css provides Bootstrap structure; these files override the palette.

const BMW_THEMES = {
    light: `/* BMW Light theme */\n:root{--bmw-bg:#f7f7f9;--bmw-fg:#222;--bmw-p:#fff;--bmw-b:#e3e3e3;--bmw-a:#2a6df4;--bmw-g:12px}\n`,
    dark:  `/* BMW Dark theme */\n:root{--bmw-bg:#1a1a1a;--bmw-fg:#e8e8e8;--bmw-p:#242424;--bmw-b:#3a3a3a;--bmw-a:#4d9fff;--bmw-g:12px;--bs-body-color:#e8e8e8;--bs-body-bg:#1a1a1a;--bs-border-color:#3a3a3a;--bs-secondary-bg:#2a2a2a;--bs-emphasis-color:#fff;--bs-secondary-color:rgba(232,232,232,.75)}body{color-scheme:dark}\n`,
    colourful: `/* BMW Colourful theme */\n:root{--bmw-bg:#f0f4ff;--bmw-fg:#1a1a2e;--bmw-p:#fff;--bmw-b:#b8c8f8;--bmw-a:#7c3aed;--bmw-g:12px}\n`,
    muted: `/* BMW Muted theme */\n:root{--bmw-bg:#f5f4f2;--bmw-fg:#4a4a4a;--bmw-p:#fafaf8;--bmw-b:#d8d6d0;--bmw-a:#6b7a8d;--bmw-g:12px}\n`,
    highviz: `/* BMW HighViz theme — high contrast accessibility */\n:root{--bmw-bg:#fff;--bmw-fg:#000;--bmw-p:#fff;--bmw-b:#000;--bmw-a:#cc0000;--bmw-g:12px;--bs-body-color:#000;--bs-body-bg:#fff;--bs-border-color:#000}\n`,
    ocean: `/* BMW Ocean theme */\n:root{--bmw-bg:#eef6fb;--bmw-fg:#1a3a4a;--bmw-p:#ffffff;--bmw-b:#9dc8e0;--bmw-a:#0077aa;--bmw-g:12px}\n`,
    forest: `/* BMW Forest theme */\n:root{--bmw-bg:#f0f5ee;--bmw-fg:#1e3a1e;--bmw-p:#ffffff;--bmw-b:#a8c9a8;--bmw-a:#2e7d32;--bmw-g:12px}\n`,
    sunset: `/* BMW Sunset theme */\n:root{--bmw-bg:#fff8f2;--bmw-fg:#3a1a00;--bmw-p:#ffffff;--bmw-b:#f5c4a0;--bmw-a:#d4500a;--bmw-g:12px}\n`,
    midnight: `/* BMW Midnight theme */\n:root{--bmw-bg:#0d1117;--bmw-fg:#e6edf3;--bmw-p:#161b22;--bmw-b:#30363d;--bmw-a:#58a6ff;--bmw-g:12px;--bs-body-color:#e6edf3;--bs-body-bg:#0d1117;--bs-border-color:#30363d;--bs-secondary-bg:#161b22;--bs-emphasis-color:#fff;--bs-secondary-color:rgba(230,237,243,.75)}body{color-scheme:dark}\n`,
    rose: `/* BMW Rose theme */\n:root{--bmw-bg:#fef5f8;--bmw-fg:#3a1a2a;--bmw-p:#ffffff;--bmw-b:#f0b8cf;--bmw-a:#c2185b;--bmw-g:12px}\n`,
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

    return css; // cleaned CSS ready to prepend to the base bundle
}

// ── Bootstrap base CSS ────────────────────────────────────────────────────────

/**
 * Download the pure Bootstrap CSS (without Bootswatch colour overrides).
 * This forms the structural foundation that all BMW themes build upon.
 */
async function downloadBootstrapCss() {
    const cssUrl = `https://cdn.jsdelivr.net/npm/bootstrap@${BOOTSTRAP_CSS_VER}/dist/css/bootstrap.min.css`;
    console.log(`Downloading bootstrap@${BOOTSTRAP_CSS_VER} CSS...`);
    return fetch(cssUrl);
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

    // 2. Shared base bundle: Bootstrap Icons + Bootstrap CSS → base.min.css
    const baseDest = path.join(THEMES_DIR, 'base.min.css');
    if (fs.existsSync(baseDest)) {
        console.log('base.min.css already exists, skipping download');
    } else {
        const iconsCss = await downloadBootstrapIcons();
        const bootstrapCss = await downloadBootstrapCss();

        const baseBundle = `/* bootstrap-icons@${BS_ICONS_VER} */\n${iconsCss}\n\n/* bootstrap@${BOOTSTRAP_CSS_VER} */\n${bootstrapCss}`;
        fs.writeFileSync(baseDest, baseBundle, 'utf8');
        console.log(`  Saved base bundle: ${path.relative(REPO_ROOT, baseDest)}`);
    }

    // 3. BMW theme files (minimal CSS-variable-only overrides)
    console.log('\nWriting BMW theme files...');
    for (const [themeName, css] of Object.entries(BMW_THEMES)) {
        const destFile = path.join(THEMES_DIR, `${themeName}.min.css`);
        if (fs.existsSync(destFile)) {
            console.log(`Theme ${themeName}.min.css already exists, skipping`);
            continue;
        }
        fs.writeFileSync(destFile, css, 'utf8');
        console.log(`  Saved theme: ${path.relative(REPO_ROOT, destFile)}`);
    }

    console.log('\n=== Done ===');
}

main().catch(err => {
    console.error('Fatal error:', err);
    process.exit(1);
});
