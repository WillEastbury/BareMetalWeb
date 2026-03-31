#!/usr/bin/env node
/**
 * tools/download-assets.js
 *
 * Downloads and localises all external CSS / font / JS assets used by BareMetalWeb.
 * Run this tool to update the static assets committed to the repository.
 * The app serves these committed files directly — no CDN access is required at runtime.
 *
 * Outputs to:
 *   BareMetalWeb.Core/wwwroot/static/css/themes/base.min.css     – Bootstrap Icons (shared base)
 *   BareMetalWeb.Core/wwwroot/static/css/themes/{theme}.min.css  – Bootswatch theme (full Bootstrap CSS)
 *   BareMetalWeb.Core/wwwroot/static/fonts/                      – woff2 font files
 *   BareMetalWeb.Core/wwwroot/static/js/bootstrap.bundle.min.js  – Bootstrap JS
 *
 * base.min.css contains only Bootstrap Icons (@font-face + icon classes).
 * Each theme file is a complete Bootswatch-themed Bootstrap CSS bundle copied
 * from node_modules/bootswatch. The "default" theme uses plain Bootstrap CSS.
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

// ── Versions ────────────────────────────────────────────────────────────────

const BS_ICONS_VER     = '1.11.3';
const BOOTSTRAP_JS_VER = '5.3.3';

// ── Bootswatch themes to include ─────────────────────────────────────────────
//
// Each entry maps our theme name → Bootswatch dist folder name.
// "default" uses plain Bootstrap CSS from the bootstrap npm package.

const THEMES = [
    'default',      // plain Bootstrap
    'cerulean',     // blue sky tones
    'cosmo',        // modern clean
    'darkly',       // dark
    'flatly',       // flat design
    'journal',      // warm newsprint
    'lux',          // elegant
    'minty',        // fresh green
    'sandstone',    // warm earthy
    'slate',        // dark slate
];

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

    css = css.replace(/url\(\s*["']?\.\/fonts\/bootstrap-icons\.woff2[^"')]*["']?\s*\)/gi,
        `url('${fontStaticRef}')`);
    css = css.replace(/url\(\s*["']?fonts\/bootstrap-icons\.woff2[^"')]*["']?\s*\)/gi,
        `url('${fontStaticRef}')`);

    if (!fs.existsSync(fontDest)) {
        console.log(`  Downloading bootstrap-icons.woff2...`);
        const fontData = await fetch(fontUrl, true);
        fs.writeFileSync(fontDest, fontData);
    } else {
        console.log(`  bootstrap-icons.woff2 already exists`);
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

// ── Bootswatch theme copy ─────────────────────────────────────────────────────

function copyBootswatchThemes() {
    const nodeModules = path.join(REPO_ROOT, 'node_modules');
    const bootswatchDist = path.join(nodeModules, 'bootswatch', 'dist');
    const bootstrapCss = path.join(nodeModules, 'bootstrap', 'dist', 'css', 'bootstrap.min.css');

    console.log('\nCopying Bootswatch theme files...');
    for (const theme of THEMES) {
        const destFile = path.join(THEMES_DIR, `${theme}.min.css`);
        let srcFile;
        if (theme === 'default') {
            srcFile = bootstrapCss;
        } else {
            srcFile = path.join(bootswatchDist, theme, 'bootstrap.min.css');
        }

        if (!fs.existsSync(srcFile)) {
            console.error(`  ERROR: source not found: ${srcFile}`);
            console.error(`  Run 'npm install' first to install bootswatch and bootstrap.`);
            process.exit(1);
        }

        fs.copyFileSync(srcFile, destFile);
        const sizeKb = (fs.statSync(destFile).size / 1024).toFixed(1);
        console.log(`  ${theme}.min.css (${sizeKb} KB)`);
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
    console.log('=== BareMetalWeb asset downloader ===\n');

    // 1. Bootstrap JS
    await downloadBootstrapJs();

    // 2. Base bundle: Bootstrap Icons only → base.min.css
    const baseDest = path.join(THEMES_DIR, 'base.min.css');
    const iconsCss = await downloadBootstrapIcons();
    const baseBundle = `/* bootstrap-icons@${BS_ICONS_VER} */\n${iconsCss}`;
    fs.writeFileSync(baseDest, baseBundle, 'utf8');
    const baseSizeKb = (fs.statSync(baseDest).size / 1024).toFixed(1);
    console.log(`  Saved base bundle (icons only): ${path.relative(REPO_ROOT, baseDest)} (${baseSizeKb} KB)`);

    // 3. Bootswatch themes (each is a complete Bootstrap CSS with theme applied)
    copyBootswatchThemes();

    // 4. Clean up old BMW CSS-variable theme files that are no longer used
    const oldThemes = ['light', 'dark', 'colourful', 'muted', 'highviz',
        'ocean', 'forest', 'sunset', 'midnight', 'rose'];
    for (const old of oldThemes) {
        if (THEMES.includes(old)) continue;
        const oldFile = path.join(THEMES_DIR, `${old}.min.css`);
        if (fs.existsSync(oldFile)) {
            fs.unlinkSync(oldFile);
            console.log(`  Removed old theme: ${old}.min.css`);
        }
    }

    console.log('\n=== Done ===');
}

main().catch(err => {
    console.error('Fatal error:', err);
    process.exit(1);
});
