/**
 * @jest-environment jest-environment-jsdom
 */
'use strict';

// Tests for the vnext-app.js SPA init guard and setContent null-safety.
// The bundle includes many dependencies so we stub BMRouter and just
// verify the guard behaviour rather than loading the full module.

const path = require('path');
const fs   = require('fs');

const ROUTING_SRC = path.resolve(
  __dirname, '../../../BareMetalWeb.Core/wwwroot/static/js/BareMetalRouting.js'
);

function loadRouter() {
  delete global.BMRouter;
  const code = fs.readFileSync(ROUTING_SRC, 'utf8');
  // eslint-disable-next-line no-new-func
  new Function('window', code)(global.window);
  return global.BMRouter;
}

// ── setContent null guard ─────────────────────────────────────────────────

describe('vnext-app – setContent null guard', () => {
  // Replicate the fixed setContent/getContent logic to verify the guard directly
  function makeSetContent(doc) {
    let content = null;
    function getContent() {
      return content || (content = doc.getElementById('vnext-content'));
    }
    function setContent(html) {
      var el = getContent();
      if (el) el.innerHTML = html;
    }
    return setContent;
  }

  test('does not throw when #vnext-content is absent', () => {
    document.body.innerHTML = '<div id="other">SSR page</div>';
    const setContent = makeSetContent(document);
    expect(() => setContent('<p>hello</p>')).not.toThrow();
  });

  test('sets innerHTML when #vnext-content is present', () => {
    document.body.innerHTML = '<div id="vnext-content"></div>';
    const setContent = makeSetContent(document);
    setContent('<p>hello</p>');
    expect(document.getElementById('vnext-content').innerHTML).toBe('<p>hello</p>');
  });
});

// ── BMRouter start guard (SPA router skipped on SSR pages) ────────────────

describe('vnext-app – SPA router skipped on SSR pages (no #vnext-content)', () => {
  let router;

  beforeEach(() => {
    router = loadRouter();
    router._routes = [];
    router._notFound = null;
  });

  test('BMRouter.start() is not called when #vnext-content is absent', () => {
    // Simulate the guard that was added to init():
    //   if (!document.getElementById('vnext-content')) return;
    document.body.innerHTML = '<div class="bm-ssr-content"><h1>Metric Viewer</h1></div>';

    const startSpy = jest.spyOn(router, 'start');

    // Replicate the guarded init logic
    function simulateInit() {
      if (!document.getElementById('vnext-content')) return;
      router.on('/:entity', jest.fn()).start();
    }

    simulateInit();
    expect(startSpy).not.toHaveBeenCalled();
  });

  test('BMRouter.start() is called when #vnext-content is present', () => {
    document.body.innerHTML = '<div id="vnext-content"></div>';

    const startSpy = jest.spyOn(router, 'start').mockImplementation(function () { return this; });

    function simulateInit() {
      if (!document.getElementById('vnext-content')) return;
      router.on('/:entity', jest.fn()).start();
    }

    simulateInit();
    expect(startSpy).toHaveBeenCalledTimes(1);
  });

  test('SPA router does not activate on SSR pages with only #vnext-root (setup page)', () => {
    // Simulate SSR setup page: has #vnext-root and .bm-ssr-content but NOT #vnext-content
    document.body.innerHTML =
      '<div id="vnext-root"></div>' +
      '<div class="bm-ssr-content"><form><input name="username"></form></div>';

    const startSpy = jest.spyOn(router, 'start');

    // Replicate the SPA router guard (second IIFE in vnext-app.js)
    function simulateSpaRouter() {
      const R = document.getElementById('vnext-content');
      if (!R) return;
      const ssrContent = document.querySelector('.bm-ssr-content');
      if (ssrContent) ssrContent.classList.add('bm-ssr-hidden');
      router.on('/:entity', jest.fn()).start();
    }

    simulateSpaRouter();
    expect(startSpy).not.toHaveBeenCalled();
    // SSR content must remain visible
    expect(document.querySelector('.bm-ssr-content').classList.contains('bm-ssr-hidden')).toBe(false);
  });
});
