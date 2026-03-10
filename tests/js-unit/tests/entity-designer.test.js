/**
 * @jest-environment jest-environment-jsdom
 */
'use strict';

const path = require('path');
const fs = require('fs');

const SRC = path.resolve(
  __dirname, '../../../BareMetalWeb.Core/wwwroot/static/js/entity-designer.js'
);

function loadDesigner() {
  const code = fs.readFileSync(SRC, 'utf8');
  const fn = new Function('document', 'window', code);
  fn(global.document, global.window);
}

describe('entity-designer', () => {
  beforeEach(() => {
    document.body.innerHTML = '<div id="designer-root"></div>';
  });

  test('loads when crypto.randomUUID is unavailable', () => {
    const originalCrypto = global.crypto;
    global.crypto = { getRandomValues: originalCrypto.getRandomValues.bind(originalCrypto) };

    expect(() => loadDesigner()).not.toThrow();
    expect(document.getElementById('designer-root').textContent).toContain('Entity Designer');

    global.crypto = originalCrypto;
  });
});
