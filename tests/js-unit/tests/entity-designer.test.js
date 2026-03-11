/**
 * @jest-environment jest-environment-jsdom
 */
'use strict';

const { TextEncoder, TextDecoder } = require('util');
global.TextEncoder = global.TextEncoder || TextEncoder;
global.TextDecoder = global.TextDecoder || TextDecoder;

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
    expect(document.getElementById('designer-root').textContent).toContain('Module Editor');

    global.crypto = originalCrypto;
  });

  test('exposes test hooks and parses binary module payload', () => {
    loadDesigner();
    const hooks = global.window.__entityDesignerTestHooks;

    expect(hooks).toBeDefined();
    const bytes = new TextEncoder().encode(JSON.stringify({
      name: 'Telemetry',
      slug: 'telemetry',
      fields: [{ name: 'Status', type: 'enum', values: ['Open', 'Closed'] }]
    }));
    const parsed = hooks.parseBinaryModule(bytes.buffer);
    const normalized = hooks.normalizeImportedModule(parsed);

    expect(normalized.name).toBe('Telemetry');
    expect(normalized.fields).toHaveLength(1);
    expect(normalized.fields[0].values).toEqual(['Open', 'Closed']);
  });

  test('builds a single object export with sub-record collections', () => {
    loadDesigner();
    const hooks = global.window.__entityDesignerTestHooks;
    hooks.setModule({
      name: 'Host Module',
      slug: 'host-module',
      fields: [{ name: 'HostName', type: 'string' }],
      reports: [{ name: 'ErrorsByType', type: 'summary', sourceField: 'ErrorType', aggregation: 'count' }],
      permissionRules: [{ principal: 'deploy-agent', level: 'write', constraint: 'OwnRecordOnly' }]
    });

    const exported = hooks.buildExportObject();
    expect(exported.name).toBe('Host Module');
    expect(exported.fields).toHaveLength(1);
    expect(exported.reports).toHaveLength(1);
    expect(exported.permissionRules).toHaveLength(1);
    expect(exported.permissions).toContain('deploy-agent');
  });
});
