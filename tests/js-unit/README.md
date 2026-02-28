# BareMetalWeb JS Unit Tests

Jest + jsdom unit tests for the client-side JavaScript mini libraries bundled with BareMetalWeb.

## Libraries Tested

| File | Tests |
|------|-------|
| `BareMetalRouting.js` | Route registration, pattern matching, URL-param extraction, query parsing, `navigate()` |
| `BareMetalRest.js` | `setRoot`/`getRoot`, CRUD entity methods, fetch error handling, CSRF header, FormData |
| `BareMetalBind.js` | `reactive()` Proxy state, `rv-text`, `rv-value`, `rv-if`, `rv-on-click`, `rv-on-submit` |
| `BareMetalTemplate.js` | `buildForm()` (all field types, layout, lookup), `buildTable()` (cells, callbacks, boolean badges) |
| `BareMetalRendering.js` | `createEntity()`, `listEntities()`, `renderUI()`, lookup hydration, `window.minibind` surface |
| `theme-switcher.js` | Cookie storage, `applyTheme()`, theme clamping, DOM state, select change listener |

## Setup

```bash
npm install
```

## Running Tests

```bash
# Run all tests
npm test

# Run with coverage
npm run test:coverage
```

## Design Notes

These tests run entirely in Node.js with a jsdom environment — no live server is required.
Each JS library is loaded via `new Function(...)` so that globals (`fetch`, `document`, etc.)
can be injected or mocked per test, keeping tests fast and hermetic.
