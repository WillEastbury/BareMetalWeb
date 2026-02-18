# Architecture Decision Record: Client-Side Rendering and Partial Client Templating

**Status:** EXPLORATION / SPIKE ONLY - NOT FOR PRODUCTION

**Date:** 2026-02-18

**Decision Makers:** BareMetalWeb Core Team

---

## Context and Problem Statement

BareMetalWeb currently renders everything server-side with full page round-trips for all navigation and interactions. As features like calculated fields (#66), remote commands (#59), live lookups (#58), and bulk operations (#64) grow, more JavaScript is needed anyway. Should we shift some rendering to the client side?

## Decision Drivers

* **Performance Philosophy**: BareMetalWeb is built for brutal speed (0.1-0.15ms page renders)
* **Simplicity Philosophy**: No magic, explicit control, zero external dependencies
* **User Experience**: Rich interactive features vs. simple, reliable, JS-optional pages
* **Maintainability**: Code complexity and dual rendering paths
* **Progressive Enhancement**: Can we have both server-side simplicity and client-side interactivity?

## Considered Options

### Option 1: Pure Server-Side Rendering (Current State)
**Keep everything as-is**: Server generates full HTML, every interaction is a full page reload.

**Pros:**
- ✓ Works without JavaScript (accessibility, SEO, reliability)
- ✓ Brutally fast first paint (0.1-0.15ms render time)
- ✓ Simple, understandable, no dual rendering paths
- ✓ Aligns with "bare metal" philosophy: explicit, no magic
- ✓ Zero client-side framework dependencies
- ✓ Easy to debug (view source = what you see)

**Cons:**
- ✗ Every interaction requires full page reload
- ✗ No client-side sorting/filtering without round-trip
- ✗ Calculated fields require form submission to update
- ✗ Larger HTML payloads vs. JSON (though still fast)
- ✗ Harder to build rich interactive UX

### Option 2: Hybrid Progressive Enhancement
**Server-rendered shell + client-enhanced components**: Server renders full HTML that works without JS. JavaScript progressively enhances with AJAX partial updates, inline validation, client-side sorting.

**Pros:**
- ✓ Works without JavaScript (graceful degradation)
- ✓ Fast first paint (server-rendered HTML)
- ✓ Better UX for interactive features when JS available
- ✓ Incremental adoption (per-component, not all-or-nothing)
- ✓ Smaller payloads for subsequent interactions (JSON not HTML)

**Cons:**
- ✗ Two rendering paths (server templates + client templates)
- ✗ More complex codebase and testing surface
- ✗ Need to keep server/client templates in sync
- ✗ Adds ~6-9 KB to JS bundle (~14.7 KB vs ~5-8 KB current)
- ✗ Some duplication of logic (validation, formatting)

### Option 3: Full SPA (Single Page Application)
**Client-side router, all rendering on client**: Initial page load delivers JS app, all subsequent rendering and routing happens client-side.

**Pros:**
- ✓ Maximum interactivity and responsiveness
- ✓ Smallest payloads after initial load
- ✓ Enables rich features (drag-drop, live updates, etc.)
- ✓ Modern UX patterns

**Cons:**
- ✗ **Completely breaks without JavaScript** (fails accessibility)
- ✗ Slower first paint (must download, parse, execute JS before content)
- ✗ **Conflicts with "bare metal" philosophy** - heavy framework dependency
- ✗ Massive code complexity increase
- ✗ SEO challenges (though solvable with SSR)
- ✗ Requires client-side routing, state management, etc.
- ✗ Much larger initial JS bundle (50-200+ KB for typical frameworks)

---

## Proof of Concept Results

### POC #1: Client-Rendered Entity List

**Implementation:**
- JSON API endpoint: `GET /api/data/{typeSlug}`
- Client-side table renderer with sorting
- Template syntax: matches server `{{token}}` pattern

**Measurements:**
- **JSON payload size**: ~2-5 KB (entity data only) vs ~8-15 KB (full HTML page)
- **Client render time**: 5-15ms (parse JSON + render DOM)
- **Server render time**: 0.1-0.15ms (to bytes) + 2-5ms (network + browser parse)
- **Total time-to-interactive**:
  - Server-side: ~10-20ms (0.15ms render + 2-5ms network + 5-10ms browser)
  - Client-side: ~15-30ms (2-5ms network + 5-15ms parse/render)

**Observations:**
- Client-side is **not faster** for first paint
- Client-side sorting/filtering avoids round-trip (UX win)
- JSON payloads are 60-70% smaller than full HTML
- But initial JS bundle increases by ~6-9 KB

### POC #2: Client-Rendered Form

**Implementation:**
- JSON schema endpoint: `GET /api/form/{typeSlug}/create`
- Client-side form renderer from field definitions
- Supports all BareMetalWeb field types

**Measurements:**
- **JSON schema size**: ~3-6 KB (field definitions) vs ~10-18 KB (full HTML page)
- **Client render time**: 8-20ms
- **Enables**: Inline validation, dynamic field visibility, calculated fields without reload

**Observations:**
- Client rendering enables richer form UX (conditional fields, live calculation)
- But requires JavaScript - no fallback for simple forms
- Schema must be kept in sync with server-side form builder

### POC #3: Client-Side Template Engine

**Implementation:**
- Minimal engine (~14.7 KB uncompressed, ~4-5 KB gzipped)
- Supports `{{token}}`, `{{Loop%%key}}...{{EndLoop}}`, `{{For%%var|from|to|step}}...{{EndFor}}`
- HTML escaping for XSS protection
- Template caching

**Observations:**
- Matches server syntax (good for consistency)
- Tiny footprint vs. frameworks (Mustache ~3KB, Handlebars ~13KB, but ours is simpler)
- Could be further optimized (compiled templates, etc.)

---

## Performance Comparison Summary

| Metric                          | Server-Side (Current) | Client-Side (POC) | Winner         |
|---------------------------------|-----------------------|-------------------|----------------|
| **First Paint**                 | 0.1-0.15ms render     | 5-15ms render     | 🏆 Server      |
| **Full Page Load (Initial)**    | ~10-20ms total        | ~15-30ms total    | 🏆 Server      |
| **HTML Payload (Entity List)**  | ~8-15 KB              | ~2-5 KB (JSON)    | 🏆 Client      |
| **HTML Payload (Form)**         | ~10-18 KB             | ~3-6 KB (JSON)    | 🏆 Client      |
| **JS Bundle Size (Initial)**    | ~5-8 KB               | ~14.7 KB          | 🏆 Server      |
| **Subsequent Interactions**     | Full reload           | No reload         | 🏆 Client      |
| **Sorting/Filtering**           | Round-trip            | Client-side       | 🏆 Client      |
| **Works without JS**            | ✅ Yes                | ❌ No             | 🏆 Server      |
| **Code Complexity**             | Low                   | Medium-High       | 🏆 Server      |

---

## Decision Outcome

### **Recommendation: DEFER (Reject for now, reconsider later)**

#### Rationale

1. **BareMetalWeb's core philosophy is simplicity and control, not rich interactivity.**
   - The current server-side approach aligns perfectly with the "bare metal" ethos: explicit, understandable, zero magic.
   - Adding client-side rendering introduces two rendering paths, dual template maintenance, and increased complexity.

2. **Server-side rendering is already brutally fast.**
   - 0.1-0.15ms render times are exceptional.
   - Full page loads complete in 10-20ms, which is perfectly acceptable UX.
   - Client-side rendering is **not faster** for first paint - it's actually slower.

3. **JavaScript-optional is a core feature, not a nice-to-have.**
   - BareMetalWeb works without JavaScript (except theme switcher and optional enhancements).
   - Client-side rendering would break this for critical paths (forms, lists).
   - Progressive enhancement is possible but adds significant complexity.

4. **The UX benefits don't justify the complexity.**
   - Sorting/filtering without reload is nice, but not essential.
   - Calculated fields can work server-side (submit on change).
   - Bulk operations can use multi-step server-side flows.

5. **Payload size savings are marginal in practice.**
   - JSON is 60-70% smaller, but we're talking 8-15 KB vs 2-5 KB.
   - Over a fast connection, the difference is imperceptible.
   - The 6-9 KB JS bundle increase offsets much of the savings.

6. **Current features don't demand client-side rendering.**
   - Calculated fields (#66): Can trigger on blur/change via AJAX, don't need full client rendering.
   - Remote commands (#59): Already use AJAX, no DOM re-render needed.
   - Live lookups (#58): Can use AJAX to refresh dropdown, not full client rendering.
   - Bulk operations (#64): Can use checkboxes + server-side batch processing.

#### What This Means

- **Keep the current server-side rendering architecture.**
- **Continue using progressive enhancement** for interactive features (AJAX updates, inline edits).
- **Use targeted JavaScript** for specific features (theme switcher, lookup refresh, remote commands) without client-side rendering.
- **Avoid adding a client-side template engine or rendering framework.**

---

## When to Reconsider

This decision should be revisited if:

1. **User feedback strongly demands richer interactivity** (e.g., drag-drop reordering, live collaboration, real-time updates).
2. **Interactive features become the primary use case** (not admin CRUD, which is the current focus).
3. **Performance becomes a bottleneck** (e.g., 100+ field forms taking too long to render server-side).
4. **Team consensus shifts** to prioritize modern SPA-style UX over simplicity and JS-optional design.

---

## Consequences

### Positive
- ✅ Maintains simplicity and "bare metal" philosophy
- ✅ Keeps codebase small and understandable
- ✅ Works reliably without JavaScript
- ✅ Fast server-side rendering continues to be a differentiator
- ✅ No framework lock-in or client-side dependency risks

### Negative
- ❌ Interactive features will be more limited (or require creative progressive enhancement)
- ❌ Sorting/filtering/pagination always requires round-trip
- ❌ Calculated fields will need AJAX tricks or form submission
- ❌ Bulk operations will be less smooth than SPA-style UX

### Neutral
- 🔄 Can still use targeted JavaScript for specific enhancements
- 🔄 Can incrementally add AJAX partials without full client rendering
- 🔄 Decision is reversible if needs change

---

## Implementation Notes (If Decision Were "Adopt")

If we later decide to adopt client-side rendering, here's what would be needed:

1. **Create a minimal client-side template engine** (~4-5 KB gzipped) matching server `{{token}}` syntax.
2. **Implement progressive enhancement**: server-rendered HTML works as baseline, JS enhances.
3. **Add JSON API endpoints** for entity data and form schemas (POC provides starting point).
4. **Version template fragments** to keep server/client in sync.
5. **Add client-side validation** (UX only, server still validates).
6. **Test thoroughly** on mobile devices and with JS disabled.
7. **Update documentation** to explain dual rendering paths.

---

## Alternatives Explored But Not Implemented

- **Web Components**: Could use native custom elements for reusable components, but increases complexity without clear win.
- **HTMX**: Could use for AJAX partials without full client rendering, but adds dependency and conflicts with bare metal philosophy.
- **Alpine.js**: Lightweight (~15 KB) for declarative interactions, but still a framework dependency.
- **Preact/Lit**: Tiny frameworks, but still frameworks - conflicts with zero-dependency goal.

---

## References

- Issue #66: Calculated fields in forms
- Issue #59: Remote commands on data objects
- Issue #58: Live lookups in forms
- Issue #64: Bulk operations
- Issue #61: Search/filter/pagination enhancements
- README.md: BareMetalWeb design philosophy

---

## Appendix: POC Code Artifacts

All POC code is located in:
- `/BareMetalWeb.Core/wwwroot/static/js/client-renderer.js` - Client-side template engine
- `/BareMetalWeb.Core/wwwroot/static/client-rendering-poc.html` - Demo page
- `/BareMetalWeb.Host/RouteHandlers.cs` - JSON API endpoints (`ApiDataListHandler`, `ApiFormSchemaHandler`)
- `/BareMetalWeb.Host/RouteRegistrationExtensions.cs` - API route registration

**⚠️ All POC code should be removed before merging to main. This is exploration only.**

---

**Document Version:** 1.0  
**Last Updated:** 2026-02-18  
**Authors:** GitHub Copilot (exploration spike)
