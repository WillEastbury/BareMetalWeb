# BareMetalWeb Documentation

Welcome to the BareMetalWeb documentation. This index is organized by audience and purpose.

---

## 🏗️ Architecture & Design

Conceptual documentation explaining how the system works.

- [System Overview](architecture/system-overview.md) — Component diagram, project dependencies, request lifecycle, and route divergence
- [Data Layer & Storage](architecture/data-layer.md) — DataStore stack, entity registration, CRUD lifecycle, binary serializer, virtual entities
- [Indexing Pipeline](architecture/indexing.md) — SearchIndexManager, index creation/update/delete lifecycle, query acceleration
- [UI Rendering](architecture/rendering.md) — SSR template pipeline, VNext SPA path, form rendering, report rendering
- [Auth & Session](architecture/auth.md) — Login flow, session validation, permission model, CSRF lifecycle, API keys

---

## 🚀 Getting Started

How-to guides for setting up and running BareMetalWeb.

- [Setup & Clear Data](SETUP_AND_CLEAR_DATA.md) — First-time setup wizard (OOBE), data-reset at startup, admin wipe, and sample-data generation
- [Background Usage & REST API](BackgroundUsage.md) — REST endpoints, authentication, query language, and CLI usage
- [Testing Guide](TESTING.md) — Test infrastructure, how to run tests, and test project overview
- [Security Policy](../SECURITY.md) — Supported versions and how to report vulnerabilities
- [OWASP Security Notes](OWASP.md) — OWASP-aligned security considerations

---

## 📖 API & Field Reference

Reference documentation for APIs, field types, and configuration.

- [Entity Field Definitions](ENTITY_FIELD_DEFINITIONS.md) — DataField attribute reference and field type catalog
- [Lookup API](LOOKUP_API.md) — Lookup field API reference
- [Search Index Types](SEARCH_INDEX_TYPES.md) — Search index types and configuration
- [Validation](VALIDATION.md) — Field validation framework and rules
- [Auto-ID Generation](AUTO_ID_GENERATION.md) — Automatic ID strategies (GUID, sequential) for data entities

---

## ⚙️ Feature Guides

Detailed guides for specific features and view types.

- [Calculated Fields](CALCULATED_FIELDS_IMPLEMENTATION.md) — Client-side and server-side expression-based field calculations
- [Computed Fields](COMPUTED_FIELDS.md) — Server-side memoized snapshots and live lookups from related entities
- [Bulk Operations](BULK_OPERATIONS.md) — Bulk create, update, and delete on entity list views
- [Entity List Enhancements](ENTITY_LIST_ENHANCEMENTS.md) — Search, filtering, sorting, and pagination on list views
- [Export & Nested Components](EXPORT_NESTED_COMPONENTS.md) — Export support for embedded/nested entity components
- [Lookup Field Buttons](LOOKUP_FIELD_BUTTONS.md) — Refresh and Add buttons on lookup fields
- [Lookup Field Buttons Visual](LOOKUP_FIELD_BUTTONS_VISUAL.md) — Visual examples for lookup field buttons
- [Timeline View](TIMELINE_VIEW.md) — Timeline visualisation for date-based entities
- [Timetable View](TIMETABLE_VIEW.md) — Timetable/schedule view for entities
- [Tree View & Org Chart Guide](TREEVIEW_ORGCHART_GUIDE.md) — Explorer-style tree view and org chart rendering

---

## 🚢 Deployment & Operations

Guides for deploying and operating BareMetalWeb in production.

- [CI Migration Deployment](CIMIGRATE_DEPLOYMENT.md) — Setup guide for the CI migration deployment workflow
- [CI Reset Deployment](CIRESET_DEPLOYMENT.md) — Setup guide for the CI reset deployment workflow

---

## 🛠️ Developer Notes

Internal notes, reviews, and issue tracking for contributors.

- [Developer Instructions](instructions.md) — Internal developer setup and workflow instructions
- [Implementation Summary](IMPLEMENTATION_SUMMARY.md) — Summary of recent implementation work
- [Test Coverage Summary](TEST_COVERAGE_SUMMARY.md) — Test coverage statistics and breakdown by component
- [Known Footguns](footguns.md) — Gotchas and pitfalls to be aware of when working with the codebase
- [Code Review Notes](review.md) — Code review findings and recommendations
- [Bug Notes](bugs.md) — Informal bug tracking notes
- [Issue Categorization](ISSUE_CATEGORIZATION.md) — Categorization of open issues by priority, type, and component
- [Issue Labeling Summary](ISSUE_LABELING_SUMMARY.md) — Summary of issue labeling actions
- [Issue Quick Reference](ISSUE_QUICK_REFERENCE.md) — Quick reference table of all open issues

---

## 📋 Release Notes

- [V1.20260224.5](releases/V1.20260224.5-v1.20260224.222.md)
- [V1.20260224.4 – V1.3](releases/V1.20260224.4-V1.3.md)
- [V1.20260224.3 – V1.3](releases/V1.20260224.3-V1.3.md)
- [V1.20260219.2 – v1.172](releases/V1.20260219.2-v1.172.md)
- [V1.20260219.1 – Initial Release v1](releases/V1.20260219.1-initial%20release%20notes%20v1.md)
