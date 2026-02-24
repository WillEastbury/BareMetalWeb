# BareMetalWeb Documentation

Welcome to the BareMetalWeb documentation. This index covers all guides, references, and notes for users and developers.

---

## Getting Started

- [Background Usage & REST API](BackgroundUsage.md) — REST endpoints, authentication, query language, and CLI usage
- [Setup & Clear Data](SETUP_AND_CLEAR_DATA.md) — First-time setup wizard (OOBE), data-reset at startup, admin wipe, and sample-data generation
- [Testing Guide](TESTING.md) — Test infrastructure, how to run tests, and test project overview
- [Security Policy](../SECURITY.md) — Supported versions and how to report vulnerabilities
- [OWASP Security Notes](OWASP.md) — OWASP-aligned security considerations

---

## Feature Guides

- [Auto-ID Generation](AUTO_ID_GENERATION.md) — Automatic ID strategies (GUID, sequential) for data entities
- [Calculated Fields](CALCULATED_FIELDS_IMPLEMENTATION.md) — Client-side and server-side expression-based field calculations
- [Computed Fields](COMPUTED_FIELDS.md) — Server-side memoized snapshots and live lookups from related entities
- [Validation](VALIDATION.md) — Field validation framework and rules
- [Bulk Operations](BULK_OPERATIONS.md) — Bulk create, update, and delete on entity list views
- [Entity Field Definitions](ENTITY_FIELD_DEFINITIONS.md) — DataField attribute reference and field type catalog
- [Entity List Enhancements](ENTITY_LIST_ENHANCEMENTS.md) — Search, filtering, sorting, and pagination on list views
- [Export & Nested Components](EXPORT_NESTED_COMPONENTS.md) — Export support for embedded/nested entity components
- [Lookup API](LOOKUP_API.md) — Lookup field API reference
- [Lookup Field Buttons](LOOKUP_FIELD_BUTTONS.md) — Refresh and Add buttons on lookup fields
- [Lookup Field Buttons Visual](LOOKUP_FIELD_BUTTONS_VISUAL.md) — Visual examples for lookup field buttons
- [Search Index Types](SEARCH_INDEX_TYPES.md) — Search index types and configuration
- [Timeline View](TIMELINE_VIEW.md) — Timeline visualisation for date-based entities
- [Timetable View](TIMETABLE_VIEW.md) — Timetable/schedule view for entities
- [Tree View & Org Chart Guide](TREEVIEW_ORGCHART_GUIDE.md) — Explorer-style tree view and org chart rendering

---

## Deployment & Operations

- [CI Migration Deployment](CIMIGRATE_DEPLOYMENT.md) — Setup guide for the CI migration deployment workflow
- [CI Reset Deployment](CIRESET_DEPLOYMENT.md) — Setup guide for the CI reset deployment workflow

---

## Developer Notes

- [Implementation Summary](IMPLEMENTATION_SUMMARY.md) — Summary of recent implementation work
- [Test Coverage Summary](TEST_COVERAGE_SUMMARY.md) — Test coverage statistics and breakdown by component
- [Issue Categorization](ISSUE_CATEGORIZATION.md) — Categorization of open issues by priority, type, and component
- [Issue Labeling Summary](ISSUE_LABELING_SUMMARY.md) — Summary of issue labeling actions
- [Issue Quick Reference](ISSUE_QUICK_REFERENCE.md) — Quick reference table of all open issues
- [Known Footguns](footguns.md) — Gotchas and pitfalls to be aware of when working with the codebase
- [Bug Notes](bugs.md) — Informal bug tracking notes
- [Code Review Notes](review.md) — Code review findings and recommendations
- [Developer Instructions](instructions.md) — Internal developer setup and workflow instructions

---

## Release Notes

- [V1.20260224.4 – V1.3](releases/V1.20260224.4-V1.3.md)
- [V1.20260224.3 – V1.3](releases/V1.20260224.3-V1.3.md)
- [V1.20260219.2 – v1.172](releases/V1.20260219.2-v1.172.md)
- [V1.20260219.1 – Initial Release v1](releases/V1.20260219.1-initial%20release%20notes%20v1.md)
