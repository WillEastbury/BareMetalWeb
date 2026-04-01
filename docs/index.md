# BareMetalWeb Documentation

Welcome to the BareMetalWeb documentation. This index is organized by audience and purpose.

---

## 🏗️ Architecture & Design

Conceptual documentation explaining how the system works.

- [System Overview](architecture/system-overview.md) — Component diagram, project dependencies, request lifecycle, and route divergence
- [HTTP Handler Reference](architecture/handlers.md) — Every HTTP route: path, handler method, auth requirement, and description
- [Domain Transition Kernel](architecture/domain-transition-kernel.md) — Runtime intent, mutation-first transaction model, and architectural guardrails
- [Data Layer & Storage](architecture/data-layer.md) — DataStore stack, entity registration, CRUD lifecycle, binary serializer, virtual entities
- [Indexing Pipeline](architecture/indexing.md) — SearchIndexManager (Inverted/BTree/Treap/Bloom/Graph/Spatial), index lifecycle, query acceleration
- [Vector Index](architecture/vector-index.md) — VectorIndexManager ANN engine, Vamana NSW graph, distance metrics, REST API
- [UI Rendering](architecture/rendering.md) — SSR template pipeline, VNext SPA path, form rendering, report rendering
- [Auth & Session](architecture/auth.md) — Login flow, session validation, permission model, CSRF lifecycle, API keys
- [Intelligence Engine](architecture/intelligence.md) — BitNet b1.58 ternary inference, semantic pruning, BMWM snapshots, SIMD dot product
- [Cluster State](architecture/cluster-state.md) — Distributed cluster state management and node coordination
- [Hosting](architecture/hosting.md) — Kestrel hosting configuration, startup lifecycle, and request pipeline
- [SIMD Optimizations](architecture/simd-optimizations.md) — Hardware-accelerated operations, Vector128/256, and performance patterns
- [System Invariants](architecture/system-invariants.md) — Architectural constraints, non-negotiable rules, and design invariants

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
- [Entity Designer](ENTITY_DESIGNER.md) — Visual tool for creating virtual entity definitions without writing code
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

- [CI/CD Pipeline](CI-CD-PIPELINE.md) — CI-only pipeline: unit tests, AOT builds, container images, and artifact publishing

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

## 🔧 Hardware / FPGA

- [iCE40 Minimum Engine](fpga/ice40-minimum-engine.md) — Design exploration: BareMetalWeb request pipeline on a Lattice iCE40UP5K FPGA with W5500, ATECC508A, AS6C6256, and QSPI flash
- [Pico + FPGA Accelerator](fpga/pico-fpga-accelerator.md) — Pico W/2W as CPU with iCE40UP5K as hardware rendering and indexing coprocessor over 16-bit PIO parallel bus

---

## 📋 Release Notes

- [V1.20260224.5](releases/V1.20260224.5-v1.20260224.222.md)
- [V1.20260224.4 – V1.3](releases/V1.20260224.4-V1.3.md)
- [V1.20260224.3 – V1.3](releases/V1.20260224.3-V1.3.md)
- [V1.20260219.2 – v1.172](releases/V1.20260219.2-v1.172.md)
- [V1.20260219.1 – Initial Release v1](releases/V1.20260219.1-initial%20release%20notes%20v1.md)
