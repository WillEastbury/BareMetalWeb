# Issue Categorization Quick Reference

| # | Title | Priority | Type | Component |
|---|-------|----------|------|-----------|
| 75 | bug in MFA Tests | **Critical** | Security | Host |
| 76 | bUG IN mALFORMED COOKIE TEST | **Critical** | Security | Host |
| 77 | BUG IN AUTO-ID GEN FOUND BY CODEX | **Critical** | Bug | Scaffolder |
| 60 | Field validation framework | Important | New Feature Request | Scaffolder |
| 61 | Search, filtering and pagination on entity list views | Important | New Feature Request | Query |
| 62 | Audit trail and change history for entities | Important | New Feature Request | Storage |
| 63 | File and image upload fields with storage integration | Important | New Feature Request | Storage |
| 71 | Wire up secondary indexes | Important | New Feature Request | Indexing |
| 73 | Address Codex Review Comment | Important | Bug | Host |
| 74 | Address Stylesheet bug from codex | Important | Bug | HTML |
| 78 | Fix Failing Unit Test on session expiration | Important | Bug | Host |
| 86 | Fix Failed Test | Important | Bug | Scaffolder |
| 57 | Virtual Objects: runtime-defined entity types | Nice to Have | New Feature Request | Scaffolder |
| 58 | Computed properties: memoized snapshots vs live lookups | Nice to Have | New Feature Request | Scaffolder |
| 59 | Remote Methods: server-side commands | Nice to Have | New Feature Request | API Extension |
| 64 | Bulk operations on entity list views | Nice to Have | New Feature Request | HTML |
| 65 | Export support for embedded/nested components | Nice to Have | New Feature Request | Scaffolder |
| 66 | Client-side calculated fields with expression engine | Nice to Have | New Feature Request | HTML |
| 69 | Reporting layer: cross-entity joins | Nice to Have | New Feature Request | Query |
| 70 | Reporting: LEFT, RIGHT, and FULL OUTER JOIN support | Nice to Have | New Feature Request | Query |
| 79 | test output is verbose and challenging to scan for errors | Nice to Have | Enrichment | Other |
| 80 | Lookup field UI cleanup (remove GUID display) | Nice to Have | Enrichment | HTML |
| 84 | UI Fluff (boolean display as checkboxes) | Nice to Have | Enrichment | HTML |
| 107 | New List features (filter/group/sort) | Nice to Have | New Feature Request | HTML |
| 67 | 🔬 Exploration: client-side rendering | Superfluous | New Feature Request | Renderer |
| 68 | 🔬 Exploration: JS lookup() function | Superfluous | New Feature Request | HTML |

## Priority Breakdown

- **Critical (3)**: Security issues and critical data integrity bugs
- **Important (9)**: Significant bugs and essential features
- **Nice to Have (12)**: Useful enhancements and features
- **Superfluous (2)**: Exploration/research only

## By Component

- **Host** (5): #73, #74, #75, #76, #78
- **HTML** (8): #64, #66, #68, #74, #80, #84, #107
- **Scaffolder** (7): #57, #58, #60, #65, #77, #86
- **Storage** (2): #62, #63
- **Query** (3): #61, #69, #70
- **Indexing** (1): #71
- **API Extension** (1): #59
- **Renderer** (1): #67
- **Other** (1): #79

---

See [ISSUE_CATEGORIZATION.md](ISSUE_CATEGORIZATION.md) for detailed analysis and rationale.
