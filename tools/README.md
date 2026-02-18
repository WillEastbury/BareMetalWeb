# BareMetalWeb Tools

This directory contains utility scripts for managing the BareMetalWeb repository.

## apply-issue-labels.sh

Applies categorized labels to all open GitHub issues based on the analysis in `ISSUE_CATEGORIZATION.md`.

### Prerequisites

- [GitHub CLI (`gh`)](https://cli.github.com/) installed and authenticated
- Write permissions to the repository issues

### Usage

```bash
./apply-issue-labels.sh
```

### Labels Applied

The script applies three labels to each issue:

1. **Priority**: `Critical`, `Important`, `Nice to Have`, or `Superfluous`
2. **Type**: `Security`, `Bug`, `New Feature Request`, or `Enrichment`
3. **Component**: `Host`, `API Extension`, `HTML`, `Renderer`, `Storage`, `Serializer`, `Indexing`, `Query`, `Scaffolder`, or `Other`

### Alternative: GitHub Actions Workflow

You can also trigger the label application via GitHub Actions:

1. Go to the repository's Actions tab
2. Select the "Apply Issue Labels" workflow
3. Click "Run workflow"

The workflow will apply all labels automatically using the repository's `GITHUB_TOKEN`.

### Categorization Details

See `ISSUE_CATEGORIZATION.md` in the repository root for:
- Detailed rationale for each issue's categorization
- Summary statistics
- Recommended action plan

---

*Note: These labels help prioritize work and organize issues by type and affected component.*
