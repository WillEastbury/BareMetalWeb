# Issue Categorization and Labeling Summary

## What Was Done

I have analyzed all 26 open issues in the BareMetalWeb repository and categorized them according to the three requested dimensions:

### Categorization Scheme

1. **Priority**: Critical (3) | Important (9) | Nice to Have (12) | Superfluous (2)
2. **Type**: Security (2) | Bug (7) | New Feature Request (15) | Enrichment (2)
3. **Component**: Host (5) | HTML (8) | Scaffolder (7) | Storage (2) | Query (3) | Indexing (1) | API Extension (1) | Renderer (1) | Other (1)

### Deliverables Created

1. **`ISSUE_CATEGORIZATION.md`** - Comprehensive analysis document with:
   - Detailed categorization of all 26 issues
   - Rationale for each categorization decision
   - Summary statistics
   - Recommended action plan prioritized by urgency

2. **`.github/workflows/apply-issue-labels.yml`** - GitHub Actions workflow that can be manually triggered to apply all labels to issues

3. **`tools/apply-issue-labels.sh`** - Standalone shell script for manual label application using GitHub CLI

4. **`tools/README.md`** - Documentation for the labeling tools

## How to Apply the Labels

### Option 1: GitHub Actions (Recommended)

1. Go to the repository's Actions tab on GitHub
2. Select the "Apply Issue Labels" workflow from the left sidebar
3. Click the "Run workflow" dropdown button
4. Click the green "Run workflow" button to execute
5. The workflow will automatically apply all labels using the repository's `GITHUB_TOKEN`

### Option 2: Manual Script Execution

If you prefer to run the script locally:

```bash
# Ensure GitHub CLI is installed and authenticated
gh auth status

# Run the script
./tools/apply-issue-labels.sh
```

**Prerequisites:**
- GitHub CLI (`gh`) installed: https://cli.github.com/
- Authenticated with write permissions to the repository

## Key Findings

### Critical Issues Requiring Immediate Attention

1. **#75 - bug in MFA Tests** (Security)
   - MFA validation test always passes (`Assert.True(result || !result)`)
   - Zero actual coverage for security-critical authentication code

2. **#76 - bUG IN mALFORMED COOKIE TEST** (Security)
   - Cookie protection test accepts malformed tokens
   - Security boundary vulnerability could go undetected

3. **#77 - BUG IN AUTO-ID GEN FOUND BY CODEX** (Bug)
   - Auto-ID generation broken in API/CSV flows
   - Data integrity issue - entities get wrong ID types

### Important Issues (Next Priority)

- **#78, #86**: Failing unit tests need fixes
- **#60**: Field validation framework (security/data integrity)
- **#61**: Search/filtering/pagination (usability blocker)
- **#71**: Activate secondary indexes (performance)
- **#73, #74**: Address code review findings

### Nice to Have Features

12 feature requests and enhancements that would improve the system but aren't critical for core operations. See `ISSUE_CATEGORIZATION.md` for details.

### Superfluous (Do Not Implement)

- **#67, #68**: Explicitly marked as exploration/research - keep for reference but do not merge

## Labels to Create in GitHub

Before running the label application, ensure these labels exist in the repository:

**Priority Labels:**
- `Critical`
- `Important`
- `Nice to Have`
- `Superfluous`

**Type Labels:**
- `Security`
- `Bug`
- `New Feature Request`
- `Enrichment`

**Component Labels:**
- `Host`
- `API Extension`
- `HTML`
- `Renderer`
- `Storage`
- `Serializer`
- `Indexing`
- `Query`
- `Scaffolder`
- `Other`

GitHub will auto-create labels as they're applied, but you may want to assign colors for better visualization.

## Next Steps

1. Review the categorization in `ISSUE_CATEGORIZATION.md`
2. Adjust any categorizations if needed by editing the workflow/script
3. Apply labels using one of the two methods above
4. Use the labels to prioritize work:
   - Start with Critical issues (security and data integrity)
   - Move to Important issues (bugs and essential features)
   - Plan Nice to Have features for future sprints
   - Keep Superfluous issues for research reference only

---

*Generated: 2026-02-18*
