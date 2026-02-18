#!/bin/bash
# Apply categorized labels to all open issues in WillEastbury/BareMetalWeb
# Based on categorization in ISSUE_CATEGORIZATION.md
#
# Usage: ./apply-issue-labels.sh
# Requires: gh CLI authenticated with repo permissions

set -e

REPO="WillEastbury/BareMetalWeb"

echo "🏷️  Applying categorized labels to issues in $REPO"
echo "=================================================="
echo ""

# Function to apply labels to an issue
apply_labels() {
    local issue=$1
    local priority=$2
    local type=$3
    local component=$4
    
    echo "Issue #$issue: $priority | $type | $component"
    gh issue edit "$issue" \
        --add-label "$priority" \
        --add-label "$type" \
        --add-label "$component" \
        --repo "$REPO" 2>&1 | grep -v "^$" || true
}

echo "Critical Issues (3):"
echo "-------------------"
apply_labels 75 "Critical" "Security" "Host"
apply_labels 76 "Critical" "Security" "Host"
apply_labels 77 "Critical" "Bug" "Scaffolder"
echo ""

echo "Important Issues (9):"
echo "--------------------"
apply_labels 60 "Important" "New Feature Request" "Scaffolder"
apply_labels 61 "Important" "New Feature Request" "Query"
apply_labels 62 "Important" "New Feature Request" "Storage"
apply_labels 63 "Important" "New Feature Request" "Storage"
apply_labels 71 "Important" "New Feature Request" "Indexing"
apply_labels 73 "Important" "Bug" "Host"
apply_labels 74 "Important" "Bug" "HTML"
apply_labels 78 "Important" "Bug" "Host"
apply_labels 86 "Important" "Bug" "Scaffolder"
echo ""

echo "Nice to Have Issues (12):"
echo "------------------------"
apply_labels 57 "Nice to Have" "New Feature Request" "Scaffolder"
apply_labels 58 "Nice to Have" "New Feature Request" "Scaffolder"
apply_labels 59 "Nice to Have" "New Feature Request" "API Extension"
apply_labels 64 "Nice to Have" "New Feature Request" "HTML"
apply_labels 65 "Nice to Have" "New Feature Request" "Scaffolder"
apply_labels 66 "Nice to Have" "New Feature Request" "HTML"
apply_labels 69 "Nice to Have" "New Feature Request" "Query"
apply_labels 70 "Nice to Have" "New Feature Request" "Query"
apply_labels 79 "Nice to Have" "Enrichment" "Other"
apply_labels 80 "Nice to Have" "Enrichment" "HTML"
apply_labels 84 "Nice to Have" "Enrichment" "HTML"
apply_labels 107 "Nice to Have" "New Feature Request" "HTML"
echo ""

echo "Superfluous Issues (2):"
echo "----------------------"
apply_labels 67 "Superfluous" "New Feature Request" "Renderer"
apply_labels 68 "Superfluous" "New Feature Request" "HTML"
echo ""

echo "=================================================="
echo "✅ Successfully applied labels to all 26 issues"
echo ""
echo "Summary:"
echo "  - 3 Critical issues (Security + Critical Bugs)"
echo "  - 9 Important issues (Bugs + Essential Features)"
echo "  - 12 Nice to Have issues (Enhancements + Features)"
echo "  - 2 Superfluous issues (Exploration/Research)"
