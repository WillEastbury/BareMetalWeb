/**
 * Tree View Expand/Collapse Handler
 * Handles interactive expansion and collapse of tree nodes
 */
(function() {
    'use strict';

    function initTreeView() {
        // Find all toggle elements
        const toggles = document.querySelectorAll('.bm-tree-toggle:not(.bm-tree-spacer)');
        
        toggles.forEach(toggle => {
            toggle.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                
                const li = this.closest('.bm-tree-item');
                if (!li) return;
                
                const childList = li.querySelector(':scope > .bm-data-tree-list');
                if (!childList) return;
                
                const icon = this.querySelector('i');
                if (!icon) return;

                const isCurrentlyExpanded = !childList.classList.contains('d-none');
                
                if (isCurrentlyExpanded) {
                    childList.classList.add('d-none');
                    icon.className = 'bi bi-chevron-right';
                    this.classList.remove('bm-tree-expanded');
                    this.classList.add('bm-tree-collapsed');
                } else {
                    childList.classList.remove('d-none');
                    icon.className = 'bi bi-chevron-down';
                    this.classList.remove('bm-tree-collapsed');
                    this.classList.add('bm-tree-expanded');
                }
            });
        });
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initTreeView);
    } else {
        initTreeView();
    }
})();
