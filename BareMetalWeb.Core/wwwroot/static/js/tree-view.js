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
                
                // Toggle visibility
                const isCurrentlyExpanded = childList.style.display !== 'none';
                
                if (isCurrentlyExpanded) {
                    // Collapse
                    childList.style.display = 'none';
                    this.textContent = '+';
                    this.classList.remove('bm-tree-expanded');
                    this.classList.add('bm-tree-collapsed');
                } else {
                    // Expand
                    childList.style.display = '';
                    this.textContent = '−';
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
