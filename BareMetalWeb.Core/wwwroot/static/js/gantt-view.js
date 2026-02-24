/**
 * Gantt View - applies dynamic positioning styles from data attributes.
 * Elements use data-gantt-left, data-gantt-width and data-gantt-bg attributes
 * instead of inline style= attributes to comply with the Content Security Policy.
 */
(function () {
    'use strict';

    function applyGanttStyles() {
        var els = document.querySelectorAll('[data-gantt-left],[data-gantt-width],[data-gantt-bg]');
        for (var i = 0; i < els.length; i++) {
            var el = els[i];
            if (el.dataset.ganttLeft) el.style.left = el.dataset.ganttLeft;
            if (el.dataset.ganttWidth) el.style.width = el.dataset.ganttWidth;
            if (el.dataset.ganttBg) el.style.background = el.dataset.ganttBg;
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', applyGanttStyles);
    } else {
        applyGanttStyles();
    }
})();
