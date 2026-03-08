// form-validation.js — Client-side field validation for BareMetalWeb
// Runs on input/change events, displays inline Bootstrap validation feedback.
(function () {
    'use strict';

    function initFormValidation() {
        // Use event delegation on document to avoid per-element listener accumulation
        document.addEventListener('input', function (e) {
            var input = e.target;
            if (input.matches('form input, form select, form textarea')) {
                validateField(input);
            }
        });
        document.addEventListener('change', function (e) {
            var input = e.target;
            if (input.matches('form input, form select, form textarea')) {
                validateField(input);
            }
        });
        document.addEventListener('submit', function (e) {
            var form = e.target;
            if (!form.matches('form')) return;
            var valid = true;
            var inputs = form.querySelectorAll('input, select, textarea');
            inputs.forEach(function (input) {
                if (!validateField(input)) valid = false;
            });
            if (!valid) {
                e.preventDefault();
                e.stopPropagation();
            }
            form.classList.add('was-validated');
        });
    }

    function validateField(input) {
        var isValid = true;
        var message = '';

        // Required
        if (input.hasAttribute('required') && !input.value.trim()) {
            isValid = false;
            message = (input.labels && input.labels[0] ? input.labels[0].textContent : input.name) + ' is required.';
        }

        // MinLength
        if (isValid && input.hasAttribute('minlength')) {
            var min = parseInt(input.getAttribute('minlength'), 10);
            if (input.value.length > 0 && input.value.length < min) {
                isValid = false;
                message = 'Must be at least ' + min + ' characters.';
            }
        }

        // MaxLength
        if (isValid && input.hasAttribute('maxlength')) {
            var max = parseInt(input.getAttribute('maxlength'), 10);
            if (input.value.length > max) {
                isValid = false;
                message = 'Must be at most ' + max + ' characters.';
            }
        }

        // Min (numeric)
        if (isValid && input.hasAttribute('min') && input.value) {
            var minVal = parseFloat(input.getAttribute('min'));
            if (parseFloat(input.value) < minVal) {
                isValid = false;
                message = 'Must be at least ' + minVal + '.';
            }
        }

        // Max (numeric)
        if (isValid && input.hasAttribute('max') && input.value) {
            var maxVal = parseFloat(input.getAttribute('max'));
            if (parseFloat(input.value) > maxVal) {
                isValid = false;
                message = 'Must be at most ' + maxVal + '.';
            }
        }

        // Pattern
        if (isValid && input.hasAttribute('pattern') && input.value) {
            var pattern = new RegExp('^' + input.getAttribute('pattern') + '$');
            if (!pattern.test(input.value)) {
                isValid = false;
                message = 'Does not match the required format.';
            }
        }

        // Update UI
        if (isValid) {
            input.classList.remove('is-invalid');
            var feedback = input.parentElement.querySelector('.invalid-feedback');
            if (feedback) feedback.textContent = '';
        } else {
            input.classList.add('is-invalid');
            var feedback = input.parentElement.querySelector('.invalid-feedback');
            if (feedback) {
                feedback.textContent = message;
            } else {
                var div = document.createElement('div');
                div.className = 'invalid-feedback';
                div.textContent = message;
                input.parentElement.appendChild(div);
            }
        }

        return isValid;
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initFormValidation);
    } else {
        initFormValidation();
    }
})();
