// Remote command execution
(function() {
    'use strict';

    function executeRemoteCommand(button) {
        var url = button.getAttribute('data-command-url');
        var confirmMsg = button.getAttribute('data-confirm');
        var csrfToken = button.getAttribute('data-csrf-token') || '';

        if (confirmMsg && !confirm(confirmMsg)) return;

        button.disabled = true;
        var originalHtml = button.innerHTML;
        button.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span> Running\u2026';

        fetch(url, { method: 'POST', headers: {
            'Accept': 'application/json',
            'X-Requested-With': 'BareMetalWeb',
            'X-CSRF-Token': csrfToken
        } })
            .then(function(response) { return response.json(); })
            .then(function(data) {
                button.disabled = false;
                button.innerHTML = originalHtml;
                showCommandToast(data.success, data.message);
                if (data.success && data.redirectUrl) {
                    window.location.href = data.redirectUrl;
                } else if (data.success) {
                    window.location.reload();
                }
            })
            .catch(function(err) {
                button.disabled = false;
                button.innerHTML = originalHtml;
                showCommandToast(false, 'Request failed: ' + err.message);
            });
    }

    function showCommandToast(success, message) {
        var container = document.getElementById('bm-toast-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'bm-toast-container';
            container.className = 'position-fixed top-0 end-0 p-3';
            container.style.zIndex = '1080';
            document.body.appendChild(container);
        }
        var cls = success ? 'bg-success' : 'bg-danger';
        var toast = document.createElement('div');
        toast.className = 'toast align-items-center text-white ' + cls + ' border-0 show';
        toast.setAttribute('role', 'alert');
        var body = document.createElement('div');
        body.className = 'd-flex';
        var text = document.createElement('div');
        text.className = 'toast-body';
        text.textContent = message;
        var closeBtn = document.createElement('button');
        closeBtn.type = 'button';
        closeBtn.className = 'btn-close btn-close-white me-2 m-auto';
        closeBtn.addEventListener('click', function() { toast.remove(); });
        body.appendChild(text);
        body.appendChild(closeBtn);
        toast.appendChild(body);
        container.appendChild(toast);
        setTimeout(function() { toast.remove(); }, 5000);
    }

    // Bind via event delegation
    document.addEventListener('click', function(e) {
        var cmdBtn = e.target.closest('[data-command-url]');
        if (cmdBtn) {
            executeRemoteCommand(cmdBtn);
        }
    });
})();
