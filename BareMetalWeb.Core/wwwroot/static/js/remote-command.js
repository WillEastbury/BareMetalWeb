// Remote command execution
(function() {
    'use strict';

    window.executeRemoteCommand = function(button) {
        var url = button.getAttribute('data-command-url');
        var confirmMsg = button.getAttribute('data-confirm');

        if (confirmMsg && !confirm(confirmMsg)) return;

        button.disabled = true;
        var originalHtml = button.innerHTML;
        button.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span> Running…';

        fetch(url, { method: 'POST', headers: { 'Accept': 'application/json' } })
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
    };

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
        toast.innerHTML = '<div class="d-flex"><div class="toast-body">' +
            message.replace(/</g, '&lt;') +
            '</div><button type="button" class="btn-close btn-close-white me-2 m-auto" onclick="this.closest(\'.toast\').remove()"></button></div>';
        container.appendChild(toast);
        setTimeout(function() { toast.remove(); }, 5000);
    }
})();
