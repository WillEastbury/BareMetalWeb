// Toast notification handler
document.addEventListener('DOMContentLoaded', function () {
    var el = document.getElementById('scaffold-toast');
    if (!el || !window.bootstrap) return;
    var toast = new bootstrap.Toast(el);
    toast.show();
    var url = new URL(window.location.href);
    if (url.searchParams.has('toast')) {
        url.searchParams.delete('toast');
    }
    if (url.searchParams.has('id')) {
        url.searchParams.delete('id');
    }
    if (url.searchParams.has('apikey')) {
        url.searchParams.delete('apikey');
    }
    window.history.replaceState({}, '', url.toString());
});
