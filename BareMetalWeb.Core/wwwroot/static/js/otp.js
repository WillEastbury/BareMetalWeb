// OTP input validation
// This function sets up OTP validation for a form with the given action
function setupOtpValidation(formAction) {
    (function () {
        const f = document.querySelector('form[action="' + formAction + '"]');
        if (!f) return;
        const i = f.querySelector('input[name="code"]');
        const b = f.querySelector('button[type="submit"]');
        if (!i || !b) return;
        const u = () => {
            const v = (i.value || '').replace(/\s+/g, '');
            b.disabled = v.length !== 6;
        };
        i.addEventListener('input', u);
        u();
    })();
}
