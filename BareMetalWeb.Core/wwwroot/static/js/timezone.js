// Timezone detection and display
(function () {
    var el = document.getElementById("tz-info");
    if (!el) return;
    var tz = "";
    try {
        tz = Intl.DateTimeFormat().resolvedOptions().timeZone || "";
    } catch (e) {
        tz = "";
    }
    var offsetMinutes = -new Date().getTimezoneOffset();
    var sign = offsetMinutes >= 0 ? "+" : "-";
    var abs = Math.abs(offsetMinutes);
    var hh = String(Math.floor(abs / 60)).padStart(2, "0");
    var mm = String(abs % 60).padStart(2, "0");
    var offset = "UTC" + sign + hh + ":" + mm;
    var label = tz ? ("Local time: " + tz + " (" + offset + ")") : ("Local time: " + offset);
    el.textContent = label;
})();
