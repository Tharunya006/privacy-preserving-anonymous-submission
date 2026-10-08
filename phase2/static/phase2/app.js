/* Phase 2 - small progressive enhancements only.
   Nothing here is a security control: every rule is enforced on the server. */
(function () {
  "use strict";

  // Confirmation prompt for destructive admin actions.
  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    var message = form.getAttribute("data-confirm");
    if (message && !window.confirm(message)) {
      event.preventDefault();
    }
  });

  // Client-side password hint. The authoritative check lives in
  // phase2/forms.py -> validate_password_strength.
  var newPassword = document.querySelector('input[name="new_password"], input[name="password"]');
  if (newPassword && newPassword.type === "password") {
    var meter = document.createElement("p");
    meter.className = "hint";
    meter.setAttribute("aria-live", "polite");
    newPassword.parentNode.appendChild(meter);

    newPassword.addEventListener("input", function () {
      var value = newPassword.value;
      var checks = [
        [value.length >= 10, "10+ characters"],
        [/[a-z]/.test(value), "lowercase"],
        [/[A-Z]/.test(value), "uppercase"],
        [/[0-9]/.test(value), "digit"],
        [/[^A-Za-z0-9]/.test(value), "special character"]
      ];
      var missing = checks.filter(function (c) { return !c[0]; })
                          .map(function (c) { return c[1]; });
      meter.textContent = value.length === 0
        ? ""
        : (missing.length === 0 ? "Password meets the policy." : "Still needed: " + missing.join(", "));
    });
  }
})();

// Phase 6 - real-time journalist notifications.
(function () {
  "use strict";

  if (typeof io === "undefined") return;

  var socket = io();

  socket.on("new_submission", function (data) {
    var message = document.createElement("div");
    message.className = "flash success";
    message.setAttribute("role", "status");
    message.textContent = data.message || "A new submission has been received.";

    var main = document.querySelector("main");
    if (main) {
      main.insertBefore(message, main.firstChild);
    }
  });
})();