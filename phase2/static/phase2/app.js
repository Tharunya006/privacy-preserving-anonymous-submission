/* Small progressive enhancements only.
   Nothing here is a security control: every rule is enforced on the server,
   and every page works with JavaScript turned off. */
(function () {
  "use strict";

  // Confirmation prompt for destructive actions (forms with data-confirm).
  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    var message = form.getAttribute("data-confirm");
    if (message && !window.confirm(message)) {
      event.preventDefault();
    }
  });

  // Client-side password hint on "new password" fields only. The
  // authoritative check lives in phase2/forms.py -> password_policy_error.
  var newPassword = document.querySelector('input[type="password"][autocomplete="new-password"]');
  if (newPassword) {
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

  // "Copy token" button on the receipt page. Hidden until JavaScript is
  // available, so it never appears as a dead control.
  Array.prototype.forEach.call(document.querySelectorAll("[data-copy-target]"), function (button) {
    var target = document.getElementById(button.getAttribute("data-copy-target"));
    var feedback = document.getElementById(button.getAttribute("data-copy-feedback"));
    if (!target) return;
    button.hidden = false;

    function say(text) { if (feedback) feedback.textContent = text; }

    function selectTarget() {
      var range = document.createRange();
      range.selectNodeContents(target);
      var selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
    }

    button.addEventListener("click", function () {
      var text = target.textContent.trim();
      var done = function () {
        button.textContent = "Copied";
        say("Token copied to your clipboard. Store it somewhere private.");
        window.setTimeout(function () { button.textContent = "Copy token"; }, 2500);
      };
      var fallback = function () {
        selectTarget();
        var ok = false;
        try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
        if (ok) { done(); } else { say("The token is selected: press Ctrl+C or Cmd+C to copy it."); }
      };
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(done, fallback);
      } else {
        fallback();
      }
    });
  });

  // Evidence picker: show the chosen file's name and size, and warn early
  // about files the server will refuse anyway (type or size). The file never
  // leaves the browser until the form is submitted.
  Array.prototype.forEach.call(document.querySelectorAll('input[type="file"][data-status]'), function (input) {
    var status = document.getElementById(input.getAttribute("data-status"));
    var maxBytes = parseInt(input.getAttribute("data-max-bytes"), 10) || 0;
    var allowed = (input.getAttribute("accept") || "").toLowerCase().split(",")
      .map(function (s) { return s.trim(); }).filter(Boolean);
    if (!status) return;

    function size(bytes) {
      if (bytes >= 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + " MB";
      return Math.max(1, Math.round(bytes / 1024)) + " KB";
    }

    input.addEventListener("change", function () {
      status.classList.remove("is-error");
      var file = input.files && input.files[0];
      if (!file) { status.textContent = ""; return; }
      var dot = file.name.lastIndexOf(".");
      var ext = dot >= 0 ? file.name.slice(dot).toLowerCase() : "";
      if (allowed.length && allowed.indexOf(ext) === -1) {
        status.classList.add("is-error");
        status.textContent = "This file type is not accepted. Choose an image (JPEG, PNG, GIF, WebP) or a text / CSV file.";
      } else if (maxBytes && file.size > maxBytes) {
        status.classList.add("is-error");
        status.textContent = "This file is " + size(file.size) + ", which is over the " + size(maxBytes) + " limit.";
      } else {
        status.textContent = "Selected: " + file.name + " (" + size(file.size) + "). Hidden details will be removed when you submit.";
      }
    });
  });
})();
