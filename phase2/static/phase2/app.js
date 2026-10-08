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

// Phase 6 - real-time notifications for authorized journalists.
// The server only accepts the connection from a signed-in, AUTHORIZED
// journalist session and re-checks the account before every event.  Events
// carry a fixed message, a reference number and a status: never report
// content, tokens or evidence.  The client library is served from this origin.
(function () {
  "use strict";

  var body = document.body;
  if (!body || body.getAttribute("data-realtime") !== "on" || typeof window.io !== "function") return;

  var stack = document.querySelector("[data-toast-stack]");
  var statusEl = document.querySelector("[data-live-status]");
  var inboxUrl = body.getAttribute("data-inbox-url") || "/journalist/inbox";

  function setStatus(text, state) {
    if (!statusEl) return;
    statusEl.hidden = false;
    statusEl.textContent = text;
    statusEl.setAttribute("data-state", state);
  }

  function toast(text, linkText, href) {
    if (!stack) return;
    var item = document.createElement("div");
    item.className = "toast";
    item.setAttribute("role", "status");
    var p = document.createElement("p");
    p.textContent = text;
    item.appendChild(p);
    var actions = document.createElement("div");
    actions.className = "toast-actions";
    if (linkText && href) {
      var a = document.createElement("a");
      a.href = href;
      a.textContent = linkText;
      actions.appendChild(a);
    }
    var close = document.createElement("button");
    close.type = "button";
    close.className = "toast-close";
    close.textContent = "Dismiss";
    close.addEventListener("click", function () { item.remove(); });
    actions.appendChild(close);
    item.appendChild(actions);
    stack.appendChild(item);
    while (stack.children.length > 4) stack.removeChild(stack.firstChild);
  }

  var socket = window.io({ transports: ["websocket", "polling"] });

  socket.on("connect", function () { setStatus("Live updates on", "on"); });
  socket.on("disconnect", function (reason) {
    setStatus(reason === "io server disconnect" ? "Live updates stopped (sign in again)" : "Live updates reconnecting", "off");
  });
  socket.on("connect_error", function () { setStatus("Live updates unavailable", "off"); });

  socket.on("new_submission", function (data) {
    toast((data && data.message) || "A new anonymous submission has been received.", "Open inbox", inboxUrl);
  });

  socket.on("submission_status_changed", function (data) {
    if (!data || typeof data.id !== "number") return;
    toast(String(data.message || ("Submission #" + data.id + " was updated.")),
          "View #" + data.id, inboxUrl.replace(/\/inbox$/, "/submissions/" + data.id));
  });
})();
