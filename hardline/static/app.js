// Progressive enhancement only. The page works without this file:
// findings are <details>, the form is a plain POST, the filter simply is not there.
(function () {
  "use strict";

  // ── landing: line counter, drop zone ────────────────────────────────────
  var ta = document.getElementById("export");
  var count = document.getElementById("line-count");
  var drop = document.getElementById("drop");

  // Mirrors hardline/redact.py. Runs in the browser BEFORE upload, so secrets never leave this machine.
  var SECRET_KEYS = ["password", "secret", "private-key", "pre-shared-key", "wpa2-pre-shared-key",
    "wpa-pre-shared-key", "passphrase", "key", "psk", "community", "shared-secret", "radius-secret",
    "token", "api-key", "cloud-key", "user-pass", "wps-pin", "encryption-password", "auth-key",
    "master-key", "private-key-name"];
  var KV = new RegExp("\\b(" + SECRET_KEYS.join("|") + ")=(\"(?:[^\"\\\\]|\\\\.)*\"|\\S+)", "gi");
  var SSH = /(ssh-(?:rsa|ed25519|dss|ecdsa)[^\s"]*)\s+[A-Za-z0-9+\/=]{20,}/g;
  var B64 = /[A-Za-z0-9+\/]{40,}={0,2}/g;
  function redact(text) {
    var n = 0;
    text = text.replace(KV, function (m, k, v) { if (v !== "<redacted>") n++; return k + "=<redacted>"; });
    text = text.replace(SSH, function (m, k) { n++; return k + " <redacted>"; });
    text = text.replace(B64, function () { n++; return "<redacted>"; });
    // SNMP community strings are written as name=... ; mask them unless they are the defaults the rules look for.
    var inSnmp = false;
    text = text.split("\n").map(function (line) {
      var t = line.trim();
      if (t.charAt(0) === "/") { inSnmp = /^\/snmp community\b/.test(t); return line; }
      if (!inSnmp) return line;
      return line.replace(/\bname=("(?:[^"\\]|\\.)*"|\S+)/, function (m, v) {
        var bare = v.replace(/^"|"$/g, "").toLowerCase();
        if (bare === "public" || bare === "private" || v === "<redacted>") return m;
        n++; return "name=<redacted>";
      });
    }).join("\n");
    return { text: text, n: n };
  }

  if (ta) {
    var update = function () {
      var v = ta.value.trim();
      var n = v ? v.split("\n").length : 0;
      if (count) count.textContent = n ? n + " lines · ready" : "nothing pasted yet";
      if (drop) drop.classList.toggle("filled", n > 0);
    };
    ta.addEventListener("input", update);
    update();

    // Uploaded file -> textarea, so the redaction below always sees it.
    var fileInput = document.getElementById("file");
    if (fileInput) {
      fileInput.addEventListener("change", function () {
        var f = fileInput.files && fileInput.files[0];
        if (!f) return;
        var r = new FileReader();
        r.onload = function () { ta.value = String(r.result || ""); fileInput.value = ""; update(); };
        r.readAsText(f);
      });
    }

    var form = ta.form;
    var stripped = document.getElementById("client-redacted");
    if (form) {
      form.addEventListener("submit", function () {
        var res = redact(ta.value);
        ta.value = res.text;
        if (stripped) stripped.value = String(res.n);
        if (count) count.textContent = res.n ? res.n + " secret" + (res.n === 1 ? "" : "s") + " stripped in your browser" : "no secrets found · uploading";
      });
    }
    if (drop) {
      ["dragenter", "dragover"].forEach(function (ev) {
        drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.add("over"); });
      });
      ["dragleave", "drop"].forEach(function (ev) {
        drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.remove("over"); });
      });
      drop.addEventListener("drop", function (e) {
        var f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
        if (!f) return;
        var r = new FileReader();
        r.onload = function () { ta.value = String(r.result || ""); update(); };
        r.readAsText(f);
      });
    }
  }

  // ── report: severity filter, expand/collapse, copy ─────────────────────
  var findings = Array.prototype.slice.call(document.querySelectorAll(".finding"));
  if (!findings.length) return;

  var seg = document.querySelectorAll(".seg button[data-filter]");
  Array.prototype.forEach.call(seg, function (b) {
    b.addEventListener("click", function () {
      var f = b.getAttribute("data-filter");
      Array.prototype.forEach.call(seg, function (x) { x.setAttribute("aria-pressed", x === b ? "true" : "false"); });
      findings.forEach(function (d) { d.hidden = !(f === "all" || d.classList.contains(f)); });
    });
  });

  var toggleAll = document.getElementById("toggle-all");
  if (toggleAll) {
    toggleAll.addEventListener("click", function () {
      var visible = findings.filter(function (d) { return !d.hidden; });
      var allOpen = visible.length && visible.every(function (d) { return d.open; });
      visible.forEach(function (d) { d.open = !allOpen; });
      toggleAll.textContent = allOpen ? "Expand all" : "Collapse all";
    });
  }

  function flash(btn, label) {
    var old = btn.getAttribute("data-label") || btn.textContent;
    btn.setAttribute("data-label", old);
    btn.classList.add("done");
    btn.lastChild.nodeValue = " " + label;
    setTimeout(function () { btn.classList.remove("done"); btn.lastChild.nodeValue = " " + old.trim(); }, 1600);
  }
  function legacyCopy(text) {
    var t = document.createElement("textarea");
    t.value = text; t.setAttribute("readonly", ""); t.style.position = "fixed"; t.style.opacity = "0";
    document.body.appendChild(t); t.select();
    try { document.execCommand("copy"); } catch (e) {}
    document.body.removeChild(t);
  }
  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).catch(function () { legacyCopy(text); });
    }
    legacyCopy(text);
    return Promise.resolve();
  }

  Array.prototype.forEach.call(document.querySelectorAll("[data-copy]"), function (btn) {
    btn.addEventListener("click", function () {
      var pre = document.getElementById(btn.getAttribute("data-copy"));
      if (!pre) return;
      copyText(pre.textContent).then(function () { flash(btn, "Copied"); });
    });
  });

  var all = document.getElementById("copy-all");
  if (all) {
    all.addEventListener("click", function () {
      var script = findings.map(function (d) {
        var pre = d.querySelector("pre.fix");
        return "# " + d.getAttribute("data-id") + " " + d.getAttribute("data-title") + "\n" + (pre ? pre.textContent.trim() : "");
      }).join("\n\n");
      copyText(script).then(function () { flash(all, "Copied " + findings.length + " fixes"); });
    });
  }
})();
