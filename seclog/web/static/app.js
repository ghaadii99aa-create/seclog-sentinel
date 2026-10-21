/* Progressive enhancement only: every page works without this script. */
(function () {
  "use strict";

  var MAX_BYTES = 5 * 1024 * 1024;

  function formatSize(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(1) + " MB";
  }

  var input = document.getElementById("logfile");
  var drop = document.querySelector(".drop");
  var hint = document.getElementById("drop-hint");
  var form = document.getElementById("upload-form");
  var button = document.getElementById("analyze-btn");

  if (input && drop && hint) {
    input.addEventListener("change", function () {
      var file = input.files && input.files[0];
      if (!file) return;
      if (file.size > MAX_BYTES) {
        input.value = "";
        hint.textContent = "That file is " + formatSize(file.size) + ". The limit is 5 MB. Split the log by day and try again.";
        return;
      }
      hint.textContent = file.name + " (" + formatSize(file.size) + ")";
    });

    ["dragenter", "dragover"].forEach(function (name) {
      drop.addEventListener(name, function (event) {
        event.preventDefault();
        drop.classList.add("is-over");
      });
    });
    ["dragleave", "drop"].forEach(function (name) {
      drop.addEventListener(name, function () {
        drop.classList.remove("is-over");
      });
    });
    drop.addEventListener("drop", function (event) {
      event.preventDefault();
      if (event.dataTransfer && event.dataTransfer.files.length) {
        input.files = event.dataTransfer.files;
        input.dispatchEvent(new Event("change"));
      }
    });
  }

  if (form && button) {
    form.addEventListener("submit", function () {
      button.textContent = "Analyzing...";
      button.setAttribute("aria-busy", "true");
      window.setTimeout(function () { button.disabled = true; }, 0);
    });
  }

  // Live search on the rows already on the page. The form still filters on the server without JS.
  var search = document.getElementById("filter-q");
  var rows = document.querySelectorAll("#events-table tbody tr, .findings .finding");
  var emptyNote = document.getElementById("events-empty");
  if (search && rows.length) {
    search.addEventListener("input", function () {
      var needle = search.value.trim().toLowerCase();
      var shownEvents = 0;
      rows.forEach(function (row) {
        var match = !needle || (row.getAttribute("data-filter-text") || "").toLowerCase().indexOf(needle) !== -1;
        row.hidden = !match;
        if (match && row.tagName === "TR") shownEvents += 1;
      });
      if (emptyNote) emptyNote.hidden = shownEvents !== 0 || !needle;
    });
    search.form.addEventListener("keydown", function (event) {
      if (event.key === "Enter" && event.target === search) { search.form.submit(); }
    });
  }

  var copy = document.getElementById("copy-blocklist");
  var list = document.getElementById("blocklist");
  if (copy && list && navigator.clipboard) {
    copy.hidden = false;
    copy.addEventListener("click", function () {
      navigator.clipboard.writeText(list.value).then(function () {
        copy.textContent = "Copied";
        window.setTimeout(function () { copy.textContent = "Copy addresses"; }, 2000);
      });
    });
  }
})();
