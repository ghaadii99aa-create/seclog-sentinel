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
