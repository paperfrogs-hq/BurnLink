(function () {
  var PBKDF2_ITERATIONS = 210000;
  var textEncoder = new TextEncoder();

  var form = document.getElementById("upload-form");
  var fileInput = document.getElementById("file");
  var passwordInput = document.getElementById("password");
  var passwordToggleBtn = document.getElementById("password-toggle");
  var uploadBtn = document.getElementById("upload-btn");
  var statusEl = document.getElementById("upload-status");
  var linkBoxEl = document.getElementById("link-box");
  var shareLinkEl = document.getElementById("share-link");
  var copyLinkBtn = document.getElementById("copy-link-btn");
  var qrBtn = document.getElementById("qr-btn");
  var qrModal = document.getElementById("qr-modal");
  var qrModalClose = document.getElementById("qr-modal-close");
  var qrImage = document.getElementById("qr-image");
  var qrDownloadBtn = document.getElementById("qr-download-btn");
  var dragDropZone = document.getElementById("drag-drop-zone");
  var progressContainer = document.getElementById("progress-container");
  var progressBarFill = document.getElementById("progress-bar-fill");
  var progressText = document.getElementById("progress-text");
  var toastContainer = document.getElementById("toast-container");

  var currentFileId = null;

  // ── Toast Notification System ──
  function showToast(message, type) {
    type = type || "info";
    var toast = document.createElement("div");
    toast.className = "toast " + type;
    toast.textContent = message;
    toastContainer.appendChild(toast);

    setTimeout(function() {
      toast.classList.add("hide");
      setTimeout(function() {
        toast.remove();
      }, 300);
    }, 3000);
  }

  function setStatus(message) {
    statusEl.textContent = message || "";
    statusEl.classList.remove("error");
  }

  function setError(message) {
    statusEl.textContent = message || "";
    statusEl.classList.add("error");
  }

  function hasWhitespace(value) {
    return /\s/.test(value || "");
  }

  // ── Drag and Drop ──
  function setupDragDrop() {
    // Click to select file
    dragDropZone.addEventListener("click", function(e) {
      e.preventDefault();
      fileInput.click();
    });

    dragDropZone.addEventListener("dragover", function(e) {
      e.preventDefault();
      e.stopPropagation();
      dragDropZone.classList.add("dragover");
    }, false);

    dragDropZone.addEventListener("dragleave", function(e) {
      e.preventDefault();
      e.stopPropagation();
      dragDropZone.classList.remove("dragover");
    }, false);

    dragDropZone.addEventListener("drop", function(e) {
      e.preventDefault();
      e.stopPropagation();
      dragDropZone.classList.remove("dragover");

      var files = e.dataTransfer.files;
      if (files && files.length > 0) {
        fileInput.files = files;
        handleFileSelected();
      }
    }, false);

    fileInput.addEventListener("change", handleFileSelected);
  }

  function handleFileSelected() {
    if (fileInput.files && fileInput.files.length > 0) {
      var file = fileInput.files[0];
      var sizeInMB = (file.size / 1024 / 1024).toFixed(2);
      dragDropZone.innerHTML = '<div class="drag-drop-text">' + file.name + '</div><div class="drag-drop-hint">' + sizeInMB + ' MB</div>';
      dragDropZone.style.borderColor = '#28a745';
      dragDropZone.style.background = '#0a2a1a';
      setStatus("File selected: " + file.name);
    }
  }

  // ── Progress Indicator ──
  function updateProgress(percent) {
    progressBarFill.style.width = percent + "%";
    progressText.textContent = percent + "%";
  }

  function showProgress() {
    progressContainer.classList.add("active");
    updateProgress(0);
  }

  function hideProgress() {
    progressContainer.classList.remove("active");
  }

  // ── Turnstile Support ──
  function getTurnstileToken() {
    if (typeof window.turnstile !== 'undefined') {
      return window.turnstile.getResponse();
    }
    return null;
  }

  function resetTurnstile() {
    if (typeof window.turnstile !== 'undefined') {
      window.turnstile.reset();
    }
  }

  function togglePasswordVisibility(e) {
    e.preventDefault();
    if (!passwordInput || !passwordToggleBtn) return;
    var showing = passwordInput.type === "text";
    passwordInput.type = showing ? "password" : "text";
    passwordToggleBtn.textContent = showing ? "Show" : "Hide";
    passwordToggleBtn.setAttribute("aria-pressed", showing ? "false" : "true");
    passwordToggleBtn.setAttribute("aria-label", showing ? "Show password" : "Hide password");
  }

  function closeQrModal() {
    if (qrModal) qrModal.classList.remove("active");
  }

  function openQrModal() {
    if (qrModal) qrModal.classList.add("active");
  }

  async function generateAndShowQr() {
    if (!currentFileId) return;
    try {
      var response = await fetch("/api/qr/" + currentFileId);
      if (!response.ok) throw new Error("Failed to generate QR code");
      var data = await response.json();
      if (qrImage) {
        qrImage.src = data.qrDataUrl;
        qrImage.alt = "QR Code for sharing";
      }
      openQrModal();
      showToast("QR code generated!", "success");
    } catch (error) {
      showToast("Failed to generate QR: " + error.message, "error");
    }
  }

  function downloadQrCode() {
    if (!qrImage || !qrImage.src) return;
    try {
      var link = document.createElement("a");
      link.href = qrImage.src;
      link.download = "burnlink-qr-" + currentFileId + ".png";
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      showToast("QR code downloaded!", "success");
    } catch (err) {
      showToast("Failed to download QR code", "error");
    }
  }

  function showLinkBox(fileId, baseUrl, hasPassword) {
    var displayUrl = baseUrl + "/s/" + fileId;
    var shareUrl;

    if (hasPassword) {
      shareUrl = displayUrl;
    } else {
      var linkKey = sessionStorage.getItem("__fse_link_key_" + fileId);
      shareUrl = linkKey ? displayUrl + "#" + linkKey : displayUrl;
    }

    currentFileId = fileId;
    shareLinkEl.href = shareUrl;
    shareLinkEl.textContent = displayUrl;
    linkBoxEl.hidden = false;
  }

  function toBase64Url(bytes) {
    var binary = "";
    for (var i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  async function deriveKeyFromPassword(password, salt) {
    var baseKey = await crypto.subtle.importKey(
      "raw",
      textEncoder.encode(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256",
      },
      baseKey,
      {
        name: "AES-GCM",
        length: 256,
      },
      false,
      ["encrypt"]
    );
  }

  async function deriveServerToken(password) {
    var baseKey = await crypto.subtle.importKey(
      "raw",
      textEncoder.encode(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    var derivedKey = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: textEncoder.encode("burnlink-server-auth-v1"),
        iterations: 1000,
        hash: "SHA-256",
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt"]
    );
    var raw = new Uint8Array(await crypto.subtle.exportKey("raw", derivedKey));
    return Array.from(raw).map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");
  }

  async function generateLinkKey() {
    var key = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt"]
    );
    var exported = await crypto.subtle.exportKey("raw", key);
    return new Uint8Array(exported);
  }

  async function encryptFileWithPassword(fileData, password) {
    var salt = crypto.getRandomValues(new Uint8Array(16));
    var iv = crypto.getRandomValues(new Uint8Array(12));

    var key = await deriveKeyFromPassword(password, salt);

    var ciphertext = new Uint8Array(
      await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, fileData)
    );

    var envelope = new Uint8Array(
      8 + salt.length + iv.length + ciphertext.length
    );

    envelope[0] = 70;
    envelope[1] = 83;
    envelope[2] = 69;
    envelope[3] = 49;
    envelope[4] = 1;
    envelope[5] = 1;
    envelope[6] = salt.length;
    envelope[7] = iv.length;

    var offset = 8;
    envelope.set(salt, offset);
    offset += salt.length;
    envelope.set(iv, offset);
    offset += iv.length;
    envelope.set(ciphertext, offset);

    return envelope;
  }

  async function encryptFileWithLink(fileData) {
    var linkKey = await generateLinkKey();
    var iv = crypto.getRandomValues(new Uint8Array(12));

    var key = await crypto.subtle.importKey(
      "raw",
      linkKey,
      { name: "AES-GCM" },
      false,
      ["encrypt"]
    );

    var ciphertext = new Uint8Array(
      await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, fileData)
    );

    var envelope = new Uint8Array(8 + iv.length + ciphertext.length);

    envelope[0] = 70;
    envelope[1] = 83;
    envelope[2] = 69;
    envelope[3] = 49;
    envelope[4] = 1;
    envelope[5] = 2;
    envelope[6] = 0;
    envelope[7] = iv.length;

    var offset = 8;
    envelope.set(iv, offset);
    offset += iv.length;
    envelope.set(ciphertext, offset);

    return {
      envelope: envelope,
      linkKey: linkKey,
    };
  }

  async function handleSubmit(event) {
    event.preventDefault();
    statusEl.classList.remove("error");
    setStatus("Preparing file...");
    uploadBtn.disabled = true;

    try {
      if (!fileInput.files || fileInput.files.length === 0) {
        setError("Please select a file.");
        uploadBtn.disabled = false;
        return;
      }

      var file = fileInput.files[0];
      var MAX_UPLOAD_BYTES = 1 * 1024 * 1024 * 1024;
      if (file.size > MAX_UPLOAD_BYTES) {
        setError("File too large. Maximum upload size is 1 GB.");
        uploadBtn.disabled = false;
        return;
      }

      var modeRadios = document.getElementsByName("mode");
      var selectedMode = "download";
      for (var i = 0; i < modeRadios.length; i++) {
        if (modeRadios[i].checked) {
          selectedMode = modeRadios[i].value;
          break;
        }
      }

      var fileData = await file.arrayBuffer();
      var fileDataBytes = new Uint8Array(fileData);
      var userPassword = passwordInput.value;

      if (hasWhitespace(userPassword)) {
        setError("Passwords cannot contain spaces.");
        uploadBtn.disabled = false;
        return;
      }

      var encryptedPayload;
      var linkKey = null;
      var hasPassword = Boolean(userPassword);

      setStatus("Encrypting file in your browser...");

      if (hasPassword) {
        encryptedPayload = await encryptFileWithPassword(fileDataBytes, userPassword);
      } else {
        var result = await encryptFileWithLink(fileDataBytes);
        encryptedPayload = result.envelope;
        linkKey = result.linkKey;
      }

      setStatus("Preparing secure upload...");
      var presignRes = await fetch("/api/presign?" + new URLSearchParams({ filename: file.name, filesize: file.size }));
      if (!presignRes.ok) throw new Error("Could not get upload URL. Please try again.");
      var presignData = await presignRes.json();

      showProgress();
      setStatus("Uploading encrypted file...");

      var blob = new Blob([encryptedPayload]);
      var xhr = new XMLHttpRequest();

      xhr.upload.addEventListener("progress", function(e) {
        if (e.lengthComputable) {
          var percent = Math.round((e.loaded / e.total) * 100);
          updateProgress(percent);
          setStatus("Uploading... " + percent + "%");
        }
      });

      xhr.addEventListener("load", async function() {
        if (xhr.status >= 200 && xhr.status < 300) {
          setStatus("Finalizing...");
          hideProgress();

          var serverToken = userPassword ? await deriveServerToken(userPassword) : null;
          var commitPayload = {
            storagePath: presignData.storagePath,
            originalName: file.name,
            mode: selectedMode,
          };
          if (serverToken) commitPayload.password = serverToken;
          if (linkKey) commitPayload.linkKey = toBase64Url(linkKey);

          var turnstileToken = getTurnstileToken();
          if (turnstileToken) {
            commitPayload["cf-turnstile-response"] = turnstileToken;
          }

          var commitRes = await fetch("/api/commit", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(commitPayload),
          });

          if (!commitRes.ok) {
            var message = "Upload failed. Please try again.";
            try {
              var errorBody = await commitRes.json();
              if (errorBody && errorBody.error) message = errorBody.error;
            } catch (e) {}
            throw new Error(message);
          }

          var commitData = await commitRes.json();
          if (linkKey) {
            sessionStorage.setItem("__fse_link_key_" + commitData.id, toBase64Url(linkKey));
          }

          showLinkBox(commitData.id, commitData.baseUrl, hasPassword);
          setStatus("File successfully uploaded!");
          showToast("File has been uploaded! Your secure link is ready to share.", "success");
          resetTurnstile();

          fileInput.value = "";
          passwordInput.value = "";
          dragDropZone.innerHTML = '<div class="drag-drop-text">Drag and drop your file here</div><div class="drag-drop-hint">or click to browse</div>';
          dragDropZone.style.borderColor = '#2a2a2a';
          dragDropZone.style.background = '#0f0f0f';
        } else {
          throw new Error("Upload to storage failed (HTTP " + xhr.status + "). Please try again.");
        }
      });

      xhr.addEventListener("error", function() {
        hideProgress();
        throw new Error("Upload blocked (CORS or network error).");
      });

      xhr.addEventListener("abort", function() {
        hideProgress();
        throw new Error("Upload cancelled.");
      });

      xhr.open("PUT", presignData.uploadUrl);
      xhr.send(blob);

    } catch (error) {
      hideProgress();
      setError(error.message || "Failed to upload file.");
      showToast(error.message || "Failed to upload", "error");
      resetTurnstile();
    } finally {
      uploadBtn.disabled = false;
    }
  }

  async function handleCopyLink(event) {
    event.preventDefault();
    var linkUrl = shareLinkEl.href;

    try {
      await navigator.clipboard.writeText(linkUrl);
      showToast("Link copied to clipboard!", "success");
    } catch (error) {
      showToast("Failed to copy link", "error");
    }
  }

  // ── Event Listeners ──
  form.addEventListener("submit", handleSubmit);

  if (copyLinkBtn) {
    copyLinkBtn.addEventListener("click", handleCopyLink);
  }

  if (passwordToggleBtn) {
    passwordToggleBtn.addEventListener("click", togglePasswordVisibility);
  }

  if (qrBtn) {
    qrBtn.addEventListener("click", generateAndShowQr);
  }

  if (qrModalClose) {
    qrModalClose.addEventListener("click", closeQrModal);
  }

  if (qrModal) {
    qrModal.addEventListener("click", function(e) {
      if (e.target === qrModal) closeQrModal();
    });
  }

  if (qrDownloadBtn) {
    qrDownloadBtn.addEventListener("click", downloadQrCode);
  }

  // Setup drag-drop on page load
  setupDragDrop();
})();
