(function () {
  var PBKDF2_ITERATIONS = 210000;
  var textEncoder = new TextEncoder();

  var form = document.getElementById("upload-form");
  var fileInput = document.getElementById("file");
  var passwordInput = document.getElementById("password");
  var uploadBtn = document.getElementById("upload-btn");
  var statusEl = document.getElementById("upload-status");
  var linkBoxEl = document.getElementById("link-box");
  var shareLinkEl = document.getElementById("share-link");
  var copyLinkBtn = document.getElementById("copy-link-btn");
  var copyStatusEl = document.getElementById("copy-status");

  function setStatus(message) {
    statusEl.textContent = message || "";
  }

  function setError(message) {
    statusEl.textContent = message || "";
    statusEl.classList.add("error");
  }

  function showLinkBox(fileId, baseUrl, hasPassword) {
    var shareUrl;

    if (hasPassword) {
      shareUrl = baseUrl + "/file/" + fileId;
    } else {
      var linkKey = sessionStorage.getItem("__fse_link_key_" + fileId);
      if (!linkKey) {
        shareUrl = baseUrl + "/file/" + fileId;
      } else {
        shareUrl = baseUrl + "/file/" + fileId + "#k=" + linkKey;
      }
    }

    shareLinkEl.href = shareUrl;
    shareLinkEl.textContent = shareUrl;
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

    // Build envelope: "FSE1" + version + mode + saltLen + ivLen + salt + iv + ciphertext
    var envelope = new Uint8Array(
      8 + salt.length + iv.length + ciphertext.length
    );

    // "FSE1" magic
    envelope[0] = 70; // F
    envelope[1] = 83; // S
    envelope[2] = 69; // E
    envelope[3] = 49; // 1
    envelope[4] = 1; // version
    envelope[5] = 1; // mode (password)
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

    // Build envelope: "FSE1" + version + mode + saltLen + ivLen + iv + ciphertext
    var envelope = new Uint8Array(8 + iv.length + ciphertext.length);

    // "FSE1" magic
    envelope[0] = 70; // F
    envelope[1] = 83; // S
    envelope[2] = 69; // E
    envelope[3] = 49; // 1
    envelope[4] = 1; // version
    envelope[5] = 2; // mode (link)
    envelope[6] = 0; // saltLen
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
        return;
      }

      var file = fileInput.files[0];
      var fileData = await file.arrayBuffer();
      var fileDataBytes = new Uint8Array(fileData);
      var userPassword = passwordInput.value.trim();

      // Get selected mode
      var modeRadios = document.getElementsByName("mode");
      var selectedMode = "download";
      for (var i = 0; i < modeRadios.length; i++) {
        if (modeRadios[i].checked) {
          selectedMode = modeRadios[i].value;
          break;
        }
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

      setStatus("Uploading encrypted file...");

      var formData = new FormData();
      formData.append(
        "file",
        new Blob([encryptedPayload], { type: "application/octet-stream" }),
        file.name
      );
      formData.append("originalName", file.name);
      formData.append("mode", selectedMode);
      if (userPassword) {
        formData.append("password", userPassword);
      }

      var response = await fetch("/api/upload", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        var message = "Upload failed. Please try again.";
        try {
          var errorBody = await response.json();
          if (errorBody && errorBody.error) {
            message = errorBody.error;
          }
        } catch (e) {
          // response was not JSON, use default message
        }
        throw new Error(message);
      }

      var result = await response.json();

      if (linkKey) {
        sessionStorage.setItem("__fse_link_key_" + result.id, toBase64Url(linkKey));
      }

      showLinkBox(result.id, result.baseUrl, hasPassword);
      setStatus("Success! Your secure link is ready.");

      // Reset form
      fileInput.value = "";
      passwordInput.value = "";
    } catch (error) {
      setError(error.message || "Failed to upload file.");
    } finally {
      uploadBtn.disabled = false;
    }
  }

  async function handleCopyLink(event) {
    event.preventDefault();
    var linkUrl = shareLinkEl.textContent || shareLinkEl.href;

    try {
      await navigator.clipboard.writeText(linkUrl);
      copyStatusEl.textContent = "Copied!";
      setTimeout(() => {
        copyStatusEl.textContent = "";
      }, 2000);
    } catch (error) {
      copyStatusEl.textContent = "Failed to copy.";
    }
  }

  form.addEventListener("submit", handleSubmit);
  copyLinkBtn.addEventListener("click", handleCopyLink);
})();
