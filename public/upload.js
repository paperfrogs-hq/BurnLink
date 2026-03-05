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
    var displayUrl = baseUrl + "/s/" + fileId; // always clean for display

    if (hasPassword) {
      shareUrl = displayUrl;
    } else {
      var linkKey = sessionStorage.getItem("__fse_link_key_" + fileId);
      shareUrl = linkKey ? displayUrl + "#" + linkKey : displayUrl;
    }

    shareLinkEl.href = displayUrl;        // clean URL — key is now stored server-side
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

  // Derives a server-side authentication token from the password.
  // A low-iteration PBKDF2 with a fixed public salt is used so the raw
  // password never leaves the browser; the server only ever stores a
  // bcrypt hash of this derived token — not the actual encryption key.
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
      var MAX_UPLOAD_BYTES = 1 * 1024 * 1024 * 1024; // 1 GB
      if (file.size > MAX_UPLOAD_BYTES) {
        setError("File too large. Maximum upload size is 1 GB.");
        return;
      }
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

      // Step 1 — get a presigned PUT URL from the server
      setStatus("Preparing secure upload...");
      var presignRes = await fetch("/api/presign?" + new URLSearchParams({ filename: file.name, filesize: file.size }));
      if (!presignRes.ok) throw new Error("Could not get upload URL. Please try again.");
      var presignData = await presignRes.json();

      // Step 2 — encrypt the file (already done above)
      // Step 3 — PUT encrypted bytes directly to R2 (bypasses Netlify size cap)
      // No Content-Type header here — keeps this a CORS simple request (no preflight)
      setStatus("Uploading encrypted file...");
      var putRes;
      try {
        putRes = await fetch(presignData.uploadUrl, {
          method: "PUT",
          body: new Blob([encryptedPayload]),
        });
      } catch (putErr) {
        throw new Error("Upload blocked (CORS or network). Check R2 CORS policy allows this origin. Detail: " + putErr.message);
      }
      if (!putRes.ok) throw new Error("Upload to storage failed (HTTP " + putRes.status + "). Please try again.");

      // Step 4 — tell the server to save the metadata
      setStatus("Finalizing...");
      var serverToken = userPassword ? await deriveServerToken(userPassword) : null;
      var turnstileInput = document.querySelector('[name="cf-turnstile-response"]');
      var commitPayload = {
        storagePath: presignData.storagePath,
        originalName: file.name,
        mode: selectedMode,
        "cf-turnstile-response": turnstileInput ? turnstileInput.value : "",
      };
      if (serverToken) commitPayload.password = serverToken;
      if (linkKey) commitPayload.linkKey = toBase64Url(linkKey);

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
        } catch (e) {
          message = "Upload failed (HTTP " + commitRes.status + ")";
        }
        throw new Error(message);
      }

      var result = await commitRes.json();

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
    var linkUrl = shareLinkEl.href; // clean URL — key is now stored server-side

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
