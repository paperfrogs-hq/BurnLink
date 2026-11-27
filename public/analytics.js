(function () {
  "use strict";

  var PREFERENCE_KEY = "burnlink.analytics.consent";
  var VISITOR_ID_KEY = "burnlink.analytics.id";
  var VISITOR_ID_RE = /^[a-f0-9]{64}$/i;
  var disabledInMemory = false;

  function isDisabled() {
    if (disabledInMemory) return true;
    try {
      return localStorage.getItem(PREFERENCE_KEY) === "rejected";
    } catch (error) {
      return false;
    }
  }

  function getStoredVisitorId() {
    try {
      var id = localStorage.getItem(VISITOR_ID_KEY);
      return VISITOR_ID_RE.test(id || "") ? id : null;
    } catch (error) {
      return null;
    }
  }

  function getVisitorId() {
    return isDisabled() ? null : getStoredVisitorId();
  }

  function makeVisitorId() {
    var bytes = new Uint8Array(32);
    window.crypto.getRandomValues(bytes);
    return Array.from(bytes, function (byte) {
      return byte.toString(16).padStart(2, "0");
    }).join("");
  }

  function headers() {
    var id = getVisitorId();
    return id ? { "X-BurnLink-Analytics-ID": id } : {};
  }

  function recordVisit() {
    var id = getVisitorId();
    if (!id) return;
    fetch("/api/analytics/visit", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-BurnLink-Analytics-ID": id,
      },
      body: "{}",
    }).then(function (response) {
      if (!response.ok) throw new Error("Analytics visit was not recorded.");
    }).catch(function (error) {
      console.error("[analytics] Visit recording failed:", error);
    });
  }

  function startAnalytics(enableExplicitly, status) {
    disabledInMemory = false;
    try {
      var id = getStoredVisitorId() || makeVisitorId();
      localStorage.setItem(VISITOR_ID_KEY, id);
      if (enableExplicitly) localStorage.setItem(PREFERENCE_KEY, "accepted");
    } catch (error) {
      disabledInMemory = true;
      console.error("[analytics] Could not initialize browser identifier:", error);
      if (status) status.textContent = "Analytics could not be enabled in this browser.";
      return false;
    }

    recordVisit();
    return true;
  }

  function showBanner() {
    var banner = document.getElementById("burnlink-analytics-consent");
    if (!banner) {
      banner = document.createElement("section");
      banner.id = "burnlink-analytics-consent";
      banner.className = "burnlink-analytics-consent";
      banner.setAttribute("role", "region");
      banner.setAttribute("aria-label", "Analytics information and preferences");

      var message = document.createElement("p");
      var actions = document.createElement("div");
      actions.className = "burnlink-analytics-actions";

      var dismiss = document.createElement("button");
      dismiss.type = "button";
      dismiss.textContent = "Got it";
      dismiss.addEventListener("click", function () {
        banner.hidden = true;
      });

      var toggle = document.createElement("button");
      toggle.type = "button";
      toggle.className = "burnlink-analytics-toggle";
      toggle.addEventListener("click", function () {
        var status = banner.querySelector(".burnlink-analytics-status");
        if (isDisabled()) {
          if (startAnalytics(true, status)) {
            banner.hidden = true;
          }
          return;
        }
        forgetAndDisable(status).then(function (removed) {
          if (removed) {
            banner.hidden = true;
          }
        });
      });

      var status = document.createElement("span");
      status.className = "burnlink-analytics-status";
      status.setAttribute("aria-live", "polite");

      actions.append(dismiss, toggle);
      banner.append(message, actions, status);
      document.body.appendChild(banner);
    }

    var messageElement = banner.querySelector("p");
    var toggleButton = banner.querySelector(".burnlink-analytics-toggle");
    if (isDisabled()) {
      messageElement.textContent =
        "Analytics is currently off. BurnLink uses first-party analytics to estimate unique browsers and count completed uploads and downloads. If enabled, a random browser ID is hashed before storage; file names, contents, IP addresses, and page URLs are not stored in analytics.";
      toggleButton.textContent = "Turn on analytics";
    } else {
      messageElement.textContent =
        "BurnLink uses first-party analytics to estimate unique browsers and count completed uploads and downloads. No action is needed. A random browser ID is hashed before storage; file names, contents, IP addresses, and page URLs are not stored in analytics. Turn it off anytime in Privacy choices.";
      toggleButton.textContent = "Turn off analytics";
    }
    banner.hidden = false;
  }

  function forgetAndDisable(status) {
    var id = getStoredVisitorId();
    disabledInMemory = true;
    try {
      localStorage.setItem(PREFERENCE_KEY, "rejected");
    } catch (error) {
      console.error("[analytics] Could not save analytics preference:", error);
    }

    if (!id) {
      try {
        localStorage.removeItem(VISITOR_ID_KEY);
      } catch (error) {
        console.error("[analytics] Could not clear analytics identifier:", error);
      }
      return Promise.resolve(true);
    }

    return fetch("/api/analytics/consent", {
      method: "DELETE",
      headers: {
        "Content-Type": "application/json",
        "X-BurnLink-Analytics-ID": id,
      },
      body: "{}",
    }).then(function (response) {
      if (!response.ok) throw new Error("Could not remove stored analytics data.");
      localStorage.removeItem(VISITOR_ID_KEY);
      return true;
    }).catch(function (error) {
      console.error("[analytics] Analytics cleanup failed:", error);
      status.textContent =
        "Analytics is off, but earlier data could not be removed yet. Select “Turn off analytics” again to retry.";
      return false;
    });
  }

  window.BurnLinkAnalytics = { headers: headers };

  if (!isDisabled()) {
    startAnalytics(false);
  }

  var preferencesButton = document.getElementById("analytics-preferences");
  if (preferencesButton) {
    preferencesButton.addEventListener("click", function (event) {
      event.preventDefault();
      showBanner();
    });
  }
})();
