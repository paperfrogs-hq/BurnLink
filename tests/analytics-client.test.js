const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function createElement(elements, id, tagName = "div") {
  const listeners = new Map();
  return {
    id,
    tagName,
    children: [],
    hidden: false,
    textContent: "",
    className: "",
    setAttribute() {},
    addEventListener(name, callback) {
      listeners.set(name, callback);
    },
    append(...children) {
      this.children.push(...children);
    },
    appendChild(child) {
      this.children.push(child);
      if (child.id) elements.set(child.id, child);
    },
    querySelector(selector) {
      const isMatch = element => {
        if (selector[0] === ".") {
          return element.className.split(/\s+/).includes(selector.slice(1));
        }
        return element.tagName === selector;
      };
      const find = elements => {
        for (const element of elements) {
          if (isMatch(element)) return element;
          const nested = find(element.children);
          if (nested) return nested;
        }
        return null;
      };
      return find(this.children);
    },
    click(event = { preventDefault() {} }) {
      const callback = listeners.get("click");
      if (callback) callback(event);
    },
  };
}

test("analytics starts automatically and can be turned off from privacy choices", async () => {
  const elements = new Map();
  const storage = new Map();
  const requests = [];
  const preferencesButton = createElement(elements, "analytics-preferences");
  elements.set("analytics-preferences", preferencesButton);
  const document = {
    body: createElement(elements, "body"),
    getElementById(id) {
      return elements.get(id) || null;
    },
    createElement(tagName) {
      return createElement(elements, undefined, tagName);
    },
  };
  document.body.appendChild = function (child) {
    this.children.push(child);
    if (child.id) elements.set(child.id, child);
  };

  const context = {
    document,
    localStorage: {
      getItem: key => storage.get(key) || null,
      setItem: (key, value) => storage.set(key, value),
      removeItem: key => storage.delete(key),
    },
    fetch: (url, options) => {
      requests.push({ url, options });
      return Promise.resolve({ ok: true });
    },
    window: {
      crypto: {
        getRandomValues(bytes) {
          bytes.forEach((_, index) => {
            bytes[index] = index;
          });
          return bytes;
        },
      },
    },
    console,
  };

  const script = fs.readFileSync(
    path.join(__dirname, "../public/analytics.js"),
    "utf8"
  );
  vm.runInNewContext(script, context);

  assert.equal(requests.length, 1);
  assert.equal(requests[0].url, "/api/analytics/visit");

  assert.equal(elements.has("burnlink-analytics-consent"), false);
  const visitorId = storage.get("burnlink.analytics.id");
  assert.match(visitorId, /^[a-f0-9]{64}$/);
  assert.equal(storage.get("burnlink.analytics.consent"), undefined);

  preferencesButton.click();
  const banner = elements.get("burnlink-analytics-consent");
  assert.match(banner.querySelector("p").textContent, /No action is needed/);
  const [, actions] = banner.children;
  const [dismiss, toggle] = actions.children;
  assert.equal(dismiss.textContent, "Got it");
  assert.equal(toggle.textContent, "Turn off analytics");
  assert.equal(requests[0].options.headers["X-BurnLink-Analytics-ID"], visitorId);
  assert.equal(
    context.window.BurnLinkAnalytics.headers()["X-BurnLink-Analytics-ID"],
    visitorId
  );

  dismiss.click();
  assert.equal(banner.hidden, true);
  assert.equal(storage.has("burnlink.analytics.notice-dismissed"), false);
  assert.equal(requests.length, 1);

  preferencesButton.click();
  toggle.click();
  await new Promise(resolve => setImmediate(resolve));

  assert.equal(requests[1].url, "/api/analytics/consent");
  assert.equal(requests[1].options.method, "DELETE");
  assert.equal(storage.get("burnlink.analytics.consent"), "rejected");
  assert.equal(storage.has("burnlink.analytics.id"), false);
  assert.equal(Object.keys(context.window.BurnLinkAnalytics.headers()).length, 0);
});

test("previously opted-out browsers stay off until enabled in privacy choices", async () => {
  const elements = new Map();
  const storage = new Map([
    ["burnlink.analytics.consent", "rejected"],
  ]);
  const requests = [];
  const preferencesButton = createElement(elements, "analytics-preferences");
  elements.set("analytics-preferences", preferencesButton);
  const document = {
    body: createElement(elements, "body"),
    getElementById(id) {
      return elements.get(id) || null;
    },
    createElement(tagName) {
      return createElement(elements, undefined, tagName);
    },
  };
  document.body.appendChild = function (child) {
    this.children.push(child);
    if (child.id) elements.set(child.id, child);
  };

  const context = {
    document,
    localStorage: {
      getItem: key => storage.get(key) || null,
      setItem: (key, value) => storage.set(key, value),
      removeItem: key => storage.delete(key),
    },
    fetch: (url, options) => {
      requests.push({ url, options });
      return Promise.resolve({ ok: true });
    },
    window: {
      crypto: {
        getRandomValues(bytes) {
          bytes.forEach((_, index) => {
            bytes[index] = index;
          });
          return bytes;
        },
      },
    },
    console,
  };

  const script = fs.readFileSync(
    path.join(__dirname, "../public/analytics.js"),
    "utf8"
  );
  vm.runInNewContext(script, context);

  assert.equal(requests.length, 0);
  assert.equal(context.window.BurnLinkAnalytics.headers()["X-BurnLink-Analytics-ID"], undefined);

  assert.equal(elements.has("burnlink-analytics-consent"), false);
  preferencesButton.click();
  const banner = elements.get("burnlink-analytics-consent");
  assert.match(banner.querySelector("p").textContent, /currently off/);
  const [, actions] = banner.children;
  const [, toggle] = actions.children;
  assert.equal(toggle.textContent, "Turn on analytics");
  toggle.click();

  assert.equal(storage.get("burnlink.analytics.consent"), "accepted");
  assert.equal(requests.length, 1);
  assert.equal(requests[0].url, "/api/analytics/visit");
  assert.match(storage.get("burnlink.analytics.id"), /^[a-f0-9]{64}$/);
});
