const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");

const app = require("../app");

let server;
let port;

async function request(path, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port,
        path,
        method: options.method || "GET",
        headers: options.headers || {},
      },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          body += chunk;
        });
        res.on("end", () => {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body,
          });
        });
      }
    );
    req.on("error", reject);
    if (options.body) req.write(options.body);
    req.end();
  });
}

test.before(async () => {
  await new Promise((resolve) => {
    server = app.listen(0, () => {
      port = server.address().port;
      resolve();
    });
  });
});

test.after(async () => {
  if (!server) return;
  await new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) return reject(error);
      resolve();
    });
  });
});

test("core pages render without crashing", async () => {
  const pages = [
    ["/", "BurnLink — Secure File Sharing with End-to-End Encryption"],
    ["/about", "How BurnLink Works — End-to-End Encrypted File Sharing"],
    ["/changelog", "BurnLink Changelog — Version History & Updates"],
    ["/roadmap", "BurnLink Roadmap — Upcoming Features & Development"],
    ["/security-policy", "BurnLink Security & Privacy Policy — End-to-End Encryption"],
    ["/hall-of-fame", "Hall of Fame — BurnLink"],
  ];

  for (const [path, title] of pages) {
    const response = await request(path);
    assert.equal(response.status, 200, `${path} should return 200`);
    assert.match(response.body, new RegExp(`<title>${title.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}<\\/title>`));
    assert.match(response.body, /BurnLink vs WeTransfer/);
  }
});

test("public pages share the same header navigation", async () => {
  const pages = ["/", "/about", "/changelog", "/roadmap", "/comparisons/wetransfer"];

  for (const path of pages) {
    const response = await request(path);
    assert.equal(response.status, 200, `${path} should return 200`);
    assert.match(response.body, /href="\/"(?: class="active")?>Home<\/a>/);
    assert.match(response.body, /href="\/about"/);
    assert.match(response.body, /href="\/changelog"/);
    assert.match(response.body, /href="\/roadmap"/);
    assert.match(response.body, /class="site-nav-toggle"/);
    assert.match(response.body, /aria-controls="site-navigation"/);
    assert.match(response.body, /href="\/responsive\.css"/);
  }
});

test("responsive navigation assets are served", async () => {
  const stylesheet = await request("/responsive.css");
  const script = await request("/site.js");

  assert.equal(stylesheet.status, 200);
  assert.match(stylesheet.headers["content-type"], /text\/css/);
  assert.match(stylesheet.body, /site-nav-open/);
  assert.match(stylesheet.body, /\.footer-wordmark\s*\{[^}]*color:\s*#331B13;[^}]*opacity:\s*0\.3/s);

  assert.equal(script.status, 200);
  assert.match(script.headers["content-type"], /javascript/);
  assert.match(script.body, /aria-expanded/);
});

test("public pages use first-party analytics without third-party trackers", async () => {
  const response = await request("/");
  const uploadScript = await request("/upload.js");
  const analyticsScript = await request("/analytics.js");

  assert.equal(response.status, 200);
  assert.doesNotMatch(response.body, /static\.cloudflareinsights\.com|cloud\.umami\.is/);
  assert.doesNotMatch(response.body, /SpeedInsights/);
  assert.match(response.body, /challenges\.cloudflare\.com\/turnstile\/v0\/api\.js/);
  assert.match(response.body, /analytics-preferences/);
  assert.equal(uploadScript.status, 200);
  assert.doesNotMatch(uploadScript.body, /sessionStorage|__fse_link_key_/);
  assert.match(uploadScript.body, /var linkUrl = shareLinkEl\.href;/);
  assert.equal(analyticsScript.status, 200);
  assert.match(analyticsScript.body, /No action is needed/);
  assert.match(analyticsScript.body, /Turn off analytics/);
  assert.doesNotMatch(analyticsScript.body, /Accept analytics|Reject/);

  for (const path of [
    "/about",
    "/security-policy",
    "/changelog",
    "/roadmap",
    "/hall-of-fame",
    "/comparisons/wetransfer",
  ]) {
    const page = await request(path);
    assert.equal(page.status, 200, `${path} should return 200`);
    assert.doesNotMatch(page.body, /static\.cloudflareinsights\.com|cloud\.umami\.is/);
  }
});

test("analytics write endpoints require a valid browser identifier", async () => {
  const visit = await request("/api/analytics/visit", { method: "POST" });
  const revoke = await request("/api/analytics/consent", { method: "DELETE" });

  assert.equal(visit.status, 400);
  assert.equal(revoke.status, 400);
});

test("changelog and roadmap expose versioning and planned work", async () => {
  const changelog = await request("/changelog");
  const roadmap = await request("/roadmap");

  assert.equal(changelog.status, 200);
  assert.match(changelog.body, /v1\.0\.2/);
  assert.match(changelog.body, /Stable Core/);
  assert.match(changelog.body, /v1\.1\.1/);
  assert.match(changelog.body, /Visibility &amp; Planning/);

  assert.equal(roadmap.status, 200);
  assert.match(roadmap.body, /v1\.1\.0/);
  assert.match(roadmap.body, /Share Flow/);
  assert.match(roadmap.body, /Platform Expansion/);
  assert.match(roadmap.body, /Transport Layer/);
  assert.match(roadmap.body, /Request a feature/);
  assert.match(roadmap.body, /mailto:hello@paperfrogs\.dev\?subject=BurnLink%20Feature%20Request/);
});

test("comparison pages render with SEO and CTA content", async () => {
  const comparisons = [
    {
      path: "/comparisons/wetransfer",
      title: "BurnLink vs WeTransfer - Private File Sharing for One-Time Delivery",
      competitor: "WeTransfer",
    },
    {
      path: "/comparisons/dropbox-transfer",
      title: "BurnLink vs Dropbox Transfer - A Privacy-First Alternative",
      competitor: "Dropbox Transfer",
    },
    {
      path: "/comparisons/smash",
      title: "BurnLink vs Smash - Secure Sharing for Sensitive Files",
      competitor: "Smash",
    },
    {
      path: "/comparisons/swisstransfer",
      title: "BurnLink vs SwissTransfer - Encrypted One-Time File Sharing",
      competitor: "SwissTransfer",
    },
  ];

  for (const comparison of comparisons) {
    const response = await request(comparison.path);
    assert.equal(response.status, 200, `${comparison.path} should return 200`);
    assert.match(response.body, new RegExp(`<title>${comparison.title.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}<\\/title>`));
    assert.match(response.body, new RegExp(`BurnLink vs ${comparison.competitor.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
    assert.match(response.body, /Share a file/);
    assert.match(response.body, /How BurnLink works/);
    assert.match(response.body, new RegExp(`<link rel="canonical" href="https://burnlink\\.page${comparison.path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`));
    assert.doesNotMatch(response.body, /no-size-limit|unlimited/i);
  }
});

test("comparison pages include related alternatives and shared footer links", async () => {
  const response = await request("/comparisons/wetransfer");

  assert.equal(response.status, 200);
  assert.match(response.body, /BurnLink vs Dropbox Transfer/);
  assert.match(response.body, /BurnLink vs Smash/);
  assert.match(response.body, /BurnLink vs SwissTransfer/);
  assert.match(response.body, /<h3>Comparisons<\/h3>/);
  assert.match(response.body, /href="\/comparisons\/wetransfer"/);
});

test("footer product section links to changelog and roadmap", async () => {
  const response = await request("/");

  assert.equal(response.status, 200);
  assert.match(response.body, /<h3>Product<\/h3>/);
  assert.match(response.body, /<div class="footer-wordmark" aria-hidden="true">BURNLINK<\/div>/);
  assert.match(response.body, /href="\/changelog"/);
  assert.match(response.body, /href="\/roadmap"/);
  assert.doesNotMatch(response.body, /<a href="\/">Share files<\/a>/);
});

test("unknown comparison slugs return the existing not found page", async () => {
  const response = await request("/comparisons/not-a-real-tool");

  assert.equal(response.status, 404);
  assert.match(response.body, /File Not Found - BurnLink/);
});
