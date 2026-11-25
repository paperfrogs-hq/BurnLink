(function () {
  var qs = (function () {
    var p = {};
    location.search.slice(1).split("&").forEach(function (kv) {
      var kvp = kv.split("=");
      if (kvp[0]) p[kvp[0]] = kvp[1] || "1";
    });
    return p;
  })();
  var forceOn = qs.winter === "1";
  var forceOff = qs.winter === "off" || localStorage.getItem("burnlink-snow") === "off";
  var m = new Date().getMonth();
  var d = new Date().getDate();
  var inSeason = m === 10 || m === 11 || m === 0 || m === 1;
  var isXmas = m === 11 && d >= 1;
  if (!forceOn && forceOff) return;
  if (!forceOn && !inSeason) return;
  if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

  var c = document.createElement("canvas");
  c.setAttribute("aria-hidden", "true");
  var s = c.style;
  s.position = "fixed";
  s.top = "0";
  s.left = "0";
  s.width = "100%";
  s.height = "100%";
  s.pointerEvents = "none";
  s.zIndex = "99999";
  document.body.appendChild(c);

  var ctx = c.getContext("2d");
  if (!ctx) return;
  var w = 0, h = 0, dpr = 1, objs = [], raf = 0, last = 0;

  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    w = window.innerWidth;
    h = window.innerHeight;
    c.width = Math.floor(w * dpr);
    c.height = Math.floor(h * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    var target = Math.min(120, Math.max(40, Math.floor(w / 14)));
    while (objs.length < target) objs.push(make(true));
    if (objs.length > target) objs.length = target;
  }

  function drawStar(x, y, r, rot) {
    ctx.beginPath();
    for (var i = 0; i < 5; i++) {
      var a = Math.PI / 2 + i * 4 * Math.PI / 5 + rot;
      var ax = x + Math.cos(a) * r;
      var ay = y - Math.sin(a) * r;
      if (i === 0) ctx.moveTo(ax, ay);
      else ctx.lineTo(ax, ay);
      var a2 = a + 2 * Math.PI / 5;
      var bx = x + Math.cos(a2) * (r * 0.382);
      var by = y - Math.sin(a2) * (r * 0.382);
      ctx.lineTo(bx, by);
    }
    ctx.closePath();
    ctx.fill();
  }

  function drawBell(x, y, r) {
    ctx.beginPath();
    ctx.arc(x, y - r * 0.18, r * 0.45, Math.PI, 2 * Math.PI);
    ctx.lineTo(x + r * 0.45, y + r * 0.25);
    ctx.arc(x, y + r * 0.28, r * 0.55, 0, Math.PI, true);
    ctx.lineTo(x - r * 0.45, y + r * 0.25);
    ctx.closePath();
    ctx.fill();
    ctx.beginPath();
    ctx.arc(x, y - r * 0.45, r * 0.08, 0, 2 * Math.PI);
    ctx.fillStyle = "#e5e7eb";
    ctx.fill();
    ctx.fillStyle = "#fbbf24";
  }

  function drawOrnament(x, y, r, c) {
    ctx.beginPath();
    ctx.arc(x, y, r, 0, 2 * Math.PI);
    ctx.fillStyle = c;
    ctx.fill();
    ctx.beginPath();
    ctx.moveTo(x - r * 0.35, y - r);
    ctx.lineTo(x + r * 0.35, y - r);
    ctx.lineTo(x, y - r * 0.2);
    ctx.closePath();
    ctx.fillStyle = "#b91c1c";
    ctx.fill();
    ctx.beginPath();
    ctx.arc(x - r * 0.25, y - r * 0.6, r * 0.16, 0, 2 * Math.PI);
    ctx.fillStyle = "#ffffff";
    ctx.fill();
  }

  function make(randY) {
    var type = Math.random();
    var r = Math.random() * 3 + 1;
    var base = {
      x: Math.random() * w,
      y: randY ? Math.random() * h : -r - Math.random() * h * 0.3,
      r: r,
      v: Math.random() * 0.7 + 0.3,
      drift: Math.random() * 0.6 - 0.3,
      phase: Math.random() * Math.PI * 2,
      a: Math.random() * 0.5 + 0.4,
      type: "snow"
    };
    if (isXmas && type < 0.15) {
      if (type < 0.05) base.type = "bell";
      else if (type < 0.10) base.type = "star";
      else base.type = "ornament";
    }
    return base;
  }

  function tick(ts) {
    if (document.hidden) { raf = requestAnimationFrame(tick); last = ts; return; }
    var dt = last ? Math.min(48, ts - last) : 16;
    last = ts;
    var k = dt / 16.67;
    ctx.clearRect(0, 0, w, h);
    for (var i = 0; i < objs.length; i++) {
      var o = objs[i];
      o.phase += 0.012 * dt;
      o.y += o.v * k * (o.r * 0.5 + 0.7);
      o.x += (o.drift + Math.sin(o.phase) * 0.4) * k;
      if (o.y > h + o.r) objs[i] = make(false);
      if (o.x < -15) o.x = w + 15;
      else if (o.x > w + 15) o.x = -15;

      ctx.save();
      ctx.translate(o.x, o.y);
      ctx.rotate(o.phase * 0.3);
      if (o.type === "snow") {
        ctx.fillStyle = "rgba(255,255,255," + o.a + ")";
        ctx.beginPath();
        ctx.arc(0, 0, o.r, 0, Math.PI * 2);
        ctx.fill();
      } else if (o.type === "bell") {
        ctx.fillStyle = "#fbbf24";
        drawBell(0, 0, o.r * 1.6);
      } else if (o.type === "star") {
        ctx.fillStyle = "#fbbf24";
        drawStar(0, 0, o.r * 1.4, o.phase);
      } else if (o.type === "ornament") {
        drawOrnament(0, 0, o.r * 1.4, o.a > 0.6 ? "#dc2626" : "#16a34a");
      }
      ctx.restore();
    }
    raf = requestAnimationFrame(tick);
  }

  window.addEventListener("resize", resize, { passive: true });
  document.addEventListener("visibilitychange", function () { if (!document.hidden) last = 0; });
  resize();
  raf = requestAnimationFrame(tick);
  try { console.log("[burnlink-winter] active month=" + m + " xmas=" + isXmas + " forceOn=" + forceOn); } catch (e) {}
})();
