(() => {
  const toggles = document.querySelectorAll(".site-nav-toggle");

  if (!toggles.length) return;

  const closeMenu = (toggle, header) => {
    toggle.setAttribute("aria-expanded", "false");
    toggle.setAttribute("aria-label", "Open navigation menu");
    header.classList.remove("site-nav-open");
  };

  toggles.forEach((toggle) => {
    const header = toggle.closest("header");
    const nav = header?.querySelector(".site-nav");

    if (!header || !nav) return;

    toggle.addEventListener("click", () => {
      const isExpanded = toggle.getAttribute("aria-expanded") === "true";
      toggle.setAttribute("aria-expanded", String(!isExpanded));
      toggle.setAttribute(
        "aria-label",
        isExpanded ? "Open navigation menu" : "Close navigation menu",
      );
      header.classList.toggle("site-nav-open", !isExpanded);
    });

    nav.addEventListener("click", (event) => {
      if (event.target instanceof Element && event.target.closest("a")) {
        closeMenu(toggle, header);
      }
    });

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") closeMenu(toggle, header);
    });
  });

  document.documentElement.classList.add("has-site-nav-toggle");
})();
