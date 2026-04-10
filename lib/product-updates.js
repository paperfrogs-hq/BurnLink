const versioningPolicy = [
  {
    label: "Patch releases",
    badge: "v1.0.x",
    description:
      "Use patch versions for trust updates, docs, public pages, security hardening, and UX polish that do not change the product model.",
  },
  {
    label: "Minor releases",
    badge: "v1.x.0",
    description:
      "Use minor versions for meaningful product capabilities like flexible expiry, QR sharing, preview updates, and guest access flows.",
  },
  {
    label: "Major releases",
    badge: "v2.0.0+",
    description:
      "Use major versions when BurnLink expands into a bigger platform surface such as self-hosting, team workspaces, enterprise APIs, or new storage architecture.",
  },
];

const currentRelease = {
  line: "Stable Core",
  version: "v1.0.2",
  status: "Current Stable",
  launchedOn: "Latest patch shipped March 22, 2026",
  summary:
    "The current public release is v1.0.2 on the Stable Core line, focused on making the core trustworthy, documented, and easy to understand before wider platform expansion.",
  shipped: [
    "AES-256 browser-side encryption",
    "One-time download links",
    "Password protection",
    "Open source on GitHub",
    "Product Hunt listing",
    "Basic security policy page",
    "Hall of Fame and comparisons pages",
  ],
  finishing: [
    "Comprehensive README refresh",
    "Self-host guide for early adopters",
  ],
};

const changelogEntries = [
  {
    version: "v1.0.2",
    name: "Visibility & Planning",
    date: "March 22, 2026",
    summary:
      "Added public-facing product updates so users can see what shipped, what is next, and where BurnLink is heading.",
    lede:
      "BurnLink now has a public changelog and roadmap so users can follow what we ship and what we are aiming for next.",
    body: [
      "We wanted a more practical way to communicate progress than scattered page updates. This release adds a dedicated changelog for shipped work and a roadmap for upcoming release trains.",
      "It also tightens product navigation so users can find these pages from anywhere in the public site without hunting through documentation first.",
    ],
    highlights: [
      "Launched a new changelog page for release history and version naming.",
      "Launched a public roadmap page with current, planned, and platform-expansion tracks.",
      "Expanded the footer product section to surface changelog and roadmap from every page.",
    ],
    notes:
      "This is a patch release on the Stable Core line because it improves clarity and product communication without changing the underlying BurnLink model.",
    media: {
      kind: "image",
      variant: "launch-poster",
      eyebrow: "Release preview",
      title: "Public updates, finally in one place",
      description:
        "A rounded visual preview for the new changelog and roadmap surfaces.",
      asset: {
        png: "/cnglog-v1.0.2.png",
        alt: "BurnLink changelog artwork for the v1.0.2 Visibility and Planning release.",
      },
    },
  },
  {
    version: "v1.0.1",
    name: "Trust Surface",
    date: "March 21, 2026",
    summary:
      "Strengthened the public trust surface around BurnLink so users can evaluate the product more easily before sharing sensitive files.",
    lede:
      "This patch release focused on making BurnLink easier to evaluate before users trust it with sensitive files.",
    body: [
      "We expanded the public-facing trust surface with clearer security and comparison pages, making it simpler to understand how BurnLink works and where it fits.",
      "The goal was not more feature sprawl. It was better clarity around the product, its security posture, and its intended use cases.",
    ],
    highlights: [
      "Published and refined the security policy page.",
      "Added public-facing comparison pages for key alternatives.",
      "Improved shared footer navigation across the marketing and app-facing pages.",
    ],
    notes:
      "Patch releases in the v1.0.x line are reserved for trust, docs, and UX improvements while the launch core stays stable.",
    media: {
      kind: "image",
      variant: "launch-poster",
      eyebrow: "Walkthrough clip",
      title: "Trust pages and comparisons",
      description:
        "A changelog-style media card for the new security, trust, and comparison surfaces.",
      asset: {
        png: "/cnglog-v1.0.1.png",
        alt: "BurnLink changelog artwork for the v1.0.1 Trust Surface release.",
      },
    },
  },
  {
    version: "v1.0.0",
    name: "Stable Core",
    date: "March 16, 2026",
    summary:
      "BurnLink shipped its stable launch baseline focused on secure, ephemeral file delivery.",
    lede:
      "The first public release established BurnLink as a privacy-first way to share files with browser-side encryption and one-time access.",
    body: [
      "Stable Core is the release line that everything else builds on. The emphasis here was simple: ship a secure baseline that is usable immediately and understandable without an account wall.",
      "That meant launch-quality encryption, one-time access behavior, password protection, and an open source story from day one.",
    ],
    highlights: [
      "AES-256 encryption happens in the browser before upload.",
      "Links are designed for one-time access and burn-after-retrieval flows.",
      "Password protection shipped as part of the core release.",
      "BurnLink launched publicly and is now live on Product Hunt.",
      "The project is open source on GitHub from day one.",
    ],
    notes:
      "This release defines the Stable Core line that all near-term improvements build on.",
    media: {
      kind: "image",
      variant: "launch-poster",
      eyebrow: "Launch snapshot",
      title: "Stable Core goes live",
      description:
        "A rounded launch card highlighting the release line, Product Hunt launch, and security-first baseline.",
      asset: {
        webp: "/cnglog-v1.0,0.webp",
        png: "/cnglog-v1.0,0.png",
        alt: "BurnLink launch artwork showing the Product Hunt launch card.",
      },
    },
  },
];

const roadmapColumns = [
  {
    status: "Released",
    description:
      "The next release train focuses on everyday sharing quality and smoother delivery UX.",
    items: [
      {
        version: "v1.1.0",
        name: "Share Flow",
        eta: "April 2026",
        summary:
          "Make sending and sharing easier without changing the BurnLink security model.",
        features: [
          "Drag-and-drop improvements",
          "Upload progress indicator",
          "Copy-to-clipboard with toast feedback",
          "QR code generation for burn links",
          "Mobile-responsive upload UI improvements",
        ],
      },
      {
        version: "v1.1.1",
        name: "Docs & Launch Finish",
        eta: "April 2026",
        summary:
          "Finish the launch-quality documentation and operational onboarding around BurnLink.",
        features: [
          "Comprehensive README refresh",
          "Self-host guide for early adopters",
          "Roadmap and changelog iteration cadence",
        ],
      },
    ],
  },
  {
    status: "In Progress",
    description:
      "After the share flow is smoother, BurnLink expands into more flexible access and delivery controls.",
    items: [
      {
        version: "v1.2.0",
        name: "Flexible Access",
        eta: "May 2026",
        summary:
          "Give senders more control over how a recipient identifies, opens, and expires a link.",
        features: [
          "Guest mode with optional recipient name",
          "Expiry options: burn after N downloads or after X hours",
          "Share sheet support",
          "Copy link improvements",
          "File previewer UI and UX update",
        ],
      },
      {
        version: "v1.3.0",
        name: "Reach & Comfort",
        eta: "June 2026",
        summary:
          "Polish the experience across devices and make BurnLink more comfortable in daily use.",
        features: [
          "Better mobile responsiveness across public pages and upload flow",
          "Dark/light mode toggle",
          "Receiver-facing polish for guest and preview states",
        ],
      },
    ],
  },
  {
    status: "Platform Expansion",
    description:
      "Longer-term work turns BurnLink from a single secure file tool into a broader ephemeral data transport layer.",
    items: [
      {
        version: "v2.0.0",
        name: "Transport Layer",
        eta: "Q3 2026+",
        summary:
          "The first major platform release grows BurnLink into a programmable and team-friendly secure delivery layer.",
        features: [
          "Self-hosted version",
          "Team workspaces",
          "Enterprise API",
          "Distributed encrypted storage foundations",
        ],
      },
      {
        version: "v2.1.0",
        name: "Expanded Payloads",
        eta: "Q4 2026+",
        summary:
          "Broaden what BurnLink can carry while preserving ephemeral access expectations.",
        features: [
          "Ephemeral secret messages",
          "Multi-file bundles",
          "Encrypted folders",
          "Private burn vaults",
        ],
      },
    ],
  },
];

module.exports = {
  versioningPolicy,
  currentRelease,
  changelogEntries,
  roadmapColumns,
};
