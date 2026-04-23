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
  version: "v1.1.1",
  status: "Current Stable",
  launchedOn: "Latest patch shipped April 2026",
  summary:
    "The current public release is v1.1.1 on the Stable Core line, with improved sharing UX and launch-quality documentation for early adopters.",
  shipped: [
    "AES-256 browser-side encryption",
    "One-time download links",
    "Password protection",
    "Drag-and-drop improvements",
    "Upload progress indicator",
    "Copy-to-clipboard with toast feedback",
    "QR code generation for burn links",
    "Comprehensive README refresh",
    "Self-host guide for early adopters",
  ],
  finishing: [
    "Link status tracking and privacy-safe analytics",
    "Link preview page with warning UI",
  ],
};

const changelogEntries = [
  {
    version: "v1.1.1",
    name: "Docs & Launch Finish",
    date: "April 2026",
    summary:
      "Completed launch-quality documentation and self-hosting guides, finishing the v1.1.x release cycle with full feature parity.",
    lede:
      "The first post-launch iteration is now complete. BurnLink is ready for both public use and self-hosted deployments with comprehensive documentation.",
    body: [
      "Together, v1.1.0 and v1.1.1 transformed the sharing experience while maintaining security-first design. Users now have drag-and-drop uploads, QR codes for mobile sharing, and straightforward progress feedback—all without changing the core encryption model.",
      "For early adopters and self-hosters, we've published a complete self-hosting guide covering everything from local setup to production deployment on VPS, Docker, or serverless platforms. The refreshed README makes the security architecture clear for everyone.",
    ],
    highlights: [
      "Refreshed README explaining the encryption model, security, and deployment options.",
      "Complete self-hosting guide with setup for Netlify, Vercel, Docker, and VPS.",
      "Published iteration cadence for roadmap and changelog updates.",
      "All v1.1.0 Share Flow features shipped: drag-and-drop, progress UI, QR codes, mobile responsiveness.",
    ],
    notes:
      "This patch release completes the v1.1.x cycle. With Share Flow and documentation shipped, BurnLink is ready for broader adoption and self-hosting.",
    media: {
      kind: "image",
      variant: "launch-poster",
      eyebrow: "Release Summary",
      title: "Ready for self-hosting",
      description:
        "BurnLink's first full release cycle, complete with improved sharing and self-hosting documentation.",
      asset: {
        png: "/Changelog-v1.1.1.png",
        alt: "BurnLink v1.1.1 Docs & Launch Finish release artwork.",
      },
    },
  },
  {
    version: "v1.1.0",
    name: "Share Flow",
    date: "April 2026",
    summary:
      "Streamlined the sharing workflow with drag-and-drop, QR codes, and real-time progress feedback—no security changes.",
    lede:
      "The first post-launch update removes friction from everyday file sharing. Faster uploads, instant QR generation, and mobile-first design make BurnLink more accessible.",
    body: [
      "Share Flow modernizes the upload experience. Drag files in instead of clicking, watch progress in real-time, and copy links with instant feedback. For mobile users sharing on-the-go, the responsive interface adapts gracefully to smaller screens.",
      "QR codes replace copy-paste for local sharing. Whether you're in a meeting or on the street, users can scan the code and access the encrypted link immediately. The security model remains unchanged—encryption happens client-side, links burn after one download.",
    ],
    highlights: [
      "Drag-and-drop file upload with visual feedback.",
      "Real-time upload progress indicator.",
      "QR code generation for instant link sharing.",
      "Copy-to-clipboard with toast notifications.",
      "Fully responsive upload interface for mobile.",
    ],
    notes:
      "This minor release adds meaningful UX improvements without changing the encryption or access model. Security remains first-class, and the user experience is now more modern.",
    media: {
      kind: "image",
      variant: "launch-poster",
      eyebrow: "Release Preview",
      title: "Sharing, reimagined",
      description:
        "v1.1.0 brings modern sharing workflows with drag-and-drop and QR codes.",
      asset: {
        png: "/Changelog-v1.1.0.png",
        alt: "BurnLink v1.1.0 Share Flow release artwork.",
      },
    },
  },
  {
    version: "v1.0.2",
    name: "Visibility & Planning",
    date: "March 22, 2026",
    summary:
      "Published public changelog and roadmap so users can see what shipped and what's coming next.",
    lede:
      "Transparency matters. BurnLink now shares its release history and planned features in one public location.",
    body: [
      "We added a dedicated changelog page that traces BurnLink's release history from Stable Core (v1.0.0) through the v1.1.x cycle. Each release explains what shipped, why it matters, and how it fits the roadmap.",
      "The public roadmap shows three release tracks: current (Released), near-term (In Progress), and long-term (Platform Expansion). Users can request features and track our progress toward self-hosting, team workspaces, and the transport layer.",
    ],
    highlights: [
      "Changelog page with full release history and version notes.",
      "Public roadmap with three release tracks and timelines.",
      "Footer links to changelog and roadmap from every page.",
      "Transparent release naming and versioning policy.",
    ],
    notes:
      "This patch release improves product communication without changing the core. Transparency builds trust—users can now understand our direction.",
    media: {
      kind: "image",
      variant: "launch-poster",
      eyebrow: "Release Preview",
      title: "Transparent shipping",
      description:
        "Public changelog and roadmap surfaces for tracking BurnLink's progress.",
      asset: {
        png: "/cnglog-v1.0.2.png",
        alt: "BurnLink v1.0.2 Visibility & Planning release artwork.",
      },
    },
  },
  {
    version: "v1.0.1",
    name: "Trust Surface",
    date: "March 21, 2026",
    summary:
      "Strengthened the trust surface with detailed security policy and comparison pages so users can confidently evaluate BurnLink.",
    lede:
      "Before users share sensitive files, they need to understand the security model. This release makes that transparent.",
    body: [
      "We published a comprehensive security policy that explains encryption, data handling, what the server sees, and compliance. We also added comparison pages that honestly position BurnLink against competitors—whether that means highlighting our advantages or acknowledging tradeoffs.",
      "The goal is clarity, not feature sprawl. Users can now read about security in one place, compare options fairly, and make an informed decision about whether BurnLink fits their use case.",
    ],
    highlights: [
      "Detailed security policy page with encryption and handling details.",
      "Comparison pages for major file-sharing alternatives.",
      "Consistent footer navigation across public and app pages.",
      "Clear explanation of the Stable Core line and versioning.",
    ],
    notes:
      "This patch focuses on trust, not features. BurnLink's v1.0.x line prioritizes security clarity and honest positioning over feature additions.",
    media: {
      kind: "image",
      variant: "launch-poster",
      eyebrow: "Feature Spotlight",
      title: "Trust through transparency",
      description:
        "Security policy and comparison pages for informed user decisions.",
      asset: {
        png: "/cnglog-v1.0.1.png",
        alt: "BurnLink v1.0.1 Trust Surface release artwork.",
      },
    },
  },
  {
    version: "v1.0.0",
    name: "Stable Core",
    date: "March 16, 2026",
    summary:
      "BurnLink launched with browser-side encryption, one-time links, and password protection—a security-first baseline for ephemeral file sharing.",
    lede:
      "The foundation is solid: client-side encryption, zero-knowledge architecture, and files that burn after one download. This is Stable Core.",
    body: [
      "Shipping fast wasn't the goal—shipping right was. Stable Core is built on AES-256-GCM encryption that happens entirely in your browser. The server never sees plaintext. Links expire after one download. Passwords work for an extra layer of protection.",
      "We shipped open-source from day one because trustworthiness matters. You can read the code, audit the crypto, and verify the security model. No tracking, no analytics, no surprises. Just a simple, secure way to share files.",
    ],
    highlights: [
      "Browser-side AES-256-GCM encryption—server never sees plaintext.",
      "One-time download links that burn immediately after access.",
      "Optional password protection with brute-force prevention.",
      "Open source and fully auditable on GitHub.",
      "Launched on Product Hunt with community feedback.",
    ],
    notes:
      "Stable Core defines the foundation that future releases build on. Every feature added preserves the security model and zero-knowledge architecture.",
    media: {
      kind: "image",
      variant: "launch-poster",
      eyebrow: "Launch Day",
      title: "Secure by default",
      description:
        "BurnLink's launch, emphasizing encryption-first design and one-time access.",
      asset: {
        webp: "/cnglog-v1.0.0.webp",
        png: "/cnglog-v1.0.0.png",
        alt: "BurnLink v1.0.0 Stable Core launch release artwork.",
      },
    },
  },
];

const roadmapColumns = [
  {
    status: "Released",
    description:
      "The v1.1 release line focuses on improving sharing UX and launch-quality documentation.",
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
      "Link Intelligence brings privacy-safe analytics and status visibility to the link lifecycle.",
    items: [
      {
        version: "v1.2.0",
        name: "Link Intelligence",
        eta: "May 2026",
        summary:
          "Add minimal, privacy-safe analytics and link status tracking without compromising user privacy.",
        features: [
          "View link status: active / burned / expired",
          "Anonymous access log: timestamp + burn confirmation",
          "Link preview page (before burning) with warning UI",
          "Link already burned graceful error page",
          "Zero-tracking analytics (metadata only, no personal data)",
        ],
      },
      {
        version: "v1.3.0",
        name: "Flexible Access",
        eta: "June 2026",
        summary:
          "Give senders more control over how a recipient identifies, opens, and expires a link, with improved comfort and responsiveness across devices.",
        features: [
          "Copy link improvements",
          "File previewer UI and UX update",
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
