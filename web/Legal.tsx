const pages = {
  privacy: {
    title: "Privacy Policy",
    updated: "11 October 2026",
    sections: [
      {
        heading: "Who is responsible",
        body: [
          "KeySprig is an invitation-only prototype operated by the KeySprig team. For privacy questions or requests about your personal data, contact privacy@keysprig.xyz.",
          "This contact statement describes the current prototype. The operator’s formal legal identity and address have not yet been published.",
        ],
      },
      {
        heading: "What we store",
        body: [
          "KeySprig stores only what the service needs to run your vault:",
        ],
        list: [
          "Account email, and a password hash if you create an email-and-password account. These are held by Supabase Auth.",
          "If you choose Google sign-in, Google’s account profile for that login (typically email and basic profile) is processed through Supabase Auth. Google is not used unless you pick that sign-in method.",
          "Encrypted API key values (ciphertext, nonce and key version). The hosted service can decrypt them to make approved requests. This is not a zero-knowledge vault.",
          "Key names and the policy you set: allowed hosts, authentication header and prefix, allowed HTTP methods, and the per-minute request limit.",
          "Connected AI agents (OAuth client id and label) and the key grants you approve, including expiry and revocation.",
          "Audit events such as key created or deleted, client approved or disconnected, and API-call metadata (key name, destination host, method and outcome). Audit events do not store secret values, request bodies or provider response bodies.",
          "Short-lived per-agent, per-key rate-limit counters used to enforce the limit you configured.",
          "Invitation code hashes and the email address associated with an invitation claim. A pending claim expires after 30 minutes. We also keep a record that an invitation has been redeemed so it cannot be used again.",
          "A salted hash of the network address used for invitation claims, with request counters and timestamps, to limit repeated attempts. KeySprig does not store the raw network address in this table.",
          "Feedback you choose to submit, its category, and your account identifier, so the team can review reports and suggestions. Do not include API keys or other secrets in feedback.",
        ],
      },
      {
        heading: "Who processes it",
        body: ["These processors handle data on our behalf:"],
        list: [
          "Supabase — accounts, authentication, OAuth grants and the vault database.",
          "Cloudflare — hosts the KeySprig Worker and static website.",
          "AgentMail — sends transactional email such as confirmation and password-reset messages.",
          "Google — only if you sign in with Google, for that identity login. It does not receive your stored API keys.",
        ],
      },
      {
        heading: "Why we process it",
        body: [
          "Contract: we process your account, keys, policies, agents and grants to provide the vault you asked for.",
          "Legitimate interests: we keep security and audit logs so we can detect abuse, debug failures and show you activity in the dashboard. Those logs do not include secret values.",
        ],
      },
      {
        heading: "How long we keep it",
        body: [
          "We keep your account data and submitted feedback while your account exists. When you delete your account, KeySprig revokes connected agents and deletes your keys, permissions, agents, audit events, feedback and the authentication user. Backups held by our processors may persist for a short time until they rotate.",
          "An invitation claim’s email is cleared when it is used. Expired pending claims are cleared during subsequent invitation activity. Invitation-attempt counters older than one day are likewise removed during subsequent invitation activity, rather than by an immediate scheduled deletion.",
        ],
      },
      {
        heading: "International transfers",
        body: [
          "Our processors may handle data outside the European Economic Area. Where they do, they rely on their own standard contractual clauses or an equivalent transfer tool. Ask privacy@keysprig.xyz if you want the current processor list and transfer terms.",
        ],
      },
      {
        heading: "Your rights",
        body: [
          "If UK or EU data-protection law applies to you, you can ask to access, correct, delete, restrict or export your data, or object to processing that relies on legitimate interests. You can also complain to a supervisory authority, such as the Hellenic Data Protection Authority (dpa.gr).",
          "The practical way to delete everything KeySprig holds is the Delete account control in Settings after you sign in. You can also email privacy@keysprig.xyz.",
        ],
      },
    ],
  },
  terms: {
    title: "Terms of Use",
    updated: "10 October 2026",
    sections: [
      {
        heading: "The service",
        body: [
          "KeySprig is a hosted vault. You store named API keys and let approved AI clients call allowed HTTPS destinations through one MCP tool. The service injects the secret into those requests. It does not make the keys visible to the client.",
          "The service is provided as-is, without warranties. It may change, break or stop. Do not rely on it as your only copy of a credential.",
        ],
      },
      {
        heading: "Your keys, your responsibility",
        body: [
          "You are responsible for every key you store and for restricting that key at its provider (scopes, spend caps, allowed operations). KeySprig host, method and rate rules are an extra boundary, not a replacement for provider permissions.",
          "Only store keys you are allowed to use. Do not put secrets into an AI chat. Review each agent grant before you approve it.",
        ],
      },
      {
        heading: "Acceptable use",
        body: [
          "Do not use KeySprig to attack systems, bypass access controls, send unlawful content, or hide activity you are not permitted to perform. Do not try to extract other people’s keys or interfere with the service.",
        ],
      },
      {
        heading: "Termination",
        body: [
          "You can delete your account at any time from Settings. We may suspend or delete an account that breaks these terms or presents a security risk. Deletion removes your vault data from the live service as described in the Privacy Policy.",
        ],
      },
      {
        heading: "Contact",
        body: ["Questions: privacy@keysprig.xyz."],
      },
    ],
  },
  cookies: {
    title: "Cookies & browser storage",
    updated: "11 October 2026",
    sections: [
      {
        heading: "No advertising or analytics",
        body: [
          "KeySprig does not set cookies and does not use analytics, advertising or social-tracking pixels. Our storage notice explains the necessary browser storage used by the service. Its acknowledgement is not consent to tracking.",
        ],
      },
      {
        heading: "Strictly necessary storage",
        body: [
          "The signed-in app keeps a Supabase session in your browser's localStorage so you stay signed in on this device. During sign-in, Supabase also stores a short-lived PKCE verifier in localStorage so the login can finish securely. These values are needed for the account to work. Signing out clears the session.",
          "KeySprig also stores keysprig-storage-notice-v1 in localStorage when you dismiss the storage notice, so it does not reappear on every visit. This preference stays on this device until you clear browser storage. Privacy and storage information remains available on the Privacy and Cookies pages. If browser storage is unavailable, the notice still works but may reappear on your next visit.",
          "The website does not use this storage for advertising or cross-site tracking.",
        ],
      },
    ],
  },
} as const;

export type LegalSlug = keyof typeof pages;

export function isLegalPath(pathname: string): pathname is `/${LegalSlug}` {
  const path = pathname.replace(/\/$/, "") || "/";
  return path === "/privacy" || path === "/terms" || path === "/cookies";
}

export function legalSlug(pathname: string): LegalSlug | null {
  const path = pathname.replace(/\/$/, "") || "/";
  return path === "/privacy" || path === "/terms" || path === "/cookies"
    ? (path.slice(1) as LegalSlug)
    : null;
}

export function LegalLinks({ className = "" }: { className?: string }) {
  return (
    <nav className={className || "legal-links"} aria-label="Legal">
      <a href="/privacy">Privacy</a>
      <a href="/terms">Terms</a>
      <a href="/cookies">Cookies</a>
    </nav>
  );
}

export default function Legal({ page }: { page: LegalSlug }) {
  const content = pages[page];
  return (
    <div className="sprig-landing legal-page">
      <header className="sprig-header">
        <a href="/" aria-label="KeySprig home">
          <img
            src="/keysprig-logo.svg"
            alt="KeySprig"
            width="760"
            height="200"
          />
        </a>
        <LegalLinks />
      </header>
      <main className="legal-article">
        <p className="eyebrow">KEYSPRIG</p>
        <h1>{content.title}</h1>
        <p className="muted">Last updated {content.updated}.</p>
        {content.sections.map((section) => (
          <section key={section.heading}>
            <h2>{section.heading}</h2>
            {section.body.map((paragraph) => (
              <p key={paragraph}>{paragraph}</p>
            ))}
            {"list" in section && section.list && (
              <ul>
                {section.list.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            )}
          </section>
        ))}
      </main>
      <footer className="sprig-footer">
        <LegalLinks />
        <div className="sprig-footer-details">
          <span>
            Created by the <a href="https://aislop.gr/">aislop.gr</a> team and
            GPT.
          </span>
        </div>
      </footer>
    </div>
  );
}
