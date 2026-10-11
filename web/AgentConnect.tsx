import { useState } from "react";
import { LegalLinks } from "./Legal";

export const agentPrompt = `First check your actual capabilities and tell me your limitation: (1) you can configure and use remote MCP with OAuth here; (2) you can use it but I must add the connection in client settings; (3) this environment does not support it; or (4) you cannot verify support. Base this on available tools and current client documentation, not assumptions. Explain my next step in plain language. If unsupported, stop and say so; if uncertain, say what you need to verify. Do not pretend these instructions alone installed anything.

Connect to KeySprig, my private API key vault, using the remote MCP server https://keysprig.xyz/mcp with OAuth sign-in. If you can configure MCP connections, add it as keysprig; otherwise give me the verified steps for this client. Never ask me to paste a secret in chat or configure a GitHub token.

After I sign in and approve the connection, verify that setup_key and call_api are available. I can connect with no saved keys. If either tool is missing, refresh the connection and tool list; do not guess URLs or use the retired workers.dev address.

When I say "Add my AgentMail API key", call setup_key with provider agentmail and show its secure setup_url. I will open it, paste the key privately, and approve access. Never collect the key through tool arguments or chat. If I do not name a service, ask which service first. Automatic setup currently supports AgentMail; for other providers explain that private dashboard setup is required.

Use call_api with key_name agentmail for my approved requests. KeySprig attaches the secret server-side. Respect allowed hosts, methods, rate limits and expiry. Do not claim the connection or key is ready until verified. For sending email or other changes, follow my actual request; never send a message just to test the connection.

For clients that support skills, the KeySprig skill is at https://keysprig.xyz/skills/keysprig/SKILL.md. Install it only if your environment supports that and I authorize installation.`;

export default function AgentConnect() {
  const [status, setStatus] = useState("");
  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setStatus("Copied. Paste it into your agent’s chat.");
    } catch {
      setStatus(
        "Copy is unavailable in this browser. Select and copy the text below.",
      );
    }
  }
  return (
    <div className="auth-layout">
      <a className="brand auth-brand" href="/">
        <img src="/keysprig-icon.svg" alt="" width="36" height="30" /> KeySprig
      </a>
      <main className="auth-card connect-guide">
        <p className="eyebrow">CONNECT ONCE · USE FROM YOUR CHAT</p>
        <h1>Connect your agent</h1>
        <ol>
          <li>Copy the instructions below into your agent’s chat.</li>
          <li>
            Add the connection in your client if asked, then sign in to KeySprig
            and approve it. No saved keys are required.
          </li>
          <li>
            Say “Add my AgentMail API key.” Open the private link, paste the key
            and approve access.
          </li>
        </ol>
        <p>
          On later visits, ask your agent to use AgentMail. Access lasts until
          its expiry or until you revoke it. Your key stays in KeySprig.
        </p>
        <div className="form-actions">
          <button className="primary" onClick={() => copy(agentPrompt)}>
            Copy instructions for my agent
          </button>
          <a href="/skills/keysprig/SKILL.md" download="SKILL.md">
            Download agent skill
          </a>
        </div>
        {status && <p role="status">{status}</p>}
        <details>
          <summary>View the instructions</summary>
          <textarea
            className="agent-instructions"
            readOnly
            value={agentPrompt}
            aria-label="Instructions for your agent"
          />
        </details>
        <section className="settings-panel">
          <h2>If your client asks for connection details</h2>
          <p>Remote MCP server</p>
          <code>https://keysprig.xyz/mcp</code>
          <p>
            Authentication: sign in with OAuth. No pasted access token is
            needed.
          </p>
          <button
            className="secondary"
            onClick={() => copy("https://keysprig.xyz/mcp")}
          >
            Copy MCP address
          </button>
          <p>
            Your client must support remote MCP with OAuth. Instructions and
            skills help your agent use the connection; they do not give an
            unsupported client MCP capabilities.
          </p>
        </section>
        <p>
          <a href="/app">Back to my vault</a>
        </p>
        <LegalLinks />
      </main>
    </div>
  );
}
