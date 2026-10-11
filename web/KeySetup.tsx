import { useEffect, useState } from "react";
import { LegalLinks } from "./Legal";

export function setupIntent() {
  if (window.location.pathname !== "/setup-key") return null;
  const fragment = window.location.hash.slice(1);
  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(fragment)) {
    sessionStorage.setItem("keysprig.setup", fragment);
    history.replaceState(
      null,
      "",
      window.location.pathname + window.location.search,
    );
  }
  return sessionStorage.getItem("keysprig.setup") || "";
}

export default function KeySetup({
  setup,
  api,
}: {
  setup: string;
  api: (path: string, init?: RequestInit) => Promise<any>;
}) {
  const [details, setDetails] = useState<{
    agent: string;
    host: string;
  } | null>(null);
  const [value, setValue] = useState("");
  const [access, setAccess] = useState("read");
  const [days, setDays] = useState(7);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  useEffect(() => {
    let active = true;
    api("/api/key-setup", {
      method: "POST",
      body: JSON.stringify({ setup, action: "details" }),
    })
      .then((result) => {
        if (active) setDetails(result);
      })
      .catch(() => {
        if (active)
          setError(
            "This link is unavailable. Make sure you signed in with the account connected to your agent, or ask it for a new setup link.",
          );
      });
    return () => {
      active = false;
    };
  }, [setup]);
  async function save(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api("/api/key-setup", {
        method: "POST",
        body: JSON.stringify({ setup, action: "save", value, access, days }),
      });
      setValue("");
      sessionStorage.removeItem("keysprig.setup");
      setSaved(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to save.");
    } finally {
      setValue("");
      setBusy(false);
    }
  }
  return (
    <div className="auth-layout">
      <a className="brand auth-brand" href="/">
        <img src="/keysprig-icon.svg" alt="" width="36" height="30" /> KeySprig
      </a>
      <main className="auth-card">
        <p className="eyebrow">PRIVATE KEY SETUP</p>
        <h1>{saved ? "AgentMail is ready" : "Connect AgentMail"}</h1>
        {saved ? (
          <>
            <p>
              Your key is saved. Return to your chat and ask your agent to use
              AgentMail. It receives results, never your key.
            </p>
            <a href="/app">Manage access</a>
          </>
        ) : (
          <>
            <p>
              Paste your API key privately. We’ve filled in the technical
              settings.
            </p>
            {error && <p role="alert">{error}</p>}
            {!details && !error && <p>Checking your setup link…</p>}
            {details && (
              <form className="auth-form" onSubmit={save}>
                <label>
                  AgentMail API key
                  <input
                    type="password"
                    autoComplete="off"
                    spellCheck={false}
                    required
                    maxLength={16000}
                    value={value}
                    onChange={(e) => setValue(e.target.value)}
                  />
                </label>
                <label>
                  What can this agent do?
                  <select
                    value={access}
                    onChange={(e) => setAccess(e.target.value)}
                  >
                    <option value="read">Read email</option>
                    <option value="send">Read and send email</option>
                  </select>
                </label>
                <label>
                  Allow access for
                  <select
                    value={days}
                    onChange={(e) => setDays(Number(e.target.value))}
                  >
                    <option value={1}>1 day</option>
                    <option value={7}>7 days</option>
                    <option value={30}>30 days</option>
                  </select>
                </label>
                <p>
                  <strong>{details.agent}</strong> will be allowed to use this
                  key at <strong>{details.host}</strong>, up to 10 requests per
                  minute.
                </p>
                {access === "send" && (
                  <p>
                    Read and send also permits other POST operations allowed by
                    your AgentMail key. A restricted provider key gives tighter
                    control.
                  </p>
                )}
                <button className="primary" disabled={busy}>
                  {busy ? "Saving…" : "Save and allow this agent"}
                </button>
                <a
                  href="/app"
                  onClick={() => sessionStorage.removeItem("keysprig.setup")}
                >
                  Cancel
                </a>
              </form>
            )}
          </>
        )}
        <div className="auth-footer">
          <LegalLinks />
        </div>
      </main>
    </div>
  );
}
