import { useState } from "react";
import { supabase } from "./supabase";

// The single-use email credential stays in the URL fragment, which is never
// sent in HTTP requests. Verification requires a click so link scanners do not
// consume the credential by merely opening this page.
export default function Confirm() {
  const [details] = useState(() => {
    const params = new URLSearchParams(window.location.hash.slice(1));
    return { token: params.get("token_hash"), type: params.get("type") };
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const valid =
    Boolean(details.token) &&
    (details.type === "recovery" || details.type === "email");
  async function confirm() {
    if (!supabase || !valid || busy) return;
    setBusy(true);
    // Remove the credential from browser history before exchanging it.
    window.history.replaceState({}, "", "/auth/confirm");
    try {
      const { error } = await supabase.auth.verifyOtp({
        token_hash: details.token!,
        type: details.type as "recovery" | "email",
      });
      if (error) throw error;
      window.location.replace(
        details.type === "recovery" ? "/?recovery=1" : "/app",
      );
    } catch {
      setError(
        "This link has expired or has already been used. Request a new email and open its newest link.",
      );
      setBusy(false);
    }
  }
  return (
    <div className="auth-layout">
      <a className="brand auth-brand" href="/">
        <img src="/keysprig-icon.svg" alt="" width="36" height="30" /> KeySprig
      </a>
      <main className="auth-card">
        <h1>
          {details.type === "recovery"
            ? "Reset your password"
            : "Confirm your email"}
        </h1>
        <p>
          {details.type === "recovery"
            ? "Continue to choose a new password for your KeySprig account."
            : "Continue to confirm your email address and open your account."}
        </p>
        {valid && !error && (
          <button className="primary full" disabled={busy} onClick={confirm}>
            {busy ? "Verifying…" : "Continue"}
          </button>
        )}
        {(!valid || error) && (
          <p className="alert" role="alert">
            {error || "This link is incomplete. Request a new email."}
          </p>
        )}
        <p>
          <a href="/app">Back to sign in</a>
        </p>
      </main>
    </div>
  );
}
