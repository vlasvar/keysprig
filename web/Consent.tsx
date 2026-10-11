import { useEffect, useState } from "react";
import type {
  OAuthAuthorizationDetails,
  OAuthRedirect,
} from "@supabase/supabase-js";
import { supabase } from "./supabase";
import type { Key } from "./App";

export default function Consent({
  authorizationId,
}: {
  authorizationId: string;
}) {
  const [details, setDetails] = useState<
    OAuthAuthorizationDetails | OAuthRedirect | null
  >(null);
  const [keys, setKeys] = useState<Key[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [days, setDays] = useState(7);
  const [loadingKeys, setLoadingKeys] = useState(true);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const { data } = await supabase!.auth.getSession();
        if (!data.session) throw new Error("Please sign in again.");
        const response = await fetch("/api/keys", {
          headers: { Authorization: `Bearer ${data.session.access_token}` },
        });
        if (!response.ok) throw new Error("Unable to load your keys.");
        const body = await response.json();
        if (active) setKeys(body.keys || []);
      } catch (e) {
        if (active)
          setError(e instanceof Error ? e.message : "Unable to load keys.");
      } finally {
        if (active) setLoadingKeys(false);
      }
    })();
    supabase!.auth.oauth
      .getAuthorizationDetails(authorizationId)
      .then(({ data, error }) => {
        if (!active) return;
        if (error) setError(error.message);
        else setDetails(data);
      })
      .catch(() => {
        if (active) setError("Unable to load this connection request.");
      });
    return () => {
      active = false;
    };
  }, [authorizationId]);
  async function decide(approve: boolean) {
    if (!details || !supabase) return;
    setBusy(true);
    setError("");
    try {
      if (!("authorization_id" in details)) {
        if (!approve) {
          window.location.assign("/");
          return;
        }
        const destination = new URL(details.redirect_url);
        if (
          !["https:", "http:"].includes(destination.protocol) ||
          (destination.protocol === "http:" &&
            !["localhost", "127.0.0.1", "[::1]"].includes(destination.hostname))
        )
          throw new Error(
            "Unsupported client redirect. Please reconnect from your AI client.",
          );
        window.location.assign(destination.href);
        return;
      }
      if (approve) {
        const { data } = await supabase.auth.getSession();
        if (!data.session) throw new Error("Please sign in again.");
        const response = await fetch("/api/consent", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${data.session.access_token}`,
          },
          body: JSON.stringify({
            authorization_id: authorizationId,
            key_ids: selected,
            expires_at: new Date(Date.now() + days * 86400000).toISOString(),
          }),
        });
        if (!response.ok) {
          const body = await response.json().catch(() => ({}));
          throw new Error(
            body.error || "Vault permission could not be recorded.",
          );
        }
      }
      const result = approve
        ? await supabase.auth.oauth.approveAuthorization(authorizationId)
        : await supabase.auth.oauth.denyAuthorization(authorizationId);
      if (result.error) throw result.error;
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "Connection request failed. Please retry.",
      );
      setBusy(false);
    }
  }
  const fullDetails = details && "authorization_id" in details ? details : null;
  return (
    <div className="auth-layout">
      <a className="brand auth-brand" href="/">
        <img src="/keysprig-icon.svg" alt="" width="36" height="30" /> KeySprig
      </a>
      <main className="auth-card">
        <div className="eyebrow">AI CLIENT CONNECTION</div>
        <h1>Connect to your vault?</h1>
        {error && (
          <div role="alert" className="alert error">
            {error}
          </div>
        )}
        {!details && !error && <p role="status">Loading connection request…</p>}
        {details && (
          <>
            <p>
              {fullDetails
                ? "Review this client before approving access."
                : "You previously approved this OAuth connection. Continue back to your client. Vault access still requires an active vault permission."}
            </p>
            {fullDetails && (
              <section className="settings-panel">
                <h2>Client details</h2>
                <p>
                  <strong>{fullDetails.client.name || "Unnamed client"}</strong>
                </p>
                <label>
                  Registered return address
                  <code style={{ overflowWrap: "anywhere" }}>
                    {fullDetails.redirect_uri}
                  </code>
                </label>
                <p className="muted">
                  Client names are supplied by the client and are not proof of
                  identity.
                </p>
                <label>
                  Requested OAuth scopes
                  <code style={{ overflowWrap: "anywhere" }}>
                    {fullDetails.scope || "No scopes listed"}
                  </code>
                </label>
              </section>
            )}
            <section className="settings-panel">
              <h2>Access you are approving</h2>
              <p>
                This client can use only the keys you select below, within each
                key's host, method and rate policy. You can connect without
                selecting any keys, then add a key from your chat and approve it
                separately. New keys are never shared automatically.
              </p>
              <p>
                Raw key values are not returned through MCP. The hosted service
                can decrypt keys for approved operations.
              </p>
              <p>
                You can disconnect this client from Agents. That blocks future
                vault access; it does not undo provider operations or revoke
                credentials outside the vault.
              </p>
            </section>
            {fullDetails && (
              <section className="settings-panel">
                <h2>Choose keys to approve</h2>
                {loadingKeys ? (
                  <p role="status">Loading keys…</p>
                ) : keys.length ? (
                  keys.map((key) => (
                    <label className="permission-choice" key={key.id}>
                      <input
                        type="checkbox"
                        checked={selected.includes(key.id)}
                        onChange={(e) =>
                          setSelected(
                            e.target.checked
                              ? [...selected, key.id]
                              : selected.filter((id) => id !== key.id),
                          )
                        }
                      />
                      <span>
                        {key.name}
                        <small>
                          {key.allowed_hosts?.join(", ")} ·{" "}
                          {key.allowed_methods?.join(", ") ||
                            "No methods allowed"}{" "}
                          · {key.rate_limit_per_minute} requests/minute
                        </small>
                      </span>
                    </label>
                  ))
                ) : (
                  <p>
                    No saved keys yet. Connect now with no key access, then ask
                    your agent to add your AgentMail API key privately.
                  </p>
                )}
                <label>
                  Selected key access expires after (days)
                  <input
                    type="number"
                    min={1}
                    max={30}
                    required
                    value={days}
                    onChange={(e) => setDays(Number(e.target.value))}
                  />
                </label>
              </section>
            )}
            <div className="form-actions">
              <button
                className="secondary"
                disabled={busy}
                onClick={() => decide(false)}
              >
                Deny
              </button>
              <button
                className="primary"
                disabled={
                  busy ||
                  Boolean(error) ||
                  (Boolean(fullDetails) &&
                    (loadingKeys ||
                      !Number.isInteger(days) ||
                      days < 1 ||
                      days > 30))
                }
                onClick={() => decide(true)}
              >
                {busy
                  ? "Please wait…"
                  : fullDetails
                    ? selected.length
                      ? "Approve connection"
                      : "Connect without key access"
                    : "Continue to client"}
              </button>
            </div>
          </>
        )}
      </main>
    </div>
  );
}
