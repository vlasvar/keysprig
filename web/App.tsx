import { useEffect, useState } from "react";
import { supabase, googleEnabled } from "./supabase";
import Consent from "./Consent";
import Permissions from "./Permissions";
import { LegalLinks } from "./Legal";
import Feedback from "./Feedback";
import Invitations from "./Invitations";
import KeySetup, { setupIntent } from "./KeySetup";
import { agentPrompt } from "./AgentConnect";

export type Key = {
  id: string;
  name: string;
  created_at: string;
  allowed_hosts: string[];
  auth_header: string;
  auth_prefix: string;
  allowed_methods?: string[];
  rate_limit_per_minute: number;
};
type Agent = { id: string; label: string; created_at: string };
type Event = {
  id?: string;
  action?: string;
  label?: string;
  created_at?: string;
};
type Page = "Keys" | "Agents" | "Activity" | "Feedback" | "Settings";
const icons: Record<Page, string> = {
  Keys: "⌘",
  Agents: "◈",
  Activity: "◷",
  Settings: "⚙",
  Feedback: "✎",
};

export default function App() {
  const [keySetupIntent] = useState(setupIntent);
  const authorizationId = new URLSearchParams(window.location.search).get(
    "authorization_id",
  );
  const authReturnUrl =
    keySetupIntent !== null
      ? `${window.location.origin}/setup-key`
      : authorizationId
        ? `${window.location.origin}${window.location.pathname}?authorization_id=${encodeURIComponent(authorizationId)}`
        : `${window.location.origin}/app`;
  const [session, setSession] = useState<any>(null);
  const [checking, setChecking] = useState(Boolean(supabase));
  const [page, setPage] = useState<Page>("Keys");
  const [keys, setKeys] = useState<Key[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [events, setEvents] = useState<Event[]>([]);
  const [search, setSearch] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(false);
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");
  const [value, setValue] = useState("");
  const [hosts, setHosts] = useState("");
  const [authHeader, setAuthHeader] = useState("Authorization");
  const [authPrefix, setAuthPrefix] = useState("Bearer ");
  const [methods, setMethods] = useState("GET");
  const [rate, setRate] = useState(60);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [invitation, setInvitation] = useState("");
  const [signup, setSignup] = useState(
    new URLSearchParams(window.location.search).get("signup") === "1",
  );
  const [emailForm, setEmailForm] = useState(
    new URLSearchParams(window.location.search).get("signup") === "1",
  );
  const [recovery, setRecovery] = useState(
    new URLSearchParams(window.location.search).get("recovery") === "1",
  );
  const [newPassword, setNewPassword] = useState("");
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [deleteTyped, setDeleteTyped] = useState("");

  useEffect(() => {
    if (!supabase) return;
    supabase.auth.getSession().then(({ data, error }) => {
      setSession(data.session);
      setChecking(false);
      if (error) setError(error.message);
    });
    const { data } = supabase.auth.onAuthStateChange((event, next) => {
      setSession(next);
      setPassword("");
      setValue("");
      if (event === "PASSWORD_RECOVERY") setRecovery(true);
    });
    return () => data.subscription.unsubscribe();
  }, []);

  async function api(path: string, init?: RequestInit) {
    const { data } = await supabase!.auth.getSession();
    if (!data.session) throw new Error("Please sign in again.");
    const response = await fetch(path, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${data.session.access_token}`,
        ...init?.headers,
      },
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok)
      throw new Error(body.error || "Request failed. Please try again.");
    return body;
  }
  async function refresh() {
    if (
      !session ||
      page === "Settings" ||
      page === "Feedback" ||
      keySetupIntent !== null ||
      authorizationId
    )
      return;
    setLoading(true);
    setError("");
    try {
      if (page === "Keys") setKeys((await api("/api/keys")).keys || []);
      if (page === "Agents") {
        const [agentData, keyData] = await Promise.all([
          api("/api/agents"),
          api("/api/keys"),
        ]);
        setAgents(agentData.agents || []);
        setKeys(keyData.keys || []);
      }
      if (page === "Activity")
        setEvents((await api("/api/activity")).events || []);
    } catch (e) {
      setError(message(e));
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    setSearch("");
    setNotice("");
    setError("");
    void refresh();
  }, [session, page]);
  async function authenticate(e: React.FormEvent) {
    e.preventDefault();
    if (!supabase) return;
    setBusy(true);
    setError("");
    setNotice("");
    const result = await supabase.auth.signInWithPassword({ email, password });
    setPassword("");
    setBusy(false);
    if (result.error) setError(result.error.message);
    else if (signup && !result.data.session)
      setNotice("Check your email to confirm your account, then sign in.");
  }
  async function google() {
    if (!supabase) return;
    setBusy(true);
    setError("");
    if (signup) {
      try {
        const response = await fetch("/api/invitations/redeem", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            code: invitation.trim(),
            email: email.trim(),
          }),
        });
        const result = await response.json();
        if (!response.ok)
          throw Error(result.error || "Invitation could not be verified.");
        setInvitation("");
      } catch (e) {
        setError(message(e));
        setBusy(false);
        return;
      }
    }
    const { error } = await supabase.auth.signInWithOAuth({
      provider: "google",
      options: {
        redirectTo: authReturnUrl,
        queryParams: signup
          ? { login_hint: email.trim(), prompt: "select_account" }
          : undefined,
      },
    });
    if (error) {
      setError(error.message);
      setBusy(false);
    }
  }
  async function requestRecovery() {
    if (!supabase || !email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setError("Enter your email address first.");
      return;
    }
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const { error } = await supabase.auth.resetPasswordForEmail(email, {
        redirectTo: `${window.location.origin}/?recovery=1`,
      });
      if (error) throw error;
      setNotice(
        "If an account exists for this email, you will receive a password reset link.",
      );
    } catch (e) {
      setError(message(e));
    } finally {
      setBusy(false);
    }
  }
  async function updatePassword(e: React.FormEvent) {
    e.preventDefault();
    if (!supabase) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await api("/api/agents/disconnect-all", { method: "POST" });
      const { error } = await supabase.auth.updateUser({
        password: newPassword,
      });
      if (error) throw error;
      setNewPassword("");
      setRecovery(false);
      window.history.replaceState({}, "", "/app");
      setNotice("Password updated. AI clients have been disconnected.");
    } catch (e) {
      setError(message(e));
    } finally {
      setBusy(false);
    }
  }
  async function addKey(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    const submittedValue = value;
    setValue("");
    try {
      await api("/api/keys", {
        method: "POST",
        body: JSON.stringify({
          name: name.trim(),
          value: submittedValue,
          allowed_hosts: hosts
            .split(",")
            .map((h) => h.trim())
            .filter(Boolean),
          auth_header: authHeader,
          auth_prefix: authPrefix,
          allowed_methods: methods
            .split(",")
            .map((m) => m.trim().toUpperCase())
            .filter(Boolean),
          rate_limit_per_minute: rate,
        }),
      });
      setAdding(false);
      setName("");
      setNotice("Key saved securely.");
      await refresh();
    } catch (e) {
      setError(`${message(e)} Re-enter the key to try again.`);
    } finally {
      setBusy(false);
    }
  }
  async function remove(kind: "keys" | "agents", id: string, label: string) {
    if (
      !window.confirm(
        kind === "keys"
          ? `Delete “${label}” from your vault?`
          : `Disconnect “${label}”? Future vault access will be blocked.`,
      )
    )
      return;
    setBusy(true);
    setError("");
    try {
      await api(`/api/${kind}/${encodeURIComponent(id)}`, { method: "DELETE" });
      setNotice(kind === "keys" ? "Key deleted." : "Agent disconnected.");
      await refresh();
    } catch (e) {
      setError(message(e));
    } finally {
      setBusy(false);
    }
  }
  async function deleteAccount() {
    if (deleteTyped !== "DELETE") return;
    setBusy(true);
    setError("");
    try {
      await api("/api/account", { method: "DELETE" });
    } catch (e) {
      setError(message(e));
      setBusy(false);
      return;
    }
    try {
      await supabase!.auth.signOut();
    } catch {
      /* The auth user is already gone. */
    }
    window.location.assign("/");
  }
  const alerts = (
    <>
      {error && (
        <div role="alert" className="alert error">
          {error}
        </div>
      )}
      {notice && (
        <div role="status" className="alert">
          {notice}
        </div>
      )}
    </>
  );

  if (!session)
    return (
      <div className="auth-layout">
        <a className="brand auth-brand" href="/">
          <img src="/keysprig-icon.svg" alt="" width="36" height="30" />{" "}
          KeySprig
        </a>
        <main className="auth-card">
          <div className="eyebrow">PRIVATE BETA · YOUR KEYS. YOUR CONTROL.</div>
          <h1>A private home for your AI keys.</h1>
          <p>
            Keep your keys in one place. Connect your AI clients and manage
            their access.
          </p>
          {!supabase ? (
            <div className="alert" role="status">
              Account setup is not configured yet. Sign-in and real key storage
              are unavailable.
            </div>
          ) : checking ? (
            <p role="status">Checking your session…</p>
          ) : (
            <>
              {signup && (
                <div className="auth-form">
                  <p>
                    One invitation, one beta tester. Enter your code and the
                    email of the Google account you will use.
                  </p>
                  <label>
                    Invitation code
                    <input
                      value={invitation}
                      onChange={(e) => setInvitation(e.target.value)}
                      autoComplete="off"
                      maxLength={100}
                    />
                  </label>
                  <label>
                    Google account email
                    <input
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      autoComplete="email"
                      maxLength={254}
                    />
                  </label>
                  <p className="legal-inline">
                    By joining you agree to the <a href="/terms">Terms</a> and
                    acknowledge our <a href="/privacy">Privacy Policy</a>.
                    Choose this same email on Google's next screen.
                  </p>
                </div>
              )}
              <button
                className="primary google"
                onClick={google}
                disabled={
                  busy ||
                  !googleEnabled ||
                  (signup &&
                    (!invitation.trim() ||
                      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)))
                }
              >
                <img src="/google-g.png" alt="" width="20" height="20" />
                {signup ? "Sign up with Google" : "Sign in with Google"}
              </button>
              {!googleEnabled && (
                <p className="muted" role="status">
                  Google sign-in setup is pending.
                </p>
              )}
              {!signup && (
                <button
                  className="secondary full"
                  onClick={() => setEmailForm(!emailForm)}
                  disabled={busy}
                >
                  Sign in with email
                </button>
              )}
              <button
                className="text-button"
                onClick={() => {
                  setSignup(!signup);
                  setEmailForm(false);
                  setError("");
                }}
              >
                {" "}
                {signup
                  ? "Already a tester? Sign in"
                  : "Have an invitation? Join the beta"}
              </button>
              {emailForm && !signup && (
                <form onSubmit={authenticate} className="auth-form">
                  <label>
                    Email
                    <input
                      type="email"
                      autoComplete="email"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                    />
                  </label>
                  <label>
                    Password
                    <input
                      type="password"
                      autoComplete={
                        signup ? "new-password" : "current-password"
                      }
                      minLength={12}
                      required
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                    />
                  </label>
                  <button className="primary" disabled={busy}>
                    {busy
                      ? "Please wait…"
                      : signup
                        ? "Create account"
                        : "Sign in"}
                  </button>
                  {!signup && (
                    <button
                      type="button"
                      className="text-button"
                      disabled={busy}
                      onClick={requestRecovery}
                    >
                      Forgot password?
                    </button>
                  )}
                  <button
                    type="button"
                    className="text-button"
                    onClick={() => {
                      setSignup(true);
                      setEmailForm(false);
                    }}
                  >
                    {signup
                      ? "Already have an account? Sign in"
                      : "New here? Create an account"}
                  </button>
                  {signup && (
                    <p className="legal-inline">
                      By creating an account you agree to the{" "}
                      <a href="/terms">Terms of Use</a> and{" "}
                      <a href="/privacy">Privacy Policy</a>. See{" "}
                      <a href="/cookies">Cookies</a>.
                    </p>
                  )}
                </form>
              )}
            </>
          )}
          {alerts}
          <div className="auth-footnote">
            Enter secrets only in your private vault, never in an AI chat.
            <LegalLinks />
          </div>
        </main>
      </div>
    );

  if (recovery)
    return (
      <div className="auth-layout">
        <a className="brand auth-brand" href="/">
          <img src="/keysprig-icon.svg" alt="" width="36" height="30" />{" "}
          KeySprig
        </a>
        <main className="auth-card">
          <h1>Choose a new password</h1>
          <p>Use at least 12 characters for your vault account.</p>
          {alerts}
          <form className="auth-form" onSubmit={updatePassword}>
            <label>
              New password
              <input
                type="password"
                minLength={12}
                autoComplete="new-password"
                required
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
              />
            </label>
            <button className="primary" disabled={busy}>
              {busy ? "Updating…" : "Update password"}
            </button>
          </form>
        </main>
      </div>
    );

  if (authorizationId) return <Consent authorizationId={authorizationId} />;
  if (keySetupIntent !== null)
    return <KeySetup setup={keySetupIntent} api={api} />;

  return (
    <div className="shell">
      <aside className="sidebar">
        <a className="brand" href="/">
          <img src="/keysprig-icon.svg" alt="" width="36" height="30" />{" "}
          KeySprig
        </a>
        <div className="workspace">
          <span className="avatar">
            {session.user.email?.slice(0, 1).toUpperCase() || "K"}
          </span>
          <div>
            <strong>Personal vault</strong>
            <small>Your private workspace</small>
          </div>
        </div>
        <nav aria-label="Main navigation">
          {(
            ["Keys", "Agents", "Activity", "Feedback", "Settings"] as Page[]
          ).map((item) => (
            <button
              key={item}
              className={page === item ? "nav-item active" : "nav-item"}
              onClick={() => {
                setPage(item);
                setAdding(false);
                setValue("");
              }}
            >
              <span>{icons[item]}</span>
              {item}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="security-note">
            <span>◈</span> Encrypted key storage
          </div>
          <div className="account">
            <span className="avatar small">
              {session.user.email?.slice(0, 1).toUpperCase() || "K"}
            </span>
            <span className="account-email">{session.user.email}</span>
            <button
              className="icon-button"
              aria-label="Sign out"
              onClick={() => supabase!.auth.signOut()}
            >
              ↪
            </button>
          </div>
        </div>
      </aside>
      <div className="main-area">
        <header className="topbar">
          <span className="sidebar-symbol">◫</span>
          <span>Dashboard</span>
          <span className="crumb">›</span>
          <strong>{page}</strong>
          <span className="topbar-end">Private beta</span>
        </header>
        <main className="content">
          <section className="page-heading">
            <div>
              <div className="eyebrow">{icons[page]} PERSONAL VAULT</div>
              <h1>{page}</h1>
              <p>
                {page === "Keys"
                  ? "Your API keys, kept private and ready for approved use."
                  : page === "Agents"
                    ? "Manage the AI clients connected to your vault."
                    : page === "Activity"
                      ? "A record of changes and access to your vault."
                      : page === "Feedback"
                        ? "Help shape KeySprig during the private beta."
                        : "Your account and connection details."}
              </p>
            </div>
            {page === "Keys" && (
              <button
                className="primary"
                onClick={() => {
                  setAdding(true);
                  setError("");
                }}
                disabled={busy}
              >
                ＋ Add key
              </button>
            )}
          </section>
          {alerts}
          {adding && (
            <section className="form-panel">
              <h2>Add a key</h2>
              <p className="muted">
                Choose a name your AI can recognise. The key value is never
                shown in this list.
              </p>
              <form onSubmit={addKey}>
                <label>
                  Name
                  <input
                    autoFocus
                    maxLength={40}
                    pattern="[a-z][a-z0-9_\-]{0,39}"
                    required
                    placeholder="provider_key"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                  />
                  <span className="muted">
                    Lowercase letters, numbers, underscores or hyphens.
                  </span>
                </label>
                <label>
                  Key value
                  <input
                    type="password"
                    autoComplete="off"
                    required
                    value={value}
                    onChange={(e) => setValue(e.target.value)}
                    placeholder="Paste your key privately"
                  />
                </label>
                <label>
                  Allowed API hosts
                  <input
                    required
                    value={hosts}
                    onChange={(e) => setHosts(e.target.value)}
                    placeholder="api.example.com, api.other.com"
                  />
                  <span className="muted">
                    Exact hostnames, comma separated. HTTPS only; no wildcards
                    or private network destinations.
                  </span>
                </label>
                <label>
                  Authentication header
                  <input
                    required
                    value={authHeader}
                    onChange={(e) => setAuthHeader(e.target.value)}
                    placeholder="Authorization"
                  />
                </label>
                <label>
                  Authentication prefix
                  <input
                    value={authPrefix}
                    onChange={(e) => setAuthPrefix(e.target.value)}
                    placeholder="Bearer "
                  />
                  <span className="muted">
                    Include a trailing space for Bearer. Leave blank for headers
                    such as x-api-key.
                  </span>
                </label>
                <label>
                  Allowed HTTP methods
                  <input
                    required
                    value={methods}
                    onChange={(e) => setMethods(e.target.value)}
                    placeholder="GET, POST"
                  />
                </label>
                <label>
                  Requests per minute
                  <input
                    type="number"
                    min={1}
                    max={1000}
                    required
                    value={rate}
                    onChange={(e) => setRate(Number(e.target.value))}
                  />
                </label>
                <div className="form-actions">
                  <button
                    type="button"
                    className="secondary"
                    onClick={() => {
                      setAdding(false);
                      setValue("");
                      setName("");
                    }}
                    disabled={busy}
                  >
                    Cancel
                  </button>
                  <button className="primary" disabled={busy}>
                    {busy ? "Saving…" : "Save key"}
                  </button>
                </div>
              </form>
            </section>
          )}
          {(page === "Keys" || page === "Agents") && (
            <>
              <div className="toolbar">
                <span className="search-symbol">⌕</span>
                <input
                  aria-label={`Search ${page.toLowerCase()}`}
                  placeholder={`Search your ${page.toLowerCase()} by name`}
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
                <button
                  className="secondary"
                  onClick={refresh}
                  disabled={loading || busy}
                >
                  Refresh
                </button>
              </div>
              <section className="list-panel" aria-busy={loading}>
                <div className="list-caption">
                  <span>
                    {page === "Keys" ? "SAVED KEYS" : "CONNECTED AGENTS"}
                  </span>
                  <span>
                    {page === "Keys" ? keys.length : agents.length} total
                  </span>
                </div>
                {loading ? (
                  <div className="empty" role="status">
                    Loading {page.toLowerCase()}…
                  </div>
                ) : page === "Keys" ? (
                  keys
                    .filter((k) =>
                      k.name.toLowerCase().includes(search.toLowerCase()),
                    )
                    .map((k) => (
                      <div className="list-row" key={k.id}>
                        <span className="row-icon">⌘</span>
                        <div className="row-copy">
                          <strong>{k.name}</strong>
                          <small>
                            Added {date(k.created_at)} · Value hidden
                            <br />
                            Hosts:{" "}
                            {(k.allowed_hosts || []).join(", ") ||
                              "No proxy hosts configured"}
                            <br />
                            {k.auth_header} ·{" "}
                            {k.allowed_methods?.join(", ") ||
                              "No methods allowed"}{" "}
                            · {k.rate_limit_per_minute} requests/minute
                          </small>
                        </div>
                        <button
                          className="text-button danger"
                          disabled={busy}
                          onClick={() => remove("keys", k.id, k.name)}
                        >
                          Delete
                        </button>
                      </div>
                    ))
                ) : (
                  agents
                    .filter((a) =>
                      a.label.toLowerCase().includes(search.toLowerCase()),
                    )
                    .map((a) => (
                      <div className="list-row" key={a.id}>
                        <span className="row-icon">◈</span>
                        <div className="row-copy">
                          <strong>{a.label}</strong>
                          <small>Connected {date(a.created_at)}</small>
                        </div>
                        <button
                          className="secondary"
                          disabled={busy}
                          onClick={() => remove("agents", a.id, a.label)}
                        >
                          Disconnect
                        </button>
                      </div>
                    ))
                )}
                {!loading &&
                  !error &&
                  !(page === "Keys"
                    ? keys.some((k) =>
                        k.name.toLowerCase().includes(search.toLowerCase()),
                      )
                    : agents.some((a) =>
                        a.label.toLowerCase().includes(search.toLowerCase()),
                      )) && (
                    <div className="empty">
                      <span className="empty-icon">{icons[page]}</span>
                      <h2>
                        {search
                          ? "No matches"
                          : page === "Keys"
                            ? "Your vault starts here"
                            : "No connected agents yet"}
                      </h2>
                      <p>
                        {search
                          ? "Try a different name."
                          : page === "Keys"
                            ? "Add your first named key using the button above."
                            : "Add the MCP connection URL in a supported AI client, then sign in and approve access."}
                      </p>
                    </div>
                  )}
              </section>
              {page === "Agents" && (
                <Permissions agents={agents} keys={keys} api={api} />
              )}
              {page === "Agents" && (
                <section className="connection-panel">
                  <h2>Connect an AI client</h2>
                  <p>
                    Connect your agent once, even with an empty vault. Then ask
                    it to add your AgentMail API key. You paste it privately and
                    approve access from the setup link.
                  </p>
                  <p>
                    Use this MCP server URL in a compatible client. Client
                    support must be validated before relying on it.
                  </p>
                  <code>{window.location.origin}/mcp</code>
                  <div className="form-actions">
                    <button
                      className="primary"
                      onClick={async () => {
                        try {
                          await navigator.clipboard.writeText(agentPrompt);
                          setNotice(
                            "Copied. Paste the instructions into your agent’s chat.",
                          );
                        } catch {
                          setError(
                            "Copy unavailable. Open the connection guide to copy the instructions manually.",
                          );
                        }
                      }}
                    >
                      Copy instructions for my agent
                    </button>
                    <a href="/connect">Connection guide and skill</a>
                  </div>
                  <p className="muted">
                    Disconnecting blocks future vault access. It does not undo
                    requests already sent or revoke the key at its provider.
                  </p>
                </section>
              )}
            </>
          )}
          {page === "Activity" && (
            <section className="list-panel">
              <div className="list-caption">
                RECENT ACTIVITY
                <button
                  className="text-button"
                  onClick={refresh}
                  disabled={loading}
                >
                  Refresh
                </button>
              </div>
              {loading ? (
                <div className="empty">Loading activity…</div>
              ) : events.length ? (
                events.map((event, index) => (
                  <div className="list-row" key={event.id || index}>
                    <span className="row-icon">◷</span>
                    <div className="row-copy">
                      <strong>
                        {event.label || event.action || "Vault event"}
                      </strong>
                      <small>{date(event.created_at)}</small>
                    </div>
                  </div>
                ))
              ) : (
                <div className="empty">
                  <h2>No activity yet</h2>
                  <p>Vault events will appear here as you use your account.</p>
                </div>
              )}
            </section>
          )}
          {page === "Feedback" && <Feedback api={api} />}
          {page === "Settings" && (
            <section className="settings-panel">
              <Invitations api={api} />
              <h2>Account</h2>
              <LegalLinks />
              <div className="setting-row">
                <span>Email</span>
                <strong>{session.user.email}</strong>
              </div>
              <div className="setting-row">
                <span>Workspace</span>
                <strong>Personal vault</strong>
              </div>
              <h2>Controlled API requests</h2>
              <p>
                Clients can send HTTPS requests through KeySprig using only
                approved keys, allowed hosts and methods, within the configured
                rate limit. Permissions expire within 30 days. API responses may
                contain sensitive provider data; choose your grants carefully.
              </p>
              <h2>How your keys are stored</h2>
              <p>
                Keys are encrypted before storage. The service can decrypt them
                for authorised operations. This is hosted storage, not a
                zero-knowledge vault.
              </p>
              <button
                className="secondary"
                onClick={() => supabase!.auth.signOut()}
              >
                Sign out
              </button>
              <h2>Delete account</h2>
              <p>
                Permanently delete your KeySprig account, stored keys, connected
                agents, permissions and activity. This cannot be undone.
              </p>
              {!confirmingDelete ? (
                <button
                  className="secondary danger"
                  disabled={busy}
                  onClick={() => {
                    setConfirmingDelete(true);
                    setDeleteTyped("");
                    setError("");
                  }}
                >
                  Delete account
                </button>
              ) : (
                <div className="delete-confirm">
                  <p role="alert">
                    Type DELETE to confirm you want to erase this account.
                  </p>
                  <label>
                    Confirmation
                    <input
                      autoComplete="off"
                      value={deleteTyped}
                      onChange={(e) => setDeleteTyped(e.target.value)}
                      placeholder="DELETE"
                    />
                  </label>
                  <div className="form-actions">
                    <button
                      type="button"
                      className="secondary"
                      disabled={busy}
                      onClick={() => {
                        setConfirmingDelete(false);
                        setDeleteTyped("");
                      }}
                    >
                      Cancel
                    </button>
                    <button
                      type="button"
                      className="primary danger"
                      disabled={busy || deleteTyped !== "DELETE"}
                      onClick={deleteAccount}
                    >
                      {busy ? "Deleting…" : "Delete my account permanently"}
                    </button>
                  </div>
                </div>
              )}
            </section>
          )}
        </main>
      </div>
    </div>
  );
}
function message(e: unknown) {
  return e instanceof Error
    ? e.message
    : "Something went wrong. Please try again.";
}
function date(value?: string) {
  if (!value) return "Date unavailable";
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf())
    ? "Date unavailable"
    : parsed.toLocaleDateString(undefined, {
        day: "numeric",
        month: "short",
        year: "numeric",
      });
}
