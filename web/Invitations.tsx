import { useEffect, useState } from "react";

export default function Invitations({
  api,
}: {
  api: (path: string, init?: RequestInit) => Promise<any>;
}) {
  const [rows, setRows] = useState<any[] | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function load() {
    try {
      setRows((await api("/api/invitations")).invitations);
    } catch {
      setRows(null);
    }
  }
  useEffect(() => {
    void load();
  }, []);
  if (!rows) return null;
  async function create() {
    setBusy(true);
    setError("");
    setCode("");
    try {
      const result = await api("/api/invitations", { method: "POST" });
      setCode(result.code);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to create invitation.");
    } finally {
      setBusy(false);
    }
  }
  async function revoke(id: string) {
    setBusy(true);
    setError("");
    try {
      await api(`/api/invitations/${id}`, { method: "DELETE" });
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to revoke invitation.");
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="settings-panel">
      <h2>Beta invitations</h2>
      <p>
        Send each invitation privately to its intended beta tester.
        Invitations expire in seven days.
        Used seats remain counted.
      </p>
      <button className="secondary" disabled={busy} onClick={create}>
        Create single-use invitation
      </button>
      {error && <p role="alert">{error}</p>}
      {code && (
        <div className="alert">
          <p>Copy this code now. It is shown only once.</p>
          <code>{code}</code>
          <p>
            Send it with this link:{" "}
            <a href="/app?signup=1">https://keysprig.xyz/app?signup=1</a>
          </p>
          <button
            className="secondary"
            onClick={() => navigator.clipboard.writeText(code)}
          >
            Copy invitation
          </button>
        </div>
      )}
      <ul>
        {rows.map((row) => (
          <li key={row.id}>
            {new Date(row.created_at).toLocaleDateString()} ·{" "}
            {row.used_at
              ? "Used"
              : row.revoked_at
                ? "Revoked"
                : Date.parse(row.expires_at) < Date.now()
                  ? "Expired"
                  : row.claimed
                    ? "Google sign-in pending"
                    : "Ready"}{" "}
            {!row.used_at && !row.revoked_at && (
              <button
                className="text-button"
                disabled={busy}
                onClick={() => revoke(row.id)}
              >
                Revoke
              </button>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}
