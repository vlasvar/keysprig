import { useEffect, useState } from "react";
import type { Key } from "./App";
type Permission = {
  id: string;
  agent_id: string;
  key_id: string;
  expires_at: string;
};
export default function Permissions({
  agents,
  keys,
  api,
}: {
  agents: { id: string; label: string }[];
  keys: Key[];
  api: (path: string, init?: RequestInit) => Promise<any>;
}) {
  const [permissions, setPermissions] = useState<Permission[]>([]);
  const [editing, setEditing] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [days, setDays] = useState(7);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  async function refresh() {
    setPermissions((await api("/api/permissions")).permissions || []);
  }
  useEffect(() => {
    refresh().catch((e) => setError(e.message));
  }, [agents]);
  async function save() {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await api("/api/permissions", {
        method: "POST",
        body: JSON.stringify({
          agent_id: editing,
          key_ids: selected,
          expires_at: new Date(Date.now() + days * 86400000).toISOString(),
        }),
      });
      await refresh();
      setEditing("");
      setNotice("Permissions updated.");
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Unable to update permissions.",
      );
    } finally {
      setBusy(false);
    }
  }
  async function revoke(id: string) {
    setBusy(true);
    setError("");
    try {
      await api(`/api/permissions/${encodeURIComponent(id)}`, {
        method: "DELETE",
      });
      await refresh();
      setNotice("Permission revoked.");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to revoke permission.");
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="settings-panel">
      <h2>Key permissions</h2>
      <p>
        Grant specific keys for up to 30 days. Saving replaces this client's
        existing grants. An empty selection removes all its grants.
      </p>
      {error && (
        <div className="alert error" role="alert">
          {error}
        </div>
      )}
      {notice && (
        <div className="alert" role="status">
          {notice}
        </div>
      )}
      {agents.map((agent) => (
        <div key={agent.id} className="permission-group">
          <h3>{agent.label}</h3>
          {permissions
            .filter((p) => p.agent_id === agent.id)
            .map((p) => (
              <div className="setting-row" key={p.id}>
                <span>
                  {keys.find((k) => k.id === p.key_id)?.name || "Deleted key"} ·
                  Expires {new Date(p.expires_at).toLocaleString()}
                </span>
                <button
                  className="text-button danger"
                  disabled={busy}
                  onClick={() => revoke(p.id)}
                >
                  Revoke
                </button>
              </div>
            ))}
          <button
            className="secondary"
            disabled={busy}
            onClick={() => {
              setEditing(agent.id);
              setSelected(
                permissions
                  .filter(
                    (p) =>
                      p.agent_id === agent.id &&
                      new Date(p.expires_at).valueOf() > Date.now(),
                  )
                  .map((p) => p.key_id),
              );
              setNotice("");
            }}
          >
            Edit permissions
          </button>
        </div>
      ))}
      {editing && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void save();
          }}
        >
          <h3>Choose keys</h3>
          {keys.map((k) => (
            <label className="permission-choice" key={k.id}>
              <input
                type="checkbox"
                checked={selected.includes(k.id)}
                onChange={(e) =>
                  setSelected(
                    e.target.checked
                      ? [...selected, k.id]
                      : selected.filter((id) => id !== k.id),
                  )
                }
              />
              <span>
                {k.name}
                <small>
                  {k.allowed_hosts?.join(", ")} ·{" "}
                  {k.allowed_methods?.join(", ")}
                </small>
              </span>
            </label>
          ))}
          <label>
            Expires after (days)
            <input
              type="number"
              min={1}
              max={30}
              required
              value={days}
              onChange={(e) => setDays(Number(e.target.value))}
            />
          </label>
          <div className="form-actions">
            <button
              type="button"
              className="secondary"
              disabled={busy}
              onClick={() => setEditing("")}
            >
              Cancel
            </button>
            <button className="primary" disabled={busy}>
              {busy ? "Saving…" : "Save permissions"}
            </button>
          </div>
        </form>
      )}
    </section>
  );
}
