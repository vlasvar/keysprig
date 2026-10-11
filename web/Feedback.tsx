import { useEffect, useState } from "react";

export default function Feedback({
  api,
}: {
  api: (path: string, init?: RequestInit) => Promise<any>;
}) {
  const [category, setCategory] = useState("Bug");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [reviews, setReviews] = useState<
    | {
        id: string;
        owner_id: string;
        category: string;
        message: string;
        created_at: string;
      }[]
    | null
  >(null);
  useEffect(() => {
    let active = true;
    // Normal testers receive 403. Only the team sees the review list.
    api("/api/feedback")
      .then((data) => {
        if (active) setReviews(data.feedback || []);
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, []);
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await api("/api/feedback", {
        method: "POST",
        body: JSON.stringify({ category, message }),
      });
      setMessage("");
      setNotice(
        "Thank you, beta tester. Your feedback has been sent to the KeySprig team.",
      );
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "Unable to send feedback. Please try again.",
      );
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="settings-card">
      <h2>Beta testers feedback</h2>
      <p>
        Found a bug, have an idea, or got stuck? Help us make KeySprig better.
      </p>
      <p>
        <strong>
          Never include API keys, passwords, invitation codes or other secrets.
        </strong>{" "}
        Feedback is shared with the KeySprig team and linked to your account. It
        is not part of your encrypted vault.
      </p>
      <form onSubmit={submit}>
        <label>
          What would you like to share?
          <select
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            disabled={busy}
          >
            <option>Bug</option>
            <option>Idea</option>
            <option>Other</option>
          </select>
        </label>
        <label>
          Your feedback
          <textarea
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            maxLength={4000}
            rows={7}
            required
            disabled={busy}
            placeholder="What happened? What did you expect?"
          />
        </label>
        <small>
          {message.length}/4000 characters · Up to 3 submissions per hour
        </small>
        {error && <p role="alert">{error}</p>}
        {notice && <p role="status">{notice}</p>}
        <div className="form-actions">
          <button className="primary" disabled={busy || !message.trim()}>
            {busy ? "Sending…" : "Send feedback"}
          </button>
        </div>
      </form>
      {reviews !== null && (
        <section>
          <h3>Team feedback inbox</h3>
          <p>
            The latest 100 submissions. Feedback can include personal
            information: keep it within the team.
          </p>
          <button
            type="button"
            onClick={() =>
              api("/api/feedback")
                .then((data) => setReviews(data.feedback || []))
                .catch(() => setError("Unable to refresh feedback."))
            }
          >
            Refresh feedback
          </button>
          {!reviews.length && <p>No feedback yet.</p>}
          {reviews.map((item) => (
            <article key={item.id}>
              <h4>
                {item.category} · {new Date(item.created_at).toLocaleString()}
              </h4>
              <small>Tester account: {item.owner_id}</small>
              <p style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>
                {item.message}
              </p>
            </article>
          ))}
        </section>
      )}
    </section>
  );
}
