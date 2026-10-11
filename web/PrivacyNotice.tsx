import { useState } from "react";

const noticeKey = "keysprig-storage-notice-v1";

function shouldShowNotice() {
  try {
    return localStorage.getItem(noticeKey) !== "acknowledged";
  } catch {
    return true;
  }
}

export default function PrivacyNotice() {
  const [open, setOpen] = useState(shouldShowNotice);

  function dismiss() {
    try {
      localStorage.setItem(noticeKey, "acknowledged");
    } catch {
      // The notice remains usable when the browser blocks local storage.
    }
    setOpen(false);
  }

  return open ? (
    <aside className="privacy-notice" aria-label="Privacy and browser storage">
      <div>
        <h2>Just the essentials.</h2>
        <p>
          We use necessary browser storage to keep you signed in and remember
          this notice. No advertising cookies. No analytics or tracking.
        </p>
        <nav aria-label="Privacy information">
          <a href="/privacy">Privacy policy</a>
          <a href="/cookies">About browser storage</a>
        </nav>
      </div>
      <button type="button" onClick={dismiss}>
        Got it
      </button>
    </aside>
  ) : null;
}
