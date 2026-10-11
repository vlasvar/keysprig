import { LegalLinks } from "./Legal";

export default function Landing() {
  return (
    <div className="sprig-landing">
      <header className="sprig-header">
        <img src="/keysprig-logo.svg" alt="KeySprig" width="760" height="200" />
      </header>
      <main className="sprig-intro">
        <h1>
          Your keys.
          <br />
          Your agents.
          <br />
          <span>Your control.</span>
        </h1>
        <p>
          Keep your API keys in one private vault. Let your AI agents make
          approved requests, while the keys stay with KeySprig.
        </p>
        <p className="sprig-beta">Beta - Invitation only</p>
        <nav className="sprig-account-links" aria-label="Account access">
          <a href="/app?signup=1">Use an invitation</a>
          <a href="/app">Already a member? Sign in</a>
          <a href="mailto:keysprig@agentmail.to?subject=KeySprig%20beta%20invitation%20request">
            Request an invitation
          </a>
        </nav>
      </main>
      <footer className="sprig-footer">
        <span className="sprig-status">
          <span aria-hidden="true" />
          Private beta
        </span>
        <div className="sprig-footer-details">
          <LegalLinks />
          <span>Currently in private testing.</span>
          <span>
            Created by the <a href="https://aislop.gr/">aislop.gr</a> team and
            GPT.
          </span>
        </div>
      </footer>
    </div>
  );
}
