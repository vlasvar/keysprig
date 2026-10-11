import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import Landing from "./Landing";
import Confirm from "./Confirm";
import Legal, { legalSlug } from "./Legal";
import PrivacyNotice from "./PrivacyNotice";
import AgentConnect from "./AgentConnect";
import "./style.css";

const params = new URLSearchParams(window.location.search);
const authCallback =
  params.has("authorization_id") ||
  params.has("code") ||
  params.has("recovery") ||
  params.has("error") ||
  window.location.hash.includes("access_token=") ||
  window.location.hash.includes("error=");
const page = legalSlug(window.location.pathname);
const showLanding = window.location.pathname === "/" && !authCallback;

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    {window.location.pathname === "/connect" ? (
      <AgentConnect />
    ) : window.location.pathname === "/auth/confirm" ? (
      <Confirm />
    ) : page ? (
      <Legal page={page} />
    ) : showLanding ? (
      <Landing />
    ) : (
      <App />
    )}
    <PrivacyNotice />
  </React.StrictMode>,
);
