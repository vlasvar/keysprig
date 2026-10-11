import { chromium } from "playwright";
const base = process.env.VAULT_TEST_URL || "http://127.0.0.1:3417";
const verify = async (page) => {
  const fs = await import("node:fs");
  const crypto = await import("node:crypto");
  const folder = process.cwd();
  const config = Object.fromEntries(
    fs
      .readFileSync(folder + "/.dev.vars", "utf8")
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        const i = line.indexOf("=");
        return [line.slice(0, i), JSON.parse(line.slice(i + 1))];
      }),
  );
  const email = "browser-" + crypto.randomUUID() + "@vault-test.invalid",
    password = crypto.randomBytes(32).toString("base64url");
  const headers = {
    apikey: config.SUPABASE_SERVICE_ROLE_KEY,
    Authorization: "Bearer " + config.SUPABASE_SERVICE_ROLE_KEY,
  };
  const created = await page.request.post(
    config.SUPABASE_URL + "/auth/v1/admin/users",
    { headers, data: { email, password, email_confirm: true } },
  );
  if (!created.ok()) throw Error("Temporary account creation failed");
  const user = await created.json();
  try {
    await page.goto(base + "/app");
    await page.getByRole("button", { name: "Got it", exact: true }).click();
    await page
      .getByRole("button", { name: "Sign in with email", exact: true })
      .click();
    await page.getByLabel("Email", { exact: true }).fill(email);
    await page.getByLabel("Password", { exact: true }).fill(password);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await page.getByRole("button", { name: "Add key" }).waitFor();
    await page.getByRole("button", { name: "Add key" }).click();
    await page.getByLabel(/^Name/).fill("browser_dummy");
    await page.getByLabel("Allowed API hosts").fill("httpbin.org");
    await page.getByLabel("Authentication header").fill("X-Api-Key");
    await page
      .getByLabel("Key value", { exact: true })
      .fill("dummy-browser-value");
    await page.getByRole("button", { name: "Save key", exact: true }).click();
    await page.getByText("browser_dummy", { exact: true }).waitFor();
    if (
      (await page.locator("body").innerText()).includes("dummy-browser-value")
    )
      throw Error("Value leaked into UI");
    await page.screenshot({
      path: folder + "/artifacts/dashboard-desktop.png",
      fullPage: true,
    });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({
      path: folder + "/artifacts/dashboard-mobile.png",
      fullPage: true,
    });
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth > innerWidth,
    );
    if (overflow) throw Error("Mobile overflow");
    await page.setViewportSize({ width: 1280, height: 900 });
    page.once("dialog", (dialog) => dialog.accept());
    await page.getByRole("button", { name: "Delete", exact: true }).click();
    await page.getByText("Your vault starts here", { exact: true }).waitFor();
    await page.getByRole("button", { name: /Agents$/ }).click();
    await page.getByText("No connected agents yet", { exact: true }).waitFor();
    await page.getByRole("button", { name: /Activity$/ }).click();
    await page.getByText("key.created", { exact: true }).first().waitFor();
    await page.getByRole("button", { name: /Feedback$/ }).click();
    await page
      .getByLabel("Your feedback", { exact: true })
      .fill("Disposable browser beta verification.");
    await page
      .getByRole("button", { name: "Send feedback", exact: true })
      .click();
    await page.getByText("Thank you, beta tester.", { exact: false }).waitFor();
    await page.screenshot({
      path: folder + "/artifacts/beta-feedback.png",
      fullPage: true,
    });
    await page.getByRole("button", { name: /Settings$/ }).click();
    await page
      .getByRole("heading", { name: "How your keys are stored" })
      .waitFor();
    await page
      .getByRole("button", { name: "Sign out", exact: true })
      .last()
      .click();
    await page
      .getByRole("button", { name: "Sign in with email", exact: true })
      .waitFor();
    await page
      .getByRole("button", {
        name: "Have an invitation? Join the beta",
        exact: true,
      })
      .click();
    const googleButton = page.getByRole("button", {
      name: "Sign up with Google",
      exact: true,
    });
    if (await googleButton.isEnabled())
      throw Error("Google signup lacks invitation input gate");
    await page
      .getByLabel("Invitation code", { exact: true })
      .fill("invalid-invitation-proof");
    await page
      .getByLabel("Google account email", { exact: true })
      .fill("tester@vault-test.invalid");
    await googleButton.click();
    await page.getByRole("alert").waitFor();
    if ((await page.locator("input[type=password]").count()) !== 0)
      throw Error("Email signup form exposed");
    await page.screenshot({
      path: folder + "/artifacts/beta-invitation.png",
      fullPage: true,
    });
    await page
      .getByRole("button", { name: "Already a tester? Sign in", exact: true })
      .click();
    const recoveryLink = await page.request.post(
      config.SUPABASE_URL +
        "/auth/v1/admin/generate_link?redirect_to=" +
        encodeURIComponent(base + "/?recovery=1"),
      { headers, data: { type: "recovery", email } },
    );
    if (!recoveryLink.ok()) throw Error("Recovery link generation failed");
    const recoveryData = await recoveryLink.json();
    if (!recoveryData.action_link) throw Error("Recovery action link missing");
    // Simulate opening an email in a browser with no requesting-browser state.
    await page.evaluate(() => localStorage.clear());
    await page.goto(
      base +
        "/auth/confirm#token_hash=" +
        encodeURIComponent(recoveryData.hashed_token) +
        "&type=recovery",
    );
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await page
      .getByRole("heading", { name: "Choose a new password" })
      .waitFor();
    await page
      .getByLabel("New password", { exact: true })
      .fill(crypto.randomBytes(32).toString("base64url"));
    await page
      .getByRole("button", { name: "Update password", exact: true })
      .click();
    await page.getByRole("button", { name: "Add key" }).waitFor();
    return {
      passed: true,
      checks: [
        "sign-in",
        "private entry",
        "metadata list",
        "delete",
        "agents",
        "activity",
        "settings",
        "beta feedback submission",
        "invitation gate and invalid-code rejection",
        "sign-out",
        "email-link recovery without browser verifier",
        "mobile no overflow",
      ],
      screenshots: ["dashboard-desktop.png", "dashboard-mobile.png"],
    };
  } finally {
    const removed = await page.request.delete(
      config.SUPABASE_URL + "/auth/v1/admin/users/" + user.id,
      { headers },
    );
    if (!removed.ok()) throw Error("Temporary account cleanup failed");
  }
};
const browser = await chromium.launch({
  headless: true,
  executablePath:
    process.env.CHROME_PATH ||
    "C:/Program Files/Google/Chrome/Application/chrome.exe",
});
try {
  const page = await browser.newPage({
    viewport: { width: 1280, height: 900 },
  });
  console.log(JSON.stringify(await verify(page)));
} finally {
  await browser.close();
}
