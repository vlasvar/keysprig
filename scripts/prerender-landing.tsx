import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import Landing from "../web/Landing";
import Legal, { type LegalSlug } from "../web/Legal";

const file = "dist/client/index.html";
const template = await readFile(file, "utf8");
const root = '<div id="root"></div>';
if (!template.includes(root))
  throw new Error("Landing root placeholder missing");

const pages: {
  route: string;
  title: string;
  description: string;
  markup: string;
}[] = [
  {
    route: "/",
    title: "KeySprig — Private API Key Vault for AI Agents",
    description:
      "Keep API keys in one private vault. Let AI agents make approved API requests without receiving your keys. KeySprig is in private beta.",
    markup: renderToStaticMarkup(<Landing />),
  },
  {
    route: "/privacy",
    title: "Privacy Policy — KeySprig",
    description:
      "What KeySprig stores, who processes it, your rights, and how to delete your account.",
    markup: renderToStaticMarkup(<Legal page={"privacy" as LegalSlug} />),
  },
  {
    route: "/terms",
    title: "Terms of Use — KeySprig",
    description:
      "KeySprig terms of use: the service is provided as-is, and you are responsible for the keys you store.",
    markup: renderToStaticMarkup(<Legal page={"terms" as LegalSlug} />),
  },
  {
    route: "/cookies",
    title: "Cookies — KeySprig",
    description:
      "KeySprig sets no cookies and uses no analytics. Learn about necessary sign-in storage and the storage-notice preference.",
    markup: renderToStaticMarkup(<Legal page={"cookies" as LegalSlug} />),
  },
];

function replaceDescription(html: string, value: string) {
  return html.replace(
    /(name="description"\s+content=")[^"]*(")/s,
    `$1${value}$2`,
  );
}

for (const page of pages) {
  const canonical = `https://keysprig.xyz${page.route === "/" ? "/" : page.route}`;
  let html = template.replace(
    /<title>.*?<\/title>/,
    `<title>${page.title}</title>`,
  );
  html = replaceDescription(html, page.description);
  html = html.replace(
    /<link rel="canonical" href="[^"]*" \/>/,
    `<link rel="canonical" href="${canonical}" />`,
  );
  html = html.replace(
    /<meta property="og:url" content="[^"]*" \/>/,
    `<meta property="og:url" content="${canonical}" />`,
  );
  html = html.replace(root, `<div id="root">${page.markup}</div>`);
  const target =
    page.route === "/" ? file : `dist/client${page.route}/index.html`;
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, html);
}
console.log(
  "Landing and legal HTML rendered for search engines and visitors without JavaScript.",
);
