const bytes = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const base64 = (b: ArrayBuffer | Uint8Array) =>
  btoa(String.fromCharCode(...new Uint8Array(b)));
async function key(root: string) {
  const raw = bytes(root);
  if (raw.length !== 32) throw Error("Invalid encryption configuration");
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}
export async function encrypt(root: string, context: string, value: string) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce,
      additionalData: new TextEncoder().encode(context),
    },
    await key(root),
    new TextEncoder().encode(value),
  );
  return { ciphertext: base64(ciphertext), nonce: base64(nonce) };
}
export async function decrypt(
  root: string,
  context: string,
  record: { nonce: string; ciphertext: string },
) {
  const value = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: bytes(record.nonce),
      additionalData: new TextEncoder().encode(context),
    },
    await key(root),
    bytes(record.ciphertext),
  );
  return new TextDecoder().decode(value);
}
export function authorize(
  claims: Record<string, unknown>,
  kind: "human" | "agent",
) {
  if (
    typeof claims.sub !== "string" ||
    !claims.sub ||
    claims.role !== "authenticated"
  )
    throw Error("Unauthorized");
  const client =
    typeof claims.client_id === "string" && claims.client_id
      ? claims.client_id
      : undefined;
  if ((kind === "human" && client) || (kind === "agent" && !client))
    throw Error("Unauthorized");
  return { owner: claims.sub, client };
}
