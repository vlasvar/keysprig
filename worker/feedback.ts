import type { SupabaseClient } from "@supabase/supabase-js";
import { readLimited } from "./http";

const json = (data: unknown, status = 200) =>
  Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
export function validateFeedback(
  input: unknown,
): { category: string; message: string } | null {
  if (!input || typeof input !== "object") return null;
  const { category, message } = input as Record<string, unknown>;
  if (
    typeof category !== "string" ||
    !["Bug", "Idea", "Other"].includes(category) ||
    typeof message !== "string"
  )
    return null;
  const trimmed = message.trim();
  if (!trimmed || Array.from(trimmed).length > 4000) return null;
  return { category, message: trimmed };
}

// Caller must authenticate a human owner and enforce same-origin writes first.
export async function feedback(
  request: Request,
  db: SupabaseClient,
  ownerId: string,
): Promise<Response> {
  if (request.method === "POST") {
    let input: unknown;
    try {
      input = JSON.parse(await readLimited(request.body, 18000));
    } catch {
      return json({ error: "Enter feedback of up to 4000 characters." }, 400);
    }
    const valid = validateFeedback(input);
    if (!valid)
      return json(
        { error: "Choose Bug, Idea or Other and enter up to 4000 characters." },
        400,
      );
    const { data, error } = await db.rpc("vault_submit_feedback", {
      p_owner: ownerId,
      p_category: valid.category,
      p_message: valid.message,
    });
    if (error)
      return json({ error: "Unable to save feedback. Please try again." }, 503);
    if (!data)
      return json(
        {
          error:
            "You have sent 3 messages in the last hour. Please try again later.",
        },
        429,
      );
    return json({ ok: true }, 201);
  }
  if (request.method === "GET") {
    const { data: admin, error: adminError } = await db
      .from("vault_admins")
      .select("user_id")
      .eq("user_id", ownerId)
      .maybeSingle();
    if (adminError) return json({ error: "Unable to check access." }, 503);
    if (!admin) return json({ error: "Team access required." }, 403);
    const { data, error } = await db
      .from("vault_feedback")
      .select("id, owner_id, category, message, created_at")
      .order("created_at", { ascending: false })
      .limit(100);
    if (error) return json({ error: "Unable to load feedback." }, 503);
    return json({ feedback: data || [] });
  }
  return json({ error: "Method not allowed." }, 405);
}
