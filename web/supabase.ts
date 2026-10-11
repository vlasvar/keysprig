import { createClient } from "@supabase/supabase-js";
const config = import.meta.env;
export const googleEnabled = config.VITE_GOOGLE_AUTH_ENABLED === "true";
export const supabase =
  config.VITE_SUPABASE_URL && config.VITE_SUPABASE_ANON_KEY
    ? createClient(config.VITE_SUPABASE_URL, config.VITE_SUPABASE_ANON_KEY, {
        auth: { flowType: "pkce" },
      })
    : null;
