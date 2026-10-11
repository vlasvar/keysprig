// Exercise the installed Codex MCP client without a model turn or credential reads.
import { spawn } from "node:child_process";
import readline from "node:readline";
import path from "node:path";
const binary = path.join(
  process.env.LOCALAPPDATA,
  "Programs/OpenAI/Codex/bin/codex.exe",
);
const child = spawn(binary, ["app-server", "--stdio"], {
  stdio: ["pipe", "pipe", "pipe"],
  windowsHide: true,
});
const pending = new Map();
let next = 0;
const lines = readline.createInterface({ input: child.stdout });
lines.on("line", (line) => {
  try {
    const msg = JSON.parse(line);
    if (msg.id !== undefined && pending.has(msg.id)) {
      const handler = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error
        ? handler.reject(Error(JSON.stringify(msg.error)))
        : handler.resolve(msg.result);
    }
  } catch {}
});
child.stderr.on("data", () => {});
const rpc = (method, params) =>
  new Promise((resolve, reject) => {
    const id = ++next;
    pending.set(id, { resolve, reject });
    child.stdin.write(
      JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n",
    );
  });
const deadline = setTimeout(() => {
  console.error("Codex MCP verification timed out.");
  child.kill();
  process.exitCode = 1;
}, 90000);
try {
  await rpc("initialize", {
    clientInfo: { name: "keysprig-prototype-check", version: "1.0.0" },
    capabilities: { experimentalApi: true },
  });
  child.stdin.write(
    JSON.stringify({ jsonrpc: "2.0", method: "initialized", params: {} }) +
      "\n",
  );
  const started = await rpc("thread/start", {
    cwd: process.cwd(),
    ephemeral: true,
  });
  const threadId = started.thread.id;
  const inventory = await rpc("mcpServerStatus/list", { threadId });
  const server = (inventory.data || []).find((s) => s.name === "keysprig");
  console.log(
    JSON.stringify({
      codexConnection: server
        ? {
            name: server.name,
            authStatus: server.authStatus,
            toolNames: Object.keys(server.tools || {}),
          }
        : "not discovered",
    }),
  );
  if (!server || !["call_api", "setup_key"].every(name => Object.keys(server.tools || {}).includes(name))) throw Error("Expected call_api and private setup_key tools");
  const keyName=process.env.VERIFY_KEY_NAME;
  const target=process.env.VERIFY_API_URL;
  if (keyName && target) {
    const result=await rpc("mcpServer/tool/call",{threadId,server:"keysprig",tool:"call_api",arguments:{key_name:keyName,method:"GET",url:target}});
    if(result.isError) throw Error("Generic call failed; approve a harmless test key for this agent first.");
    const response=JSON.parse(result.content[0].text);
    if(!Number.isInteger(response.status)) throw Error("Invalid generic response");
    console.log(JSON.stringify({passed:true,checks:["real Codex MCP discovery","generic harmless outbound request"],status:response.status}));
  } else console.log(JSON.stringify({passed:true,checks:["real Codex MCP discovery"],callVerified:false,reason:"Set VERIFY_KEY_NAME and VERIFY_API_URL for an approved harmless test credential; response content is never printed."}));
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
} finally {
  clearTimeout(deadline);
  lines.close();
  child.kill();
}
