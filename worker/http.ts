export async function withDeadline<T>(
  task: (signal: AbortSignal) => Promise<T>,
  milliseconds = 10000,
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), milliseconds);
  try {
    return await task(controller.signal);
  } finally {
    clearTimeout(timer);
  }
}
export async function readLimited(
  body: ReadableStream<Uint8Array> | null,
  limit: number,
): Promise<string> {
  if (!body) return "";
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let text = "",
    size = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > limit) throw Error("Body too large");
      text += decoder.decode(chunk.value, { stream: true });
    }
    return text + decoder.decode();
  } finally {
    await reader.cancel();
    reader.releaseLock();
  }
}
