/**
 * Fetch helpers: bounded body reads, and a timeout that composes with the
 * caller's AbortSignal.
 */

export class BodyTooLargeError extends Error {
  constructor(readonly limitBytes: number) {
    super(`Response body exceeds ${limitBytes} bytes`);
    this.name = "BodyTooLargeError";
  }
}

export function withTimeout(
  signal: AbortSignal | undefined,
  timeoutMs: number,
): AbortSignal {
  const timeout = AbortSignal.timeout(timeoutMs);
  if (!signal) return timeout;
  const any = (AbortSignal as unknown as {
    any?: (signals: AbortSignal[]) => AbortSignal;
  }).any;
  if (typeof any === "function") return any.call(AbortSignal, [signal, timeout]);
  const controller = new AbortController();
  for (const s of [signal, timeout]) {
    if (s.aborted) {
      controller.abort(s.reason);
      break;
    }
    s.addEventListener("abort", () => controller.abort(s.reason), { once: true });
  }
  return controller.signal;
}

export async function readTextCapped(
  res: Response,
  limitBytes: number,
): Promise<string> {
  const declared = Number(res.headers.get("content-length") ?? "");
  if (Number.isFinite(declared) && declared > limitBytes) {
    throw new BodyTooLargeError(limitBytes);
  }
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limitBytes) {
      await reader.cancel();
      throw new BodyTooLargeError(limitBytes);
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return new TextDecoder().decode(out);
}

export async function readJsonCapped(
  res: Response,
  limitBytes: number,
): Promise<unknown> {
  return JSON.parse(await readTextCapped(res, limitBytes));
}
