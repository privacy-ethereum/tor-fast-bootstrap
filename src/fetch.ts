import {
  AUTHORITIES,
  BODY_TIMEOUT_MS,
  CONNECT_TIMEOUT_MS,
  INITIAL_BACKOFF_MS,
} from "./config.ts";

function shuffled<T>(arr: T[]): T[] {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function truncPath(path: string, max = 100): string {
  if (path.length <= max) return path;
  const half = Math.floor((max - 3) / 2);
  return path.slice(0, half) + "..." + path.slice(-half);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function fetchFromAuthority(
  path: string,
  validate?: (text: string) => boolean,
): Promise<string> {
  const shortPath = truncPath(path);
  let backoff = INITIAL_BACKOFF_MS;
  for (let round = 1; ; round++) {
    const order = shuffled(AUTHORITIES);
    for (const auth of order) {
      const url = `http://${auth.host}:${auth.port}${path}`;
      try {
        const resp = await fetch(url, {
          signal: AbortSignal.timeout(CONNECT_TIMEOUT_MS),
        });
        if (!resp.ok) {
          console.warn(`  [${auth.name}] HTTP ${resp.status} for ${shortPath}`);
          resp.body?.cancel();
          continue;
        }
        // Decompress if Content-Encoding is set (Tor sends deflate/zlib)
        let bodyStream = resp.body!;
        const encoding = resp.headers.get("Content-Encoding");
        if (encoding === "deflate" || encoding === "gzip") {
          bodyStream = bodyStream.pipeThrough(new DecompressionStream(encoding));
        }
        // Longer timeout for reading the body
        const body = await Promise.race([
          new Response(bodyStream).text(),
          new Promise<never>((_, reject) =>
            setTimeout(() => reject(new Error("body timeout")), BODY_TIMEOUT_MS)
          ),
        ]);
        if (validate && !validate(body)) {
          console.warn(`  [${auth.name}] validation failed for ${shortPath}`);
          continue;
        }
        return body;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.warn(`  [${auth.name}] ${msg} for ${shortPath}`);
      }
    }
    console.warn(`  All authorities failed (round ${round}), retrying in ${(backoff / 1000).toFixed(1)}s...`);
    await sleep(backoff);
    backoff = Math.round(backoff * 1.5);
  }
}
