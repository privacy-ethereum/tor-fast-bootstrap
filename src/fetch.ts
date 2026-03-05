import { BODY_TIMEOUT_MS, CONNECT_TIMEOUT_MS, INITIAL_BACKOFF_MS } from "./config.ts";
import type { DirNode, NodeSelector } from "./node-selector.ts";

function truncPath(path: string, max = 100): string {
  if (path.length <= max) return path;
  const half = Math.floor((max - 3) / 2);
  return path.slice(0, half) + "..." + path.slice(-half);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Fetch a directory document from the node pool.
 * Tries weighted-random selections; reports success/failure to the selector.
 * Returns both the body text and the node that served it.
 */
export async function fetchFromNode(
  selector: NodeSelector,
  path: string,
  validate?: (text: string) => boolean,
): Promise<{ body: string; node: DirNode }> {
  const shortPath = truncPath(path);
  let backoff = INITIAL_BACKOFF_MS;
  const attemptsPerRound = Math.min(selector.size, 10);

  for (let round = 1; ; round++) {
    for (let i = 0; i < attemptsPerRound; i++) {
      const node = selector.select();
      const scheme = node.port === 443 ? "https" : "http";
      const url = `${scheme}://${node.host}:${node.port}${path}`;
      try {
        const resp = await fetch(url, {
          signal: AbortSignal.timeout(CONNECT_TIMEOUT_MS),
        });
        if (!resp.ok) {
          console.warn(`  [${node.name}] HTTP ${resp.status} for ${shortPath}`);
          resp.body?.cancel();
          selector.reportFailure(node);
          continue;
        }
        // Decompress if Content-Encoding is set (Tor sends deflate/zlib)
        let bodyStream = resp.body!;
        const encoding = resp.headers.get("Content-Encoding");
        if (encoding === "deflate" || encoding === "gzip") {
          bodyStream = bodyStream.pipeThrough(new DecompressionStream(encoding));
        }
        const body = await Promise.race([
          new Response(bodyStream).text(),
          new Promise<never>((_, reject) =>
            setTimeout(() => reject(new Error("body timeout")), BODY_TIMEOUT_MS)
          ),
        ]);
        if (validate && !validate(body)) {
          console.warn(`  [${node.name}] validation failed for ${shortPath}`);
          selector.reportFailure(node);
          continue;
        }
        selector.reportSuccess(node);
        return { body, node };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.warn(`  [${node.name}] ${msg} for ${shortPath}`);
        selector.reportFailure(node);
      }
    }
    console.warn(
      `  All nodes failed (round ${round}), retrying in ${(backoff / 1000).toFixed(1)}s...`,
    );
    await sleep(backoff);
    backoff = Math.round(backoff * 1.5);
  }
}
