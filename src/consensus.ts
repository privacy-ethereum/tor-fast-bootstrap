import { crypto } from "jsr:@std/crypto";
import { fetchFromNode } from "./fetch.ts";
import { verifyConsensus } from "./verify.ts";
import type { NodeSelector } from "./node-selector.ts";

export function parseFreshUntil(consensus: string): Date {
  const match = consensus.match(
    /^fresh-until (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})$/m,
  );
  if (!match) throw new Error("Could not parse fresh-until from consensus");
  return new Date(match[1] + "Z");
}

export function parseValidUntil(consensus: string): Date {
  const match = consensus.match(
    /^valid-until (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})$/m,
  );
  if (!match) throw new Error("Could not parse valid-until from consensus");
  return new Date(match[1] + "Z");
}

export function extractDigests(consensus: string): string[] {
  const digests: string[] = [];
  for (const line of consensus.split("\n")) {
    if (line.startsWith("m ")) {
      for (const d of line.slice(2).trim().split(",")) {
        if (d) digests.push(d.trim());
      }
    }
  }
  return digests;
}

// ---------------------------------------------------------------------------
// KV caching (chunked to stay under 64 KB per value)
// ---------------------------------------------------------------------------

const CHUNK_SIZE = 60_000;

function toHex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha3(text: string): Promise<string> {
  const hash = await crypto.subtle.digest(
    "SHA3-256",
    new TextEncoder().encode(text),
  );
  return toHex(hash);
}

async function purgeConsensus(
  kv: Deno.Kv,
  hash: string,
  count: number,
): Promise<void> {
  await Promise.all(
    Array.from({ length: count }, (_, i) =>
      kv.delete(["dir", "consensus", "microdesc", hash, i]),
    ),
  );
  await kv.delete(["dir", "consensus", "microdesc", "ptr"]);
}

export async function loadCachedConsensus(kv: Deno.Kv): Promise<string | null> {
  const ptr = await kv.get<{ hash: string; chunks: number }>(
    ["dir", "consensus", "microdesc", "ptr"],
  );
  if (ptr.value === null) return null;
  const { hash, chunks: count } = ptr.value;
  const parts: string[] = [];
  for (let i = 0; i < count; i += 10) {
    const keys = Array.from(
      { length: Math.min(10, count - i) },
      (_, j) => ["dir", "consensus", "microdesc", hash, i + j],
    );
    const entries = await kv.getMany<string[]>(keys);
    for (const e of entries) {
      if (e.value === null) return null;
      parts.push(e.value as string);
    }
  }
  const text = parts.join("");
  if ((await sha3(text)) !== hash) {
    console.warn("  Consensus cache integrity check failed, purging");
    await purgeConsensus(kv, hash, count);
    return null;
  }
  return text;
}

async function cacheConsensus(
  kv: Deno.Kv,
  text: string,
  expireIn: number,
): Promise<void> {
  const hash = await sha3(text);
  const chunks: string[] = [];
  for (let i = 0; i < text.length; i += CHUNK_SIZE) {
    chunks.push(text.slice(i, i + CHUNK_SIZE));
  }
  await Promise.all(
    chunks.map((c, i) =>
      kv.set(["dir", "consensus", "microdesc", hash, i], c, { expireIn }),
    ),
  );
  await kv.set(
    ["dir", "consensus", "microdesc", "ptr"],
    { hash, chunks: chunks.length },
    { expireIn },
  );
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Fetch (or load cached) consensus.
 * Pass `newerThan` to skip cache if its fresh-until is at or before that date
 * (used by the refresh loop to force fetching a newer consensus).
 */
export async function fetchConsensus(
  kv: Deno.Kv,
  selector: NodeSelector,
  newerThan?: Date,
): Promise<string> {
  const cached = await loadCachedConsensus(kv);
  if (cached) {
    if (newerThan) {
      const fu = parseFreshUntil(cached);
      if (fu <= newerThan) {
        console.log("  Cached consensus is stale, fetching fresh...");
      } else {
        console.log("  Using cached consensus");
        return cached;
      }
    } else {
      console.log("  Using cached consensus");
      return cached;
    }
  }

  const { body: text } = await fetchFromNode(
    selector,
    "/tor/status-vote/current/consensus-microdesc",
    (body) => body.startsWith("network-status-version"),
  );

  // Verify signatures before trusting
  await verifyConsensus(text, selector);

  // Cache until valid-until (not fresh-until) so restarts during the stale
  // window still have data
  const validUntil = parseValidUntil(text);
  const expireIn = Math.max(0, validUntil.getTime() - Date.now());
  const freshUntil = parseFreshUntil(text);
  console.log(
    `  Fresh until: ${freshUntil.toISOString()}, valid until: ${validUntil.toISOString()}`,
  );
  await cacheConsensus(kv, text, expireIn);

  return text;
}
