import { BATCH_SIZE, CONCURRENCY, WEEK_MS } from "./config.ts";
import { fetchFromAuthority } from "./fetch.ts";

function splitMicrodescs(text: string): string[] {
  return text.split(/(?=^onion-key\n)/m).filter((s) => s.startsWith("onion-key"));
}

async function microdescDigest(md: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(md));
  return btoa(String.fromCharCode(...new Uint8Array(hash))).replace(/=+$/, "");
}

async function fetchMicrodescBatch(digests: string[]): Promise<string> {
  const path = `/tor/micro/d/${digests.join("-")}`;
  return await fetchFromAuthority(
    path,
    (body) => body.includes("-----BEGIN") && !body.slice(0, 100).toLowerCase().includes("<html"),
  );
}

export async function fetchAllMicrodescs(
  kv: Deno.Kv,
  digests: string[],
): Promise<string> {
  // Load cached microdescs from KV
  const have = new Map<string, string>();
  const needed = new Set(digests);
  for await (const entry of kv.list<string>({ prefix: ["md"] })) {
    const d = entry.key[1] as string;
    if (needed.has(d)) {
      have.set(d, entry.value);
    }
  }
  const missing = digests.filter((d) => !have.has(d));
  console.log(`  ${have.size} cached, ${missing.length} to fetch`);

  // Fetch missing in batches with bounded concurrency
  const batches: string[][] = [];
  for (let i = 0; i < missing.length; i += BATCH_SIZE) {
    batches.push(missing.slice(i, i + BATCH_SIZE));
  }
  let completed = 0;
  const queue = [...batches];
  const workers = Array.from({ length: CONCURRENCY }, async () => {
    while (queue.length > 0) {
      const batch = queue.shift()!;
      const text = await fetchMicrodescBatch(batch);
      // Split response into individual microdescs, hash each, cache in KV
      const mds = splitMicrodescs(text);
      for (const md of mds) {
        const digest = await microdescDigest(md);
        have.set(digest, md);
        kv.set(["md", digest], md, { expireIn: WEEK_MS });
      }
      completed++;
      if (completed % 10 === 0 || completed === batches.length) {
        console.log(`  ${completed}/${batches.length} batches fetched`);
      }
    }
  });
  await Promise.all(workers);

  // Reassemble in consensus order
  return digests.map((d) => have.get(d) ?? "").join("");
}
