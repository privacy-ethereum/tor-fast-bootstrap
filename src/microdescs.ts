import { BATCH_SIZE, CONCURRENCY, WEEK_MS } from "./config.ts";
import { fetchFromNode } from "./fetch.ts";
import type { NodeSelector } from "./node-selector.ts";

function splitMicrodescs(text: string): string[] {
  return text
    .split(/(?=^onion-key\n)/m)
    .filter((s) => s.startsWith("onion-key"));
}

async function microdescDigest(md: string): Promise<string> {
  const hash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(md),
  );
  return btoa(String.fromCharCode(...new Uint8Array(hash))).replace(/=+$/, "");
}

export async function fetchAllMicrodescs(
  kv: Deno.Kv,
  digests: string[],
  selector: NodeSelector,
): Promise<string> {
  // Load cached microdescs from KV, verifying integrity
  const have = new Map<string, string>();
  const needed = new Set(digests);
  let corrupt = 0;
  for await (const entry of kv.list<string>({ prefix: ["dir", "microdesc"] })) {
    const d = entry.key[2] as string;
    if (needed.has(d)) {
      if ((await microdescDigest(entry.value)) === d) {
        have.set(d, entry.value);
      } else {
        corrupt++;
        kv.delete(["dir", "microdesc", d]);
      }
    }
  }
  if (corrupt > 0) {
    console.warn(
      `  ${corrupt} cached microdescs failed integrity check, purged`,
    );
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
      const batchSet = new Set(batch);
      const path = `/tor/micro/d/${batch.join("-")}`;
      const { body: text, node } = await fetchFromNode(
        selector,
        path,
        (body) =>
          body.includes("-----BEGIN") &&
          !body.slice(0, 100).toLowerCase().includes("<html"),
      );

      // Verify each microdesc's digest matches a requested digest
      const mds = splitMicrodescs(text);
      let rejected = 0;
      for (const md of mds) {
        const digest = await microdescDigest(md);
        if (batchSet.has(digest)) {
          have.set(digest, md);
          kv.set(["dir", "microdesc", digest], md, { expireIn: WEEK_MS });
        } else {
          rejected++;
        }
      }
      if (rejected > 0) {
        console.warn(
          `  [${node.name}] ${rejected} microdescs didn't match requested digests`,
        );
        selector.reportFailure(node);
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
