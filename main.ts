import { zipSync } from "npm:fflate@0.8";

const AUTHORITIES = [
  { host: "204.13.164.118", port: 80, name: "bastet" },
  { host: "199.58.81.140", port: 80, name: "longclaw" },
  { host: "171.25.193.9", port: 443, name: "maatuska" },
  { host: "86.59.21.38", port: 80, name: "tor26" },
];

const BATCH_SIZE = 92;
const CONCURRENCY = 5;
const CONNECT_TIMEOUT_MS = 2_000;
const BODY_TIMEOUT_MS = 60_000;
const MAX_ATTEMPTS = 3;

const WEEK_MS = 7 * 24 * 60 * 60 * 1000;

let cachedZip: Uint8Array | null = null;
let validUntil: Date | null = null;
let building = false;

const kv = await Deno.openKv();

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

async function fetchFromAuthority(
  path: string,
  validate?: (text: string) => boolean,
): Promise<string | null> {
  const order = shuffled(AUTHORITIES);
  const shortPath = truncPath(path);
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
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
    if (attempt < MAX_ATTEMPTS - 1) {
      console.warn(`  Retrying all authorities (attempt ${attempt + 2}/${MAX_ATTEMPTS})...`);
    }
  }
  return null;
}

async function fetchConsensus(): Promise<string> {
  const text = await fetchFromAuthority(
    "/tor/status-vote/current/consensus-microdesc",
    (body) => body.startsWith("network-status-version"),
  );
  if (!text) throw new Error("Failed to fetch consensus from any authority");
  return text;
}

function parseValidUntil(consensus: string): Date {
  const match = consensus.match(
    /^valid-until (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})$/m,
  );
  if (!match) throw new Error("Could not parse valid-until from consensus");
  return new Date(match[1] + "Z");
}

function extractDigests(consensus: string): string[] {
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
  ) ?? "";
}

async function fetchAllMicrodescs(digests: string[]): Promise<string> {
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

async function buildZip(): Promise<Uint8Array> {
  console.log("Fetching consensus...");
  const consensus = await fetchConsensus();
  const vu = parseValidUntil(consensus);
  console.log(`  Valid until: ${vu.toISOString()}`);

  const digests = extractDigests(consensus);
  console.log(`  ${digests.length} microdescriptor digests`);

  console.log("Fetching microdescriptors...");
  const microdescs = await fetchAllMicrodescs(digests);
  const mdCount = (microdescs.match(/^onion-key$/gm) || []).length;
  console.log(`  ${mdCount} microdescriptors fetched`);

  const enc = new TextEncoder();
  const zip = zipSync({
    "cached-microdesc-consensus": [enc.encode(consensus), { level: 0 }],
    "cached-microdescs.new": [enc.encode(microdescs), { level: 0 }],
  });

  console.log(`  ZIP: ${zip.byteLength} bytes`);
  validUntil = vu;
  return zip;
}

async function getZip(): Promise<Uint8Array> {
  if (cachedZip && validUntil && new Date() < validUntil) {
    return cachedZip;
  }
  if (!building) {
    building = true;
    try {
      cachedZip = await buildZip();
    } finally {
      building = false;
    }
  }
  return cachedZip!;
}

// Build on startup
console.log("Starting up...");
cachedZip = await buildZip();
building = false;
console.log("Ready.");

const handler = async (req: Request) => {
  if (new URL(req.url).pathname === "/") {
    const zip = await getZip();
    return new Response(Uint8Array.from(zip), {
      headers: {
        "Content-Type": "application/zip",
        "Content-Disposition": 'attachment; filename="tor-bootstrap.zip"',
        "Content-Length": String(zip.byteLength),
      },
    });
  }
  return new Response("Not Found", { status: 404 });
};

const BASE_PORT = 8080;
for (let port = BASE_PORT; ; port++) {
  try {
    Deno.serve({ port, onListen: ({ port }) => console.log(`Listening on :${port}`) }, handler);
    break;
  } catch (e) {
    if (e instanceof Deno.errors.AddrInUse) {
      console.warn(`Port ${port} in use, trying ${port + 1}...`);
      continue;
    }
    throw e;
  }
}
