import { zipSync } from "npm:fflate@0.8";
import {
  fetchConsensus,
  parseFreshUntil,
  parseValidUntil,
  extractDigests,
} from "./consensus.ts";
import { fetchAllMicrodescs } from "./microdescs.ts";
import type { NodeSelector } from "./node-selector.ts";

export interface CachedBundle {
  raw: Uint8Array;
  gzip: Uint8Array;
  brotli: Uint8Array;
  freshUntil: Date;
  validUntil: Date;
}

let cached: CachedBundle | null = null;

export function getCurrentBundle(): CachedBundle | null {
  return cached;
}

export function setBundle(bundle: CachedBundle): void {
  cached = bundle;
}

// ---------------------------------------------------------------------------
// Compression
// ---------------------------------------------------------------------------

async function gzipCompress(data: Uint8Array): Promise<Uint8Array> {
  const cs = new CompressionStream("gzip");
  const writer = cs.writable.getWriter();
  writer.write(Uint8Array.from(data));
  writer.close();
  return new Uint8Array(await new Response(cs.readable).arrayBuffer());
}

async function brotliCompress(data: Uint8Array): Promise<Uint8Array> {
  const proc = new Deno.Command("brotli", {
    args: ["--quality=6", "-"],
    stdin: "piped",
    stdout: "piped",
  }).spawn();
  const [, output] = await Promise.all([
    async function () {
      const writer = proc.stdin.getWriter();
      await writer.write(data);
      await writer.close();
    }(),
    proc.output(),
  ]);
  return output.stdout;
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

export async function buildBundle(
  kv: Deno.Kv,
  selector: NodeSelector,
  newerThan?: Date,
): Promise<CachedBundle> {
  console.log("Fetching consensus...");
  const consensus = await fetchConsensus(kv, selector, newerThan);

  const freshUntil = parseFreshUntil(consensus);
  const validUntil = parseValidUntil(consensus);
  console.log(`  Valid until: ${validUntil.toISOString()}`);

  // Update node pool from the fresh consensus so microdesc fetches use relays
  selector.updateFromConsensus(consensus);

  const digests = extractDigests(consensus);
  console.log(`  ${digests.length} microdescriptor digests`);

  console.log("Fetching microdescriptors...");
  const microdescs = await fetchAllMicrodescs(kv, digests, selector);
  const mdCount = (microdescs.match(/^onion-key$/gm) || []).length;
  console.log(`  ${mdCount} microdescriptors fetched`);

  const enc = new TextEncoder();
  const raw = zipSync({
    "tor-bootstrap-data/consensus.txt": [enc.encode(consensus), { level: 0 }],
    "tor-bootstrap-data/microdescs.txt": [enc.encode(microdescs), { level: 0 }],
  });

  console.log("Compressing...");
  const [gzip, brotli] = await Promise.all([
    gzipCompress(raw),
    brotliCompress(raw),
  ]);

  return { raw, gzip, brotli, freshUntil, validUntil };
}
