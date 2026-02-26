import { zipSync } from "npm:fflate@0.8";
import { fetchConsensus, parseValidUntil, extractDigests } from "./consensus.ts";
import { fetchAllMicrodescs } from "./microdescs.ts";

let cachedZip: Uint8Array | null = null;
let validUntil: Date | null = null;
let building = false;

export async function buildZip(kv: Deno.Kv): Promise<Uint8Array> {
  console.log("Fetching consensus...");
  const consensus = await fetchConsensus();
  const vu = parseValidUntil(consensus);
  console.log(`  Valid until: ${vu.toISOString()}`);

  const digests = extractDigests(consensus);
  console.log(`  ${digests.length} microdescriptor digests`);

  console.log("Fetching microdescriptors...");
  const microdescs = await fetchAllMicrodescs(kv, digests);
  const mdCount = (microdescs.match(/^onion-key$/gm) || []).length;
  console.log(`  ${mdCount} microdescriptors fetched`);

  const enc = new TextEncoder();
  const zip = zipSync({
    "cached-microdesc-consensus": [enc.encode(consensus), { level: 0 }],
    "cached-microdescs.new": [enc.encode(microdescs), { level: 0 }],
  });

  console.log(`  ZIP: ${zip.byteLength} bytes`);
  validUntil = vu;
  cachedZip = zip;
  return zip;
}

export async function getZip(kv: Deno.Kv): Promise<Uint8Array> {
  if (cachedZip && validUntil && new Date() < validUntil) {
    return cachedZip;
  }
  if (!building) {
    building = true;
    try {
      cachedZip = await buildZip(kv);
    } finally {
      building = false;
    }
  }
  return cachedZip!;
}
