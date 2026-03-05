import { fetchFromNode } from "./fetch.ts";
import type { NodeSelector } from "./node-selector.ts";

const REQUIRED_SIGS = 5; // majority of 9 directory authorities

// ---------------------------------------------------------------------------
// Key certificate parsing
// ---------------------------------------------------------------------------

interface AuthorityCert {
  fingerprint: string; // identity key SHA-1 fingerprint (uppercase hex)
  signingKeyPem: string; // PEM RSA PUBLIC KEY of the signing key
  expires: Date;
}

function parseKeyCertificates(text: string): AuthorityCert[] {
  const certs: AuthorityCert[] = [];
  const blocks = text.split(/(?=^dir-key-certificate-version\s)/m);

  for (const block of blocks) {
    if (!block.startsWith("dir-key-certificate-version")) continue;

    const fp = block.match(/^fingerprint\s+([0-9A-Fa-f]+)/m)?.[1]?.toUpperCase();
    const expiresStr = block.match(/^dir-key-expires\s+(.+)/m)?.[1];
    const keyMatch = block.match(
      /dir-signing-key\n(-----BEGIN RSA PUBLIC KEY-----\n[\s\S]*?-----END RSA PUBLIC KEY-----)/m,
    );

    if (!fp || !expiresStr || !keyMatch) continue;
    const expires = new Date(expiresStr.trim() + "Z");
    if (expires < new Date()) continue; // skip expired

    certs.push({ fingerprint: fp, signingKeyPem: keyMatch[1], expires });
  }
  return certs;
}

// ---------------------------------------------------------------------------
// Raw RSA verification using BigInt
//
// Tor uses "raw" PKCS#1 v1.5 signatures: the encrypted block is
//   00 01 FF..FF 00 <raw-SHA256-hash>
// with NO ASN.1 DigestInfo wrapper. WebCrypto's RSASSA-PKCS1-v1_5 expects
// DigestInfo and Deno doesn't implement node:crypto.publicDecrypt, so we do
// the RSA public-key operation (sig^e mod n) with BigInt and check manually.
// ---------------------------------------------------------------------------

function pemToDer(pem: string): Uint8Array {
  const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s/g, "");
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

/** Minimal ASN.1 DER reader — just enough to parse RSAPublicKey { n, e }. */
function parseRsaPublicKey(der: Uint8Array): { n: bigint; e: bigint } {
  let pos = 0;

  function readTag(): { tag: number; len: number } {
    const tag = der[pos++];
    let len = der[pos++];
    if (len & 0x80) {
      const numBytes = len & 0x7f;
      len = 0;
      for (let i = 0; i < numBytes; i++) len = (len << 8) | der[pos++];
    }
    return { tag, len };
  }

  function readInteger(): bigint {
    const { tag, len } = readTag();
    if (tag !== 0x02) throw new Error(`Expected INTEGER (0x02), got 0x${tag.toString(16)}`);
    let value = 0n;
    for (let i = 0; i < len; i++) value = (value << 8n) | BigInt(der[pos++]);
    return value;
  }

  // SEQUENCE { INTEGER n, INTEGER e }
  const seq = readTag();
  if (seq.tag !== 0x30) throw new Error("Expected SEQUENCE");
  const n = readInteger();
  const e = readInteger();
  return { n, e };
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

function bigIntToBytes(v: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/**
 * RSA public-key operation + PKCS#1 v1.5 type-1 padding strip.
 * Returns the raw payload (hash) or null if padding is invalid.
 */
function rsaVerifyRaw(pkcs1Der: Uint8Array, signature: Uint8Array): Uint8Array | null {
  const { n, e } = parseRsaPublicKey(pkcs1Der);
  const s = bytesToBigInt(signature);
  const m = modPow(s, e, n);
  const block = bigIntToBytes(m, signature.length);

  // Expect: 00 01 FF FF .. FF 00 <payload>
  if (block[0] !== 0x00 || block[1] !== 0x01) return null;
  let i = 2;
  while (i < block.length && block[i] === 0xff) i++;
  if (i < 10 || i >= block.length || block[i] !== 0x00) return null;
  return block.slice(i + 1);
}

// ---------------------------------------------------------------------------
// Consensus signature verification
// ---------------------------------------------------------------------------

interface SigBlock {
  identityFp: string;
  sigB64: string;
}

function parseSignatures(consensus: string): SigBlock[] {
  const sigs: SigBlock[] = [];
  const re =
    /^directory-signature sha256 ([0-9A-Fa-f]+) [0-9A-Fa-f]+\n-----BEGIN SIGNATURE-----\n([\s\S]*?)-----END SIGNATURE-----/gm;
  let m;
  while ((m = re.exec(consensus)) !== null) {
    sigs.push({
      identityFp: m[1].toUpperCase(),
      sigB64: m[2].replace(/\s/g, ""),
    });
  }
  return sigs;
}

/**
 * The signed portion of a consensus runs from the first byte through
 * the space after the first "directory-signature " keyword (inclusive).
 */
function signedPortion(consensus: string): string {
  const marker = "\ndirectory-signature ";
  const idx = consensus.indexOf(marker);
  if (idx === -1) throw new Error("No directory-signature found in consensus");
  return consensus.slice(0, idx + marker.length);
}

export async function verifyConsensus(
  consensus: string,
  selector: NodeSelector,
): Promise<void> {
  // 1. Fetch key certificates
  console.log("  Fetching authority key certificates...");
  const { body: certText } = await fetchFromNode(
    selector,
    "/tor/keys/all",
    (b) => b.includes("dir-key-certificate-version"),
  );
  const certs = parseKeyCertificates(certText);
  console.log(`  ${certs.length} valid key certificates`);

  // Build lookup by fingerprint (keep latest if duplicates)
  const certMap = new Map<string, AuthorityCert>();
  for (const c of certs) {
    const existing = certMap.get(c.fingerprint);
    if (!existing || c.expires > existing.expires) {
      certMap.set(c.fingerprint, c);
    }
  }

  // 2. Compute SHA-256 of the signed portion
  const signedBytes = new TextEncoder().encode(signedPortion(consensus));
  const expectedHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", signedBytes),
  );

  // 3. Verify each SHA-256 signature using raw RSA + PKCS#1 v1.5 padding check
  const sigs = parseSignatures(consensus);
  let valid = 0;
  for (const sig of sigs) {
    const cert = certMap.get(sig.identityFp);
    if (!cert) continue;

    try {
      const keyDer = pemToDer(cert.signingKeyPem);
      const sigBytes = Uint8Array.from(atob(sig.sigB64), (c) => c.charCodeAt(0));
      const hash = rsaVerifyRaw(keyDer, sigBytes);
      if (
        hash &&
        hash.length === expectedHash.length &&
        hash.every((b, i) => b === expectedHash[i])
      ) {
        valid++;
      }
    } catch (err) {
      console.warn(`  [verify] ${sig.identityFp.slice(0, 12)}...: ${err}`);
    }
  }

  console.log(`  Consensus signatures: ${valid}/${sigs.length} valid`);
  if (valid < REQUIRED_SIGS) {
    throw new Error(
      `Consensus verification failed: ${valid} valid signatures, need ${REQUIRED_SIGS}`,
    );
  }
}
