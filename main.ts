import { getCurrentBundle } from "./src/zip.ts";
import { NodeSelector } from "./src/node-selector.ts";
import { AUTHORITIES } from "./src/config.ts";
import { startRefreshLoop } from "./src/refresh.ts";

const kv = await Deno.openKv();

// Cold-start node pool: equal-weight authorities
const selector = new NodeSelector(
  AUTHORITIES.map((a) => ({
    host: a.host,
    port: a.port,
    name: a.name,
    bandwidth: 1,
  })),
);

// ---------------------------------------------------------------------------
// Request handler
// ---------------------------------------------------------------------------

const handler = (_req: Request) => {
  if (new URL(_req.url).pathname === "/") {
    const bundle = getCurrentBundle();
    if (!bundle) {
      return new Response("Bootstrap data not yet available. Please retry.", {
        status: 503,
        headers: { "Retry-After": "30" },
      });
    }
    const ae = _req.headers.get("Accept-Encoding") ?? "";
    let body: Uint8Array;
    let encoding: string | undefined;
    if (ae.includes("br")) {
      body = bundle.brotli;
      encoding = "br";
    } else if (ae.includes("gzip")) {
      body = bundle.gzip;
      encoding = "gzip";
    } else {
      body = bundle.raw;
    }
    const headers: Record<string, string> = {
      "Content-Type": "application/zip",
      "Content-Disposition": 'attachment; filename="tor-bootstrap-data.zip"',
      "Content-Length": String(body.byteLength),
    };
    if (encoding) headers["Content-Encoding"] = encoding;
    return new Response(Uint8Array.from(body), { headers });
  }
  return new Response("Not Found", { status: 404 });
};

// ---------------------------------------------------------------------------
// Network / TLS helpers
// ---------------------------------------------------------------------------

function getLanAddress(): string | null {
  for (const iface of Deno.networkInterfaces()) {
    if (iface.family === "IPv4" && !iface.address.startsWith("127.")) {
      return iface.address;
    }
  }
  return null;
}

async function generateSelfSignedCert(): Promise<{ cert: string; key: string }> {
  const { stdout: key } = await new Deno.Command("openssl", {
    args: ["ecparam", "-genkey", "-name", "prime256v1", "-noout"],
    stdout: "piped",
    stderr: "null",
  }).output();

  const keyPem = new TextDecoder().decode(key);

  const proc = new Deno.Command("openssl", {
    args: [
      "req", "-new", "-x509",
      "-key", "/dev/stdin",
      "-days", "365",
      "-subj", "/CN=tor-bootstrap-helper",
      "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ],
    stdin: "piped",
    stdout: "piped",
    stderr: "null",
  }).spawn();

  const [, output] = await Promise.all([
    async function () {
      const writer = proc.stdin.getWriter();
      await writer.write(key);
      await writer.close();
    }(),
    proc.output(),
  ]);

  return { cert: new TextDecoder().decode(output.stdout), key: keyPem };
}

// ---------------------------------------------------------------------------
// Start servers immediately, then refresh in background
// ---------------------------------------------------------------------------

const lan = getLanAddress();

function tryServe(
  basePort: number,
  extra: Record<string, unknown>,
  scheme: string,
) {
  for (let port = basePort; ; port++) {
    try {
      Deno.serve({
        port,
        hostname: "0.0.0.0",
        onListen() {
          console.log(`  ${scheme}://${lan ?? "0.0.0.0"}:${port}`);
        },
        ...extra,
      }, handler);
      return;
    } catch (e) {
      if (e instanceof Deno.errors.AddrInUse) {
        console.warn(`Port ${port} in use, trying ${port + 1}...`);
        continue;
      }
      throw e;
    }
  }
}

// HTTP
tryServe(8080, {}, "http");

// HTTPS (self-signed)
console.log("Generating self-signed certificate...");
const tls = await generateSelfSignedCert();
tryServe(8443, { cert: tls.cert, key: tls.key }, "https");

// Background refresh (non-blocking — runs forever)
startRefreshLoop(kv, selector);
