import { buildZip, getZip } from "./src/zip.ts";

const kv = await Deno.openKv();

// Build on startup
console.log("Starting up...");
await buildZip(kv);
console.log("Ready.");

const handler = async (_req: Request) => {
  if (new URL(_req.url).pathname === "/") {
    const zip = await getZip(kv);
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
