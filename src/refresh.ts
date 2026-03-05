import { buildBundle, getCurrentBundle, setBundle } from "./zip.ts";
import { loadCachedConsensus } from "./consensus.ts";
import { verifyConsensus } from "./verify.ts";
import type { NodeSelector } from "./node-selector.ts";

const REFRESH_RETRY_MS = 5 * 60_000; // retry every 5 min on failure
const JITTER_MS = 5 * 60_000; // 0–5 min random window
const MAX_SANE_OFFSET_MS = 30 * 60_000; // ignore saved offsets > 30 min (cold-start outliers)

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function fmtMs(ms: number): string {
  if (ms < 60_000) return `${(ms / 1000).toFixed(0)}s`;
  return `${(ms / 60_000).toFixed(1)}m`;
}

interface RefreshState {
  lastSuccessOffsetMs: number;
}

async function loadState(kv: Deno.Kv): Promise<RefreshState | null> {
  const entry = await kv.get<RefreshState>(["refresh", "state"]);
  return entry.value;
}

async function saveState(kv: Deno.Kv, state: RefreshState): Promise<void> {
  await kv.set(["refresh", "state"], state);
}

/**
 * Background loop that keeps the bundle up to date.
 * Never throws — errors are caught and retried.
 */
export async function startRefreshLoop(
  kv: Deno.Kv,
  selector: NodeSelector,
): Promise<never> {
  // Phase 0: if we have a cached consensus, verify it and seed the node selector
  // so the initial build can use relay mirrors instead of just authorities
  try {
    const cached = await loadCachedConsensus(kv);
    if (cached) {
      console.log("Verifying cached consensus...");
      await verifyConsensus(cached, selector);
      selector.updateFromConsensus(cached);
      console.log("Cached consensus verified, node selector seeded.");
    }
  } catch (err) {
    console.warn("Cached consensus verification failed, using authorities:", err instanceof Error ? err.message : err);
  }

  // Phase 1: initial build (retry every 30s until success)
  while (getCurrentBundle() === null) {
    try {
      const bundle = await buildBundle(kv, selector);
      setBundle(bundle);
      logBundleSizes(bundle);
      console.log("Initial bundle ready.");
    } catch (err) {
      console.error("Initial build failed, retrying in 30s:", err);
      await sleep(30_000);
    }
  }

  // Phase 2: continuous refresh
  while (true) {
    const bundle = getCurrentBundle()!;
    const freshUntil = bundle.freshUntil;
    const state = await loadState(kv);

    // Compute target wake time
    let targetTime: number;
    if (state && state.lastSuccessOffsetMs <= MAX_SANE_OFFSET_MS) {
      // Start 0–5 min before the offset that worked last time
      const early = Math.random() * JITTER_MS;
      targetTime = freshUntil.getTime() + state.lastSuccessOffsetMs - early;
    } else {
      // No history: wake at freshUntil + random 0–5 min
      targetTime = freshUntil.getTime() + Math.random() * JITTER_MS;
    }

    const waitMs = Math.max(0, targetTime - Date.now());
    if (waitMs > 0) {
      console.log(`Next refresh attempt in ${fmtMs(waitMs)}`);
      await sleep(waitMs);
    }

    // Attempt refresh, retrying every 5 min until success
    while (true) {
      try {
        const newBundle = await buildBundle(kv, selector, freshUntil);
        if (newBundle.freshUntil > freshUntil) {
          setBundle(newBundle);
          logBundleSizes(newBundle);
          const offsetMs = Date.now() - freshUntil.getTime();
          await saveState(kv, { lastSuccessOffsetMs: offsetMs });
          console.log(
            `Refresh succeeded (${fmtMs(offsetMs)} after fresh-until)`,
          );
          break;
        }
        // Got same consensus (not updated yet) — wait and retry
        console.log("  Consensus not yet updated, retrying in 5m...");
      } catch (err) {
        console.error("Refresh failed:", err);
      }
      await sleep(REFRESH_RETRY_MS);
    }
  }
}

function logBundleSizes(b: { raw: Uint8Array; gzip: Uint8Array; brotli: Uint8Array }) {
  function fmt(n: number) {
    return n < 1024 * 1024
      ? `${(n / 1024).toFixed(0)} KB`
      : `${(n / 1024 / 1024).toFixed(1)} MB`;
  }
  console.log(
    `  raw: ${fmt(b.raw.byteLength)}, gzip: ${fmt(b.gzip.byteLength)}, brotli: ${fmt(b.brotli.byteLength)}`,
  );
}
