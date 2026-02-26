import { fetchFromAuthority } from "./fetch.ts";

export async function fetchConsensus(): Promise<string> {
  return await fetchFromAuthority(
    "/tor/status-vote/current/consensus-microdesc",
    (body) => body.startsWith("network-status-version"),
  );
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
