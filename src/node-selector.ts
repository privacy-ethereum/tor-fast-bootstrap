export interface DirNode {
  host: string;
  port: number;
  name: string;
  bandwidth: number;
}

interface WeightedNode extends DirNode {
  multiplier: number; // starts at 1, adjusted by success/failure
}

export class NodeSelector {
  private nodes: WeightedNode[];

  constructor(seeds: DirNode[]) {
    this.nodes = seeds.map((n) => ({ ...n, multiplier: 1 }));
  }

  /** Replace the node pool from a fresh consensus. */
  updateFromConsensus(consensus: string): void {
    const parsed = parseRelays(consensus);
    if (parsed.length === 0) return; // keep existing pool
    this.nodes = parsed.map((r) => ({ ...r, multiplier: 1 }));
    console.log(`  NodeSelector: ${parsed.length} directory nodes from consensus`);
  }

  /** Bandwidth-weighted random pick. */
  select(): DirNode {
    const total = this.nodes.reduce((s, n) => s + n.bandwidth * n.multiplier, 0);
    let r = Math.random() * total;
    for (const n of this.nodes) {
      r -= n.bandwidth * n.multiplier;
      if (r <= 0) return n;
    }
    return this.nodes[this.nodes.length - 1];
  }

  /** Number of nodes in the pool. */
  get size(): number {
    return this.nodes.length;
  }

  reportSuccess(node: DirNode): void {
    const w = this.nodes.find((n) => n.host === node.host && n.port === node.port);
    if (w) w.multiplier = Math.min(w.multiplier * 1.1, 10);
  }

  reportFailure(node: DirNode): void {
    const w = this.nodes.find((n) => n.host === node.host && n.port === node.port);
    if (w) w.multiplier = Math.max(w.multiplier * 0.9, 0.01);
  }
}

// ---------------------------------------------------------------------------
// Consensus relay parsing
// ---------------------------------------------------------------------------

function parseRelays(consensus: string): DirNode[] {
  const out: DirNode[] = [];
  const lines = consensus.split("\n");
  let nick = "";
  let ip = "";
  let dirPort = 0;
  let flags: string[] = [];
  let bw = 0;
  let inRouter = false;

  for (const line of lines) {
    if (line.startsWith("r ")) {
      // Flush previous
      // DirPort > 0 means the relay serves directory data over plain HTTP
      if (inRouter && dirPort > 0) {
        out.push({ host: ip, port: dirPort, name: nick, bandwidth: Math.max(bw, 1) });
      }
      // microdesc consensus: r <nick> <identity> <date> <time> <ip> <orport> <dirport>
      const p = line.split(" ");
      nick = p[1];
      ip = p[5];
      dirPort = parseInt(p[7], 10);
      bw = 0;
      inRouter = true;
    } else if (line.startsWith("w ") && inRouter) {
      const m = line.match(/Bandwidth=(\d+)/);
      if (m) bw = parseInt(m[1], 10);
    } else if (line.startsWith("directory-footer")) {
      if (inRouter && dirPort > 0) {
        out.push({ host: ip, port: dirPort, name: nick, bandwidth: Math.max(bw, 1) });
      }
      break;
    }
  }
  return out;
}
