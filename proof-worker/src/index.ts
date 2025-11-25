export interface Env {
  LAYERS: R2Bucket;
  LOOKUP: R2Bucket;
  CLAIM_AMOUNT: string; // wei
  META_KEY?: string; // defaults to "merkle-meta.json"
  LOOKUP_PREFIX?: string; // defaults to "lookup"
}

type Meta = {
  root: string; // 0x-prefixed hex
  leafCount: number;
  layerFiles: string[]; // ["layer0.bin", "layer1.bin", ...] stored in LAYERS bucket
  claimAmount?: string; // optional override; otherwise Env.CLAIM_AMOUNT
  hashFn?: string;
  leafEncoding?: string;
  pairOrdering?: string; // expect "sorted"
};

type LookupEntry = { address: string; index: number };

const cache: { meta?: Meta } = {};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return cors(new Response(null, { status: 204 }));

    try {
      if (url.pathname === "/info") {
        const meta = await loadMeta(env);
        return cors(json({ root: meta.root, leafCount: meta.leafCount, claimAmount: effectiveClaimAmount(meta, env) }));
      }

      if (url.pathname === "/proof") {
        const addr = url.searchParams.get("address");
        if (!addr) return cors(error("missing address", 400));
        const address = addr.toLowerCase();
        if (!/^0x[0-9a-f]{40}$/.test(address)) return cors(error("invalid address", 400));

        const meta = await loadMeta(env);
        const entry = await lookupIndex(address, env);
        if (!entry) return cors(error("address not eligible", 404));

        const proof = await buildProof(entry.index, meta, env);
        return cors(json({ ...entry, amount: effectiveClaimAmount(meta, env), proof, root: meta.root }));
      }

      return cors(new Response("not found", { status: 404 }));
    } catch (err: any) {
      return cors(error(err?.message || "server error", 500));
    }
  },
};

// --- Core helpers ---

async function loadMeta(env: Env): Promise<Meta> {
  if (cache.meta) return cache.meta;
  const key = env.META_KEY || "merkle-meta.json";
  const obj = await env.LAYERS.get(key);
  if (!obj) throw new Error("meta not found");
  const meta = JSON.parse(await obj.text()) as Meta;
  cache.meta = meta;
  return meta;
}

function effectiveClaimAmount(meta: Meta, env: Env): string {
  return meta.claimAmount || env.CLAIM_AMOUNT;
}

async function lookupIndex(address: string, env: Env): Promise<LookupEntry | null> {
  // Shard by first 2 bytes (4 hex chars) for manageable shard sizes.
  const shard = address.slice(2, 6); // e.g., "abcd"
  const prefix = env.LOOKUP_PREFIX || "lookup";
  const key = `${prefix}/${shard}.json`;
  const obj = await env.LOOKUP.get(key);
  if (!obj) return null;
  const entries = (await obj.json()) as LookupEntry[];
  // Linear scan is fine for moderate shard sizes; if shards are large, make them sorted and binary search.
  const found = entries.find((e) => e.address.toLowerCase() === address);
  return found || null;
}

async function buildProof(index: number, meta: Meta, env: Env): Promise<string[]> {
  let idx = index;
  let width = meta.leafCount;
  const proof: string[] = [];

  for (let layer = 0; layer < meta.layerFiles.length; layer++) {
    const siblingIdx = siblingIndex(idx, width);
    const offset = BigInt(siblingIdx) * 32n;
    const obj = await env.LAYERS.get(meta.layerFiles[layer], { range: { offset: Number(offset), length: 32 } });
    if (!obj) throw new Error(`missing layer data: ${meta.layerFiles[layer]} @ ${siblingIdx}`);
    const buf = await obj.arrayBuffer();
    proof.push(toHex(buf));

    idx = Math.floor(idx / 2);
    width = Math.floor((width + 1) / 2);
  }

  return proof;
}

function siblingIndex(idx: number, width: number): number {
  const sib = idx ^ 1;
  return sib < width ? sib : idx; // duplicate last node if odd count
}

// --- Response helpers ---

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function error(message: string, status: number): Response {
  return json({ error: message }, status);
}

function cors(res: Response): Response {
  const headers = new Headers(res.headers);
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("Access-Control-Allow-Methods", "GET,OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Content-Type");
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}

function toHex(buf: ArrayBuffer): string {
  const view = new Uint8Array(buf);
  let out = "0x";
  for (let i = 0; i < view.length; i++) {
    out += view[i].toString(16).padStart(2, "0");
  }
  return out;
}
