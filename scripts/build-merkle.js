#!/usr/bin/env node
// Build Merkle layers and lookup shards from the shard manifest.
// Requires: node >=18, `npm install ethers`.

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { solidityPackedKeccak256, keccak256, concat } from "ethers";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---- CLI args ----
const args = parseArgs(process.argv.slice(2));
const manifestPath = path.resolve(args.manifest || "shards/manifest.txt");
const shardDir = path.resolve(args.shardDir || "shards");
const outDir = path.resolve(args.out || "out");
const lookupPrefix = args.lookupPrefix || "lookup";
const shardPrefixLength = Number(args.shardPrefixLength || 4); // first N hex chars after 0x for shard key
const lookupBufferSize = Number(args.lookupBufferSize || 1000); // entries per shard before flushing
const LOG_INTERVAL = Number(args.logInterval || 1_000_000); // log every N leaves

await fs.promises.mkdir(outDir, { recursive: true });

const layer0Path = path.join(outDir, "layer0.bin");
const lookupDir = path.join(outDir, lookupPrefix);
await fs.promises.mkdir(lookupDir, { recursive: true });

const leafStream = fs.createWriteStream(layer0Path);
const shardBuffers = new Map(); // prefix -> array of entry strings
const shardCounts = new Map(); // prefix -> total entries written
const usedShards = new Set(); // prefix keys seen
const flushPromises = [];

// ---- Pass 1: build leaves + lookup shards ----
let index = 0;
const startedAt = Date.now();
const manifestEntries = (await fs.promises.readFile(manifestPath, "utf8"))
  .trim()
  .split(/\r?\n/)
  .filter(Boolean);

for (const rel of manifestEntries) {
  const shardPath = path.join(shardDir, rel.trim());
  console.log(`Processing shard ${rel.trim()}...`);
  await processShardFile(shardPath);
}

await leafStreamEnd();
// Flush any pending lookup buffers, then close shards with trailing brackets.
for (const [prefix] of shardBuffers) {
  await flushShard(prefix);
}
for (const prefix of usedShards) {
  const fp = lookupFile(prefix);
  await fs.promises.appendFile(fp, "]");
}

const leafCount = index;
console.log(`Wrote layer0 with ${leafCount} leaves to ${layer0Path}`);

// ---- Build upper layers ----
const layerFiles = ["layer0.bin"];
let currentPath = layer0Path;
let width = leafCount;
let layer = 0;

while (width > 1) {
  const nextLayer = layer + 1;
  const nextPath = path.join(outDir, `layer${nextLayer}.bin`);
  await hashLayer(currentPath, width, nextPath);
  layerFiles.push(path.basename(nextPath));
  console.log(`Built layer${nextLayer} (${Math.floor((width + 1) / 2)} nodes)`);
  currentPath = nextPath;
  width = Math.floor((width + 1) / 2);
  layer = nextLayer;
}

const root = await readRoot(currentPath);
const meta = {
  root,
  leafCount,
  hashFn: "keccak256",
  leafEncoding: "abi.encodePacked(index,address)",
  pairOrdering: "sorted",
  layerFiles,
};
const metaPath = path.join(outDir, "merkle-meta.json");
await fs.promises.writeFile(metaPath, JSON.stringify(meta, null, 2));
console.log(`Wrote ${metaPath}`);

// ---- Functions ----

async function processShardFile(filePath) {
  const data = await fs.promises.readFile(filePath, "utf8");
  const lines = data.split(/\r?\n/);
  for (const line of lines) {
    const address = line.trim().toLowerCase();
    if (!address) continue;
    // Leaf hashes only index and address; contract enforces fixed drop size.
    const leafHex = solidityPackedKeccak256(["uint256", "address"], [index, address]);
    const leafBuf = Buffer.from(leafHex.slice(2), "hex");
    if (!leafStream.write(leafBuf)) await onceDrain(leafStream);

    // shard lookup by prefix
    const shardKey = address.slice(2, 2 + shardPrefixLength);
    queueLookup(shardKey, { address, index });
    index++;

    if (LOG_INTERVAL > 0 && index > 0 && index % LOG_INTERVAL === 0) {
      const elapsed = (Date.now() - startedAt) / 1000;
      const rate = (index / elapsed).toFixed(0);
      console.log(`Processed ${index.toLocaleString()} leaves (~${rate}/s)`);
    }
  }
}

function queueLookup(prefix, entry) {
  usedShards.add(prefix);
  let buf = shardBuffers.get(prefix);
  if (!buf) {
    buf = [];
    shardBuffers.set(prefix, buf);
  }
  buf.push(JSON.stringify(entry));
  if (buf.length >= lookupBufferSize) {
    // fire and forget flush; we await globally to keep sequence safe
    flushPromises.push(flushShard(prefix));
  }
}

async function flushShard(prefix) {
  const buf = shardBuffers.get(prefix);
  if (!buf || buf.length === 0) return;
  const filePath = lookupFile(prefix);
  const count = shardCounts.get(prefix) || 0;
  const prefixStr = count === 0 ? "[" : ",";
  const data = prefixStr + buf.join(",");
  await fs.promises.appendFile(filePath, data);
  shardCounts.set(prefix, count + buf.length);
  shardBuffers.set(prefix, []);
}

function lookupFile(prefix) {
  return path.join(lookupDir, `${prefix}.json`);
}

function onceDrain(stream) {
  return new Promise((resolve) => stream.once("drain", resolve));
}

async function leafStreamEnd() {
  await Promise.all(flushPromises);
  await new Promise((resolve, reject) => {
    leafStream.end((err) => (err ? reject(err) : resolve()));
  });
}

async function hashLayer(inputPath, width, outPath) {
  const fd = await fs.promises.open(inputPath, "r");
  const out = fs.createWriteStream(outPath);
  const left = Buffer.alloc(32);
  const right = Buffer.alloc(32);

  for (let i = 0; i < width; i += 2) {
    await fd.read(left, 0, 32, i * 32);
    if (i + 1 < width) {
      await fd.read(right, 0, 32, (i + 1) * 32);
    } else {
      right.set(left);
    }
    const parent = hashPair(left, right);
    if (!out.write(parent)) await onceDrain(out);
  }

  await fd.close();
  await new Promise((resolve, reject) => out.end((err) => (err ? reject(err) : resolve())));
}

function hashPair(a, b) {
  const left = Buffer.compare(a, b) <= 0 ? a : b;
  const right = left === a ? b : a;
  return Buffer.from(keccak256(concat([left, right])).slice(2), "hex");
}

async function readRoot(finalLayerPath) {
  const buf = Buffer.alloc(32);
  const fd = await fs.promises.open(finalLayerPath, "r");
  await fd.read(buf, 0, 32, 0);
  await fd.close();
  return "0x" + buf.toString("hex");
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith("--")) {
      const key = arg.slice(2);
      const val = argv[i + 1];
      out[key] = val;
      i++;
    }
  }
  return out;
}
