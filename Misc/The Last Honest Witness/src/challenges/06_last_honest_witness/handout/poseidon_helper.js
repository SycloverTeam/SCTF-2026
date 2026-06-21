#!/usr/bin/env node
const fs = require("fs");
const circomlibjs = require("circomlibjs");

const EXTERNAL_NULLIFIER = 48879n;
const LEAF_COUNT = 32;

function parseBigInt(value, name) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`missing ${name}`);
  }
  return BigInt(value);
}

function toDecimal(value) {
  return value.toString(10);
}

async function buildPrimitives() {
  const poseidon = await circomlibjs.buildPoseidon();
  const field = poseidon.F;
  const hash = (values) => BigInt(field.toString(poseidon(values)));

  return {
    commitment: (plaintext) => hash([1n, plaintext]),
    identitySecret: (plaintext, p, q) => hash([2n, plaintext, p, q, EXTERNAL_NULLIFIER]),
    leaf: (identity, commitment) => hash([3n, identity, commitment]),
    node: (left, right) => hash([4n, left, right]),
    nullifierHash: (identity) => hash([5n, identity, EXTERNAL_NULLIFIER]),
    emptyLeaf: (index) => hash([6n, BigInt(index), EXTERNAL_NULLIFIER]),
  };
}

async function merkleData(p, q, plaintext) {
  const h = await buildPrimitives();
  const activeIndex = Number((plaintext + p + q) % BigInt(LEAF_COUNT));
  const commitment = h.commitment(plaintext);
  const identitySecret = h.identitySecret(plaintext, p, q);
  const nullifierHash = h.nullifierHash(identitySecret);

  const leaves = Array.from({ length: LEAF_COUNT }, (_, index) => h.emptyLeaf(index));
  leaves[activeIndex] = h.leaf(identitySecret, commitment);

  const pathElements = [];
  const pathIndices = [];
  let pos = activeIndex;
  let level = leaves;
  while (level.length > 1) {
    const sibling = pos ^ 1;
    pathElements.push(level[sibling]);
    pathIndices.push(pos & 1);

    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(h.node(level[i], level[i + 1]));
    }
    level = next;
    pos = Math.floor(pos / 2);
  }

  return {
    activeIndex,
    commitment,
    identitySecret,
    nullifierHash,
    merkleRoot: level[0],
    pathElements,
    pathIndices,
    input: {
      p: toDecimal(p),
      q: toDecimal(q),
      plaintext: toDecimal(plaintext),
      pathElements: pathElements.map(toDecimal),
      pathIndices: pathIndices.map((x) => x.toString(10)),
      modulus: toDecimal(p * q),
      merkleRoot: toDecimal(level[0]),
      recipientCommitment: toDecimal(commitment),
      nullifierHash: toDecimal(nullifierHash),
      externalNullifier: toDecimal(EXTERNAL_NULLIFIER),
    },
  };
}

async function main() {
  const args = process.argv.slice(2);
  const outputIndex = args.indexOf("--input");
  const outputPath = outputIndex >= 0 ? args[outputIndex + 1] : null;
  const positional = args.filter((_, index) => index !== outputIndex && index !== outputIndex + 1);

  if (positional.length !== 3 || (outputIndex >= 0 && !outputPath)) {
    console.error("usage: poseidon_helper.js <p> <q> <plaintext> [--input input.json]");
    process.exit(1);
  }

  const p = parseBigInt(positional[0], "p");
  const q = parseBigInt(positional[1], "q");
  const plaintext = parseBigInt(positional[2], "plaintext");
  const data = await merkleData(p, q, plaintext);

  if (outputPath) {
    fs.writeFileSync(outputPath, JSON.stringify(data.input, null, 2) + "\n");
  }

  console.log(`activeIndex = ${data.activeIndex}`);
  console.log(`commitment = ${data.commitment}`);
  console.log(`identitySecret = ${data.identitySecret}`);
  console.log(`nullifierHash = ${data.nullifierHash}`);
  console.log(`merkleRoot = ${data.merkleRoot}`);
  console.log(`pathElements = [${data.pathElements.map(toDecimal).join(",")}]`);
  console.log(`pathIndices = [${data.pathIndices.join(",")}]`);
  if (outputPath) {
    console.log(`inputJson = ${outputPath}`);
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.stack || error.message);
    process.exit(1);
  });
}

module.exports = { EXTERNAL_NULLIFIER, buildPrimitives, merkleData };
