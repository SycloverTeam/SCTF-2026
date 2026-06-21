#!/usr/bin/env python3
import argparse
import subprocess
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Poseidon Merkle data and optional Groth16 input JSON.")
    parser.add_argument("p")
    parser.add_argument("q")
    parser.add_argument("m")
    parser.add_argument("--input", help="write circuit input JSON to this path")
    args = parser.parse_args()

    helper = Path(__file__).with_name("poseidon_helper.js")
    cmd = ["node", str(helper), args.p, args.q, args.m]
    if args.input:
        cmd.extend(["--input", args.input])
    subprocess.run(cmd, check=True)


if __name__ == "__main__":
    main()
