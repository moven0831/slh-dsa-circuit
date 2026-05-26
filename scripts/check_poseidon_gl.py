#!/usr/bin/env python3
"""Compare Circom Goldilocks Poseidon witness output against Plonky2 reference test
vectors (from 0xPolygonZero/plonky2 @ v1.1.0, plonky2/src/hash/poseidon.rs `test_vectors`).

Usage: python3 scripts/check_poseidon_gl.py <vector-name> <witness.json>
       where <vector-name> ∈ {zeros, range, neg_one, random}
       and  <witness.json> is the result of `snarkjs wtns export json`.

Exit code 0 on byte-for-byte match across all 12 output lanes, 1 otherwise.
"""
import json
import sys

# Plonky2 v1.1.0 reference vectors. Width=12, p = 2^64 - 2^32 + 1.
VECTORS = {
    "zeros": (
        [0] * 12,
        [0x3c18a9786cb0b359, 0xc4055e3364a246c3, 0x7953db0ab48808f4, 0xc71603f33a1144ca,
         0xd7709673896996dc, 0x46a84e87642f44ed, 0xd032648251ee0b3c, 0x1c687363b207df62,
         0xdf8565563e8045fe, 0x40f5b37ff4254dae, 0xd070f637b431067c, 0x1792b1c4342109d7],
    ),
    "range": (
        list(range(12)),
        [0xd64e1e3efc5b8e9e, 0x53666633020aaa47, 0xd40285597c6a8825, 0x613a4f81e81231d2,
         0x414754bfebd051f0, 0xcb1f8980294a023f, 0x6eb2a9e4d54a9d0f, 0x1902bc3af467e056,
         0xf045d5eafdc6021f, 0xe4150f77caaa3be5, 0xc9bfd01d39b50cce, 0x5c0a27fcb0e1459b],
    ),
    "neg_one": (
        # GoldilocksField NEG_ONE = p - 1 = 2^64 - 2^32 = 0xFFFFFFFF00000000.
        [0xFFFFFFFF00000000] * 12,
        [0xbe0085cfc57a8357, 0xd95af71847d05c09, 0xcf55a13d33c1c953, 0x95803a74f4530e82,
         0xfcd99eb30a135df1, 0xe095905e913a3029, 0xde0392461b42919b, 0x7d3260e24e81d031,
         0x10d3d0465d9deaa0, 0xa87571083dfc2a47, 0xe18263681e9958f8, 0xe28e96f1ae5e60d3],
    ),
    "random": (
        [0x8ccbbbea4fe5d2b7, 0xc2af59ee9ec49970, 0x90f7e1a9e658446a, 0xdcc0630a3ab8b1b8,
         0x7ff8256bca20588c, 0x5d99a7ca0c44ecfb, 0x48452b17a70fbee3, 0xeb09d654690b6c88,
         0x4a55d3a39c676a88, 0xc0407a38d2285139, 0xa234bac9356386d1, 0xe1633f2bad98a52f],
        [0xa89280105650c4ec, 0xab542d53860d12ed, 0x5704148e9ccab94f, 0xd3a826d4b62da9f5,
         0x8a7a6ca87892574f, 0xc7017e1cad1a674e, 0x1f06668922318e34, 0xa3b203bc8102676f,
         0xfcc781b0ce382bf2, 0x934c69ff3ed14ba5, 0x504688a5996e8f13, 0x401f3f2ed524a2ba],
    ),
}


def input_json(vector_name: str) -> str:
    """Build the Circom witness input JSON for a named vector."""
    inputs, _ = VECTORS[vector_name]
    return json.dumps({"state_in": [str(v) for v in inputs]})


def check(witness_path: str, vector_name: str) -> bool:
    """Compare lanes 0-11 of the witness to the reference output. Returns True on PASS."""
    _, expected = VECTORS[vector_name]
    w = json.load(open(witness_path))
    # Circom witness layout for PoseidonGlSmoke: w[0]=1, w[1..13]=state_out (public outputs).
    all_match = True
    print(f"=== {vector_name} ===")
    for i in range(12):
        actual = int(w[1 + i])
        ok = actual == expected[i]
        if not ok:
            all_match = False
        marker = "OK " if ok else "FAIL"
        print(f"  out[{i:2d}] = 0x{actual:016x}  (expected 0x{expected[i]:016x})  {marker}")
    print(f"{vector_name}: {'PASS' if all_match else 'FAIL'}\n")
    return all_match


def main() -> None:
    if len(sys.argv) < 2:
        sys.stderr.write("usage: check_poseidon_gl.py [emit <name> | check <name> <witness.json>]\n")
        sys.exit(2)
    cmd = sys.argv[1]
    if cmd == "emit":
        # Print just the input-JSON for the named vector (for piping into a witness call).
        print(input_json(sys.argv[2]))
    elif cmd == "check":
        ok = check(sys.argv[3], sys.argv[2])
        sys.exit(0 if ok else 1)
    else:
        sys.stderr.write(f"unknown command: {cmd}\n")
        sys.exit(2)


if __name__ == "__main__":
    main()
