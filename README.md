# Check it yourself: the FinalBoss gate run of November 18, 2026

This is the record behind "The kernel said no. 1,600 times. 0 escapes."
100 fresh cloud machines, Ubuntu 24.04 with its own 6.8 kernel. The FinalBoss gate installed with one command on each,
then attacked: a scripted kernel test on every machine, and live AI agents behind the gate's sidecar.

You do not have to trust us for any of it. Everything below runs on your machine, offline, in about two seconds.

## Run it

You need Python 3.9 or newer.

```
pip install -U cryptography
python3 check.py
```

Add `--cases` to see every case on every machine.

`cryptography` is the standard open-source Python library. It does both signature checks: Ed25519 (classical) and
ML-DSA-87 (post-quantum, FIPS 204). `check.py` is short on purpose. Read it before you run it.

## What you should see

```
1. Record list SHA-256: d5343bf00c09ed29a7be30aa6551fcc1fbd6c702437522df3a02853fd0fa81d1
   Printed on finalbosstech.com/proof-sheet for the Nov 18 run: d5343bf00c09ed29a7be30aa6551fcc1fbd6c702437522df3a02853fd0fa81d1  -> SAME
   Files here: 101, all in the list and matching: YES (114 in the list are not shipped: the test PC's own consoles, logs and per-machine driver files)
2. Machines: 100
   Receipts: 2223 | bad hash 0 | bad Ed25519 0 | bad ML-DSA-87 0 | chain breaks 0
   Decisions: ALLOW 501, DENY 1221 | connections through 501 (without an ALLOW receipt first: 0) | refused 1221 (without a receipt: 0)
3. Kernel test: 2100 scored cases, 2100 passed | 1600 moves the kernel had to stop, 1600 stopped | 300 moves with a permit, 300 went through | escapes 0

CHECK=PASS
```

## What each step shows

1. **These are the files we fingerprinted on November 18.** The record list's SHA-256 has been printed on
   finalbosstech.com/proof-sheet for this run. The checker compares it, then checks every file here against that list.
   Change one byte anywhere and step 1 says so.
2. **Every receipt is whole and signed twice.** For all 2,223 receipts: the SHA-256 hash, the Ed25519 signature, the
   ML-DSA-87 signature, and the chain from each receipt to the one before it. Then: every connection that went through had
   an ALLOW receipt first, and every refused connection has its receipt.
3. **The 1,600.** Each machine's kernel test, case by case: what was tried, what had to happen, what happened.
   `CASES.md` lists all 23 cases, word for word from the records.

How a receipt is signed: `body` is the receipt without `hash` and `signature_ed25519`; `canon` is JSON with sorted keys,
no spaces, UTF-8. `hash` = SHA-256 of canon(body). `signature_ed25519` = Ed25519 over canon(body).
`signature_pq` = ML-DSA-87 over canon(body without `signature_pq`). Each machine's two public keys are in its record.

Test build. No hardware attestation on these machines.

## What is in here

| Path | What it is |
|---|---|
| `check.py` | The checker |
| `CASES.md` | Every case of the kernel test, with its result on 100 machines |
| `record/SHA256SUMS.txt` | The record list of November 18 (its fingerprint is on the proof sheet) |
| `record/run/HUND_SUMMARY.json` | The run summary (its fingerprint is on the proof sheet too) |
| `record/box_out/NNN_a1_out_nokeys.tgz` | One machine's record each, 100 in all: receipts, connections, public keys, kernel test, logs. Private keys are not in here. |
| `BUNDLE_SHA256SUMS.txt` | The fingerprint of every file in this folder |

Questions, or the full records under NDA: abraham@finalbosstech.com. FinalBoss Technology Inc. No receipt, no run.
