#!/usr/bin/env python3
"""check.py: check the FinalBoss gate run of 2026-11-18 yourself, offline.

Needs Python 3.9+ and the standard `cryptography` library (it carries both Ed25519 and ML-DSA-87):
    pip install -U cryptography
    python3 check.py

What it does, in order. Nothing is unpacked to disk and nothing is sent anywhere.
  1. Fingerprints record/SHA256SUMS.txt. Compare the value with the "Record list SHA-256" printed for the
     November 18 run on finalbosstech.com/proof-sheet. Then checks every file here against that list.
  2. Opens each machine's record (record/box_out/NNN_a1_out_nokeys.tgz) and checks every receipt:
     its hash, its Ed25519 signature, its ML-DSA-87 signature, and the chain from one receipt to the next.
     Then checks that every connection that went through had an ALLOW receipt first, and every refused one has a receipt.
  3. Reads each machine's kernel test (akern/STEP5_A_KERNEL.json) and counts every case: what was tried, what had to
     happen, what happened.
How a receipt is signed (read from the receipts themselves):
  body      = the receipt without "hash" and "signature_ed25519"
  canon(x)  = JSON with sorted keys, no spaces, UTF-8
  hash      = SHA-256 of canon(body);  signature_ed25519 = Ed25519 over canon(body)
  signature_pq = ML-DSA-87 over canon(body without "signature_pq")
"""
import base64, hashlib, json, pathlib, sys, tarfile
from collections import Counter

HERE = pathlib.Path(__file__).resolve().parent
REC = HERE / 'record'
PUBLISHED_RECORD_LIST = 'd5343bf00c09ed29a7be30aa6551fcc1fbd6c702437522df3a02853fd0fa81d1'


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def sha(b):
    return hashlib.sha256(b).hexdigest()


def main():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA87PublicKey
    except ImportError as e:
        sys.exit('This needs a cryptography library with ML-DSA: pip install -U cryptography  (%s)' % e)
    problems = []

    # 1. the record list, then every file against it
    listed = REC / 'SHA256SUMS.txt'
    fp = sha(listed.read_bytes())
    print('1. Record list SHA-256: %s' % fp)
    print('   Printed on finalbosstech.com/proof-sheet for the Nov 18 run: %s  -> %s' % (PUBLISHED_RECORD_LIST, 'SAME' if fp == PUBLISHED_RECORD_LIST else 'DIFFERENT'))
    if fp != PUBLISHED_RECORD_LIST: problems.append('record list fingerprint differs from the published one')
    want = {}
    for line in listed.read_text().splitlines():
        if line.strip():
            h, name = line.split('  ', 1); want[name] = h
    here = sorted(p.relative_to(REC).as_posix() for p in REC.rglob('*') if p.is_file() and p.name != 'SHA256SUMS.txt')
    bad = [n for n in here if want.get(n) != sha((REC / n).read_bytes())]
    print('   Files here: %d, all in the list and matching: %s (%d in the list are not shipped: the test PC\'s own consoles, logs and per-machine driver files)'
          % (len(here), 'YES' if not bad else 'NO %s' % bad[:3], len(set(want) - set(here))))
    if bad: problems.append('files that do not match the record list: %s' % bad[:5])

    # 2. receipts, machine by machine
    t = Counter(); cases = {}
    boxes = sorted((REC / 'box_out').glob('*_a1_out_nokeys.tgz'))
    for box in boxes:
        m = box.name[:3]
        with tarfile.open(box) as tf:
            read = lambda n: tf.extractfile('out/' + n).read()
            recs = [json.loads(l) for l in read('c1_live/sidecar/RECEIPTS.jsonl').decode().splitlines() if l.strip()]
            conns = [json.loads(l) for l in read('c1_live/sidecar/CONNECTIONS.jsonl').decode().splitlines() if l.strip()]
            ed_raw = base64.b64decode(read('c1_live/sidecar/SIDECAR_PUBKEY.b64').strip())
            pq_raw = base64.b64decode(read('c1_live/sidecar/SIDECAR_PUBKEY_MLDSA87.b64').strip())
            kernel = json.loads(read('akern/STEP5_A_KERNEL.json'))
        ed, pq = Ed25519PublicKey.from_public_bytes(ed_raw), MLDSA87PublicKey.from_public_bytes(pq_raw)
        prev = 'GENESIS'; by_hash = {}
        for r in recs:
            body = {k: v for k, v in r.items() if k not in ('hash', 'signature_ed25519')}
            pq_body = {k: v for k, v in body.items() if k != 'signature_pq'}
            t['receipts'] += 1; t[r.get('kind', '?') + ' ' + str(r.get('decision', ''))] += 1
            if sha(canon(body)) != r.get('hash'): t['bad hash'] += 1
            try: ed.verify(base64.b64decode(r['signature_ed25519']), canon(body))
            except Exception: t['bad Ed25519'] += 1
            try: pq.verify(base64.b64decode(r['signature_pq']), canon(pq_body))
            except Exception: t['bad ML-DSA-87'] += 1
            if r.get('prev') != prev: t['chain breaks'] += 1
            prev = r.get('hash'); by_hash[prev] = r
        for c in conns:
            r = by_hash.get(c.get('receipt'))
            if c.get('forwarded'):
                t['went through'] += 1
                if not r or r.get('decision') != 'ALLOW' or r.get('op') != c.get('op') or r.get('ts') > c.get('ts'): t['went through without an ALLOW receipt first'] += 1
            else:
                t['refused'] += 1
                if r is None and not str(c.get('why', '')).startswith(('RECEIPT_PATH_FAILED', 'UPSTREAM_CONNECT_FAILED')): t['refused without a receipt'] += 1
        # 3. the kernel test
        for c in kernel['cases']:
            k = cases.setdefault(c['id'], {'case': c['case'], 'expected': c['expected'], 'scored': c.get('scored'), 'got': Counter()})
            k['got'][c['got']] += 1
            if c.get('scored'):
                t['kernel cases scored'] += 1
                if c['status'] == 'PASS': t['kernel cases passed'] += 1
                if c['expected'] == 'DENIED': t['moves the kernel had to stop'] += 1; t['stopped'] += c['got'] == 'DENIED'
                if c['expected'] == 'DELIVERED': t['moves with a permit'] += 1; t['went through with a permit'] += c['got'] == 'DELIVERED'
        t['kernel escapes'] += len(kernel.get('escapes') or [])

    print('2. Machines: %d' % len(boxes))
    print('   Receipts: %d | bad hash %d | bad Ed25519 %d | bad ML-DSA-87 %d | chain breaks %d'
          % (t['receipts'], t['bad hash'], t['bad Ed25519'], t['bad ML-DSA-87'], t['chain breaks']))
    print('   Decisions: ALLOW %d, DENY %d | connections through %d (without an ALLOW receipt first: %d) | refused %d (without a receipt: %d)'
          % (t['DECISION ALLOW'], t['DECISION DENY'], t['went through'], t['went through without an ALLOW receipt first'], t['refused'], t['refused without a receipt']))
    print('3. Kernel test: %d scored cases, %d passed | %d moves the kernel had to stop, %d stopped | %d moves with a permit, %d went through | escapes %d'
          % (t['kernel cases scored'], t['kernel cases passed'], t['moves the kernel had to stop'], t['stopped'], t['moves with a permit'], t['went through with a permit'], t['kernel escapes']))
    for k in ('bad hash', 'bad Ed25519', 'bad ML-DSA-87', 'chain breaks', 'went through without an ALLOW receipt first', 'refused without a receipt', 'kernel escapes'):
        if t[k]: problems.append('%s: %d' % (k, t[k]))
    if t['kernel cases passed'] != t['kernel cases scored'] or t['stopped'] != t['moves the kernel had to stop']: problems.append('kernel cases not all as expected')
    if '--cases' in sys.argv:
        print('\nEvery case, every machine (id | what was tried | had to | what happened):')
        for cid, k in cases.items():
            print('  %-5s %s | %s | %s%s' % (cid, k['case'], k['expected'], ', '.join('%s on %d' % g for g in k['got'].items()), '' if k['scored'] else ' | not scored'))
    print('\nCHECK=%s' % ('PASS' if not problems else 'FAIL: ' + '; '.join(problems)))
    return 0 if not problems else 1


if __name__ == '__main__':
    sys.exit(main())
