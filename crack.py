#!/usr/bin/env python3
# Structural swing at T:  C = M.P (+) K_family   (affine over GF(2), 16B ECB).
# Known plaintext = erased fill (block 0 = sig). Question: can M be recovered?
import sys, glob, collections

def blocks(p):
    d=open(p,'rb').read(); n=len(d)//16
    return [d[i*16:i*16+16] for i in range(n)]

def lanes(b):  # 4 big-chunks as hex
    return [b[i:i+4].hex() for i in range(0,16,4)]
def xreg(a,b): return bytes(x^y for x,y in zip(a,b))
def lane_periodic(b): return b[0:4]==b[4:8]==b[8:12]==b[12:16]
def byte_periodic(b): return len(set(b))==1

files=sorted(glob.glob('extract/program files/Bloody7/FW/**/*.sn8encode5',recursive=True)) \
    + sorted(glob.glob('fw_acir/*.sn8encode5')) + sorted(glob.glob('issue_zip/*.sn8encode5'))
print(f"{len(files)} .sn8encode5 images\n")

sigs={}; second={}; UNI=collections.Counter()
delta_set=collections.Counter()
for f in files:
    bl=blocks(f)
    if not bl: continue
    c=collections.Counter(bl)
    sig=bl[0]
    # 2nd most common distinct from sig
    top=[b for b,_ in c.most_common(6) if b!=sig]
    sigs[f]=sig
    # inter-lane delta of sig (should be universal (0,d1,d2,d3))
    d=(xreg(sig[4:8],sig[0:4]).hex(),xreg(sig[8:12],sig[0:4]).hex(),xreg(sig[12:16],sig[0:4]).hex())
    delta_set[d]+=1
    if top:
        second[f]=top[0]
        UNI[xreg(sig,top[0]).hex()]+=1

print("=== sig inter-lane deltas (want ONE universal (d1,d2,d3)) ===")
for d,n in delta_set.most_common(5): print(f"  x{n:<4} {d}")

print("\n=== U = sig XOR 2nd-common-block  (want ONE universal U) ===")
for u,n in UNI.most_common(6): print(f"  x{n:<4} {u}")

# pick dominant U, test its structure
U=bytes.fromhex(UNI.most_common(1)[0][0])
print(f"\nU dominant = {U.hex()}")
print(f"  lane_periodic(U)? {lane_periodic(U)}   byte_periodic(U)? {byte_periodic(U)}")
print(f"  => M bytewise-identical (H1)? {'possible' if byte_periodic(U) else 'REJECTED (U not byte-periodic)'}")

# pairwise sig XOR lane-periodic? sample across distinct families
fam=sorted(set(sigs.values()))
print(f"\n{len(fam)} distinct family signatures")
import itertools
lp=all(lane_periodic(xreg(a,b)) for a,b in itertools.islice(itertools.combinations(fam,2),200))
print(f"  all sampled pairwise sig-XOR lane-periodic (broadcast key)? {lp}")

# Known-plaintext dimensionality:
# we KNOW exactly one plaintext value: fill=FF*16 -> sig. Second anchor Z's plaintext
# value is UNKNOWN (only that it's universal). So independent KNOWN-value anchors = 1.
print("\n=== verdict ===")
print("known-plaintext VALUES available: 1 (erased fill 0xFF*16 -> block0 sig)")
print("M unknowns (128x128 GF(2) matrix): 16384 bits")
print("anchors from ciphertext-only universals pin M.fill and M.(fill^Pz), but Pz value unknown")
print("=> M under-determined by 16384-128 ; recovery impossible from this data.")
