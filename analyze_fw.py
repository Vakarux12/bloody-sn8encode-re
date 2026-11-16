import sys, collections
def blocks(p):
    d = open(p,'rb').read()
    return d, [d[i:i+16] for i in range(0, len(d)//16*16, 16)]
for p in sys.argv[1:]:
    d, bl = blocks(p)
    c = collections.Counter(bl)
    sig = bl[0]
    nhead = next((i for i,b in enumerate(bl) if b != sig), None)
    top = c.most_common(3)
    trailer = d[len(bl)*16:]
    print(f"{p.split('/')[-1]}: {len(d)} bytes, {len(bl)} blocks, trailer={trailer.hex()}")
    print(f"  sig(block0)={sig.hex()}  head_repeat={nhead}")
    for b,n in top: print(f"  x{n:<5} {b.hex()}")
# cross-file block overlap for same family (bank variants)
if len(sys.argv) > 2:
    sets = [set(blocks(p)[1]) for p in sys.argv[1:]]
    common = set.intersection(*sets)
    print(f"blocks common to all {len(sys.argv)-1} files: {len(common)}")
