# Offline self-check for the request/response framing and decoders, no hardware.
import os,sys; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bloody
class FakeDev:
    # Minimal mouse: echoes op, serves canned identity/backlight replies.
    def __init__(s): s.store={0x11:3}
    def set(s,buf): s.last=bytes(buf)
    def get(s):
        op=s.last[1]; out=bytearray(64); out[0]=7; out[1]=op
        if s.last[4]==0x80: s.store[op]=s.last[8]  # write
        if op==0x11: out[8]=s.store[0x11]
        if op==0x1f: out[10],out[11],out[12]=0xee,0x04,0x13
        if op==0x02:
            out[20],out[21]=0xec,0x04
            for i,v in enumerate(range(0x08,0x18)): out[24+2*i]=v; out[25+2*i]=0x81
            out[24+2*15+1]=0xff
        return bytes(out)

fake=FakeDev()
def fake_ioctl(fd,req,arg):
    if req==bloody._SF(64): fake.set(arg); return 0
    fake_out=bytearray(fake.get()); arg[:]=fake_out; return 0
bloody.fcntl.ioctl=fake_ioctl

r=bloody.xfer(0, 0x1f)
assert r[10]|(r[11]<<8)==0x04ee and r[12]==0x13, 'identity decode'
b=bloody.xfer(0, 0x02)
assert b[20]|(b[21]<<8)==0x04ec, 'fw code'
# backlight write round-trips through byte 4 = 0x80 and byte 8 = level
bloody.xfer(0, 0x11, bytes([2]), write=True)
# request framing: op in [1], write flag in [4], data at [8]
assert fake.last[0]==7 and fake.last[1]==0x11 and fake.last[4]==0x80 and fake.last[8]==2, 'framing'
assert bloody.xfer(0, 0x11)[8]==2, 'backlight write/read'
print('OK')
