#!/usr/bin/env python3
"""Extract public BCC vectors, never wallet data. Usage: extract-bcc-vectors.py bitconnect.zip

The pinned archive URL/checksum and independent block/address anchors are documented in
docs/BITCONNECT-VERIFICATION.md. JSON goes to stdout; diagnostics go to stderr.
This checks byte provenance/header linkage/Merkle roots, not full consensus validation.
"""
import zipfile,struct,hashlib,json,sys
from pathlib import Path
D=lambda b:hashlib.sha256(hashlib.sha256(b).digest()).digest()
def vi(b,p):
 n=b[p];p+=1
 if n<253:return n,p
 z={253:2,254:4,255:8}[n];return int.from_bytes(b[p:p+z],"little"),p+z
def tx(b,p):
 start=p;v,t=struct.unpack_from("<II",b,p);p+=8
 n,p=vi(b,p);ins=[]
 for _ in range(n):
  prev=b[p:p+32][::-1].hex();idx=int.from_bytes(b[p+32:p+36],"little");p+=36
  l,p=vi(b,p);sig=b[p:p+l];p+=l+4;ins.append((prev,idx,sig.hex()))
 n,p=vi(b,p);outs=[]
 for _ in range(n):
  a=int.from_bytes(b[p:p+8],"little");p+=8;l,p=vi(b,p);s=b[p:p+l];p+=l;outs.append((a,s.hex()))
 p+=4;raw=b[start:p];return p,dict(txid=D(raw)[::-1].hex(),raw=raw.hex(),version=v,time=t,inputs=ins,outputs=outs)
archive=Path(sys.argv[1])
with archive.open('rb') as f:
 digest=hashlib.sha256()
 for chunk in iter(lambda:f.read(1024*1024),b''):digest.update(chunk)
 assert digest.hexdigest()=='fa28f1c06e1ce1b4d66db10046806d4e4d71298e224e6a30412ca1b0ff183992'
known={};selected=[];found=False;previous=None;anchored=False
with zipfile.ZipFile(archive) as z:
 with z.open('bitconnect/blk0001.dat') as f:
  for index in range(10000):
   h=f.read(8)
   if not h:break
   assert h[:4]==bytes.fromhex('325e6f86')
   size=int.from_bytes(h[4:],'little');assert 80<=size<=1000000
   b=f.read(size);assert len(b)==size
   if previous is not None:assert b[4:36]==previous,index
   previous=hashlib.scrypt(b[:80],salt=b[:80],n=1024,r=1,p=1,dklen=32)
   if index==0:assert previous[::-1].hex()=='00000d3bd95c47fa17c47e1e2732d7072a6c4014a2fa93873124418a8fd9a300'
   n,p=vi(b,80);ts=[]
   for _ in range(n):
    p,t=tx(b,p);ts.append(t);known[t['txid']]=t
   hashes=[D(bytes.fromhex(t['raw'])) for t in ts]
   while len(hashes)>1:
    if len(hashes)%2:hashes.append(hashes[-1])
    hashes=[D(hashes[i]+hashes[i+1]) for i in range(0,len(hashes),2)]
   assert hashes[0]==b[36:68], index
   if index==0:
    print('genesis',ts[0]['txid'],file=sys.stderr);selected.append(dict(label='genesis',block_raw=b.hex(),block_txs=[x['raw'] for x in ts],**ts[0]))
   for t in ts:
    if not found and all(i[0] in known and known[i[0]]['outputs'][i[1]][1].startswith('76a914') and i[2] for i in t['inputs']):
     selected.append(dict(label='spend',block_raw=b.hex(),block_txs=[x['raw'] for x in ts],**t))
     for prev,idx,sig in t['inputs']:
      selected.append(dict(label='prevout',**known[prev]))
     print('first p2pkh spend',index,t['txid'],file=sys.stderr);found=True
   if any(t['txid']=='97536cabf065a9818448ee8566df1d2a0bdfb7e2e6d51f85084b912579bf81b4' for t in ts):
    bh=hashlib.scrypt(b[:80],salt=b[:80],n=1024,r=1,p=1,dklen=32)[::-1].hex()
    assert index==1337
    print('README anchor',index,bh,file=sys.stderr);anchored=True
    assert bh=='0000000000d9a46c3126e02b128234d38be28397b13363c9dedf1dbc177dc687'
    selected.append(dict(label='height1337',block_raw=b.hex(),block_txs=[x['raw'] for x in ts],**next(t for t in ts if t['txid']=='97536cabf065a9818448ee8566df1d2a0bdfb7e2e6d51f85084b912579bf81b4')))
    break
assert found and anchored
print(json.dumps(selected,indent=2))
