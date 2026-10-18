#!/usr/bin/env python3
"""Install an explicitly selected official helper; never execute its contents.

Only the intended executable is extracted, after checking the committed SHA256.
No archive paths, links, configuration or other files are written to the host.
"""
import argparse, hashlib, io, json, os, pathlib, platform, tarfile, tempfile, urllib.request, zipfile

def install(helper, arch, destination):
    locks=json.loads(pathlib.Path(__file__).with_name('helper-lock.json').read_text())
    item=locks[f'{helper}-linux-{arch}']
    request=urllib.request.Request(item['url'],headers={'User-Agent':'Arange-tun-helper-installer'})
    with urllib.request.urlopen(request,timeout=60) as response:
        data=response.read((200<<20)+1)
    if len(data)>200<<20 or hashlib.sha256(data).hexdigest()!=item['sha256']:
        raise ValueError('Helper archive checksum mismatch or size limit exceeded')
    name=item['executable']
    if item['url'].endswith('.zip'):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            matches=[m for m in archive.infolist() if pathlib.PurePosixPath(m.filename).name==name and not m.is_dir()]
            if len(matches)!=1 or matches[0].file_size>200<<20: raise ValueError('Invalid helper archive')
            binary=archive.read(matches[0])
    else:
        with tarfile.open(fileobj=io.BytesIO(data),mode='r:*') as archive:
            matches=[m for m in archive.getmembers() if pathlib.PurePosixPath(m.name).name==name and m.isfile()]
            if len(matches)!=1 or matches[0].size>200<<20: raise ValueError('Invalid helper archive')
            with archive.extractfile(matches[0]) as source: binary=source.read((200<<20)+1)
    if not binary.startswith(b'\x7fELF'): raise ValueError('Expected a Linux ELF executable')
    destination=pathlib.Path(destination).resolve();destination.mkdir(parents=True,exist_ok=True)
    fd,temp=tempfile.mkstemp(prefix=f'.{helper}-',dir=destination)
    try:
        with os.fdopen(fd,'wb') as out: out.write(binary);out.flush();os.fsync(out.fileno())
        os.chmod(temp,0o755);os.replace(temp,destination/name)
    finally:
        if os.path.exists(temp): os.unlink(temp)
    print(f"Installed {helper} {item['version']} at {destination/name} (SHA256 verified)")

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('helper',choices=['xray','sing-box','naive'])
    parser.add_argument('--arch',choices=['amd64','arm64'],default={'x86_64':'amd64','AMD64':'amd64','aarch64':'arm64','arm64':'arm64'}.get(platform.machine()))
    parser.add_argument('--destination',default='/usr/local/lib/arange-tun')
    args=parser.parse_args()
    if not args.arch: parser.error('specify --arch for this architecture')
    install(args.helper,args.arch,args.destination)
