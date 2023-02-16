#!/usr/bin/env python3
# -*- coding=utf-8 -*-

'''
SET DOWNURL=...
python -c "import urllib.request;HTTPGET=urllib.request.urlopen;exec(HTTPGET('%DOWNURL%').read().decode('utf-8'))"
'''


import os, sys, lzma, platform, urllib.request

# https://docs.python.org/3/library/platform.html?highlight=is_64bits#platform.architecture
IS64BITS = bool(sys.maxsize > 2**32)

HTTPGET = urllib.request.urlopen

EXTRACT = lambda target, data: \
    open(os.path.splitext(target)[0], "wb").write(lzma.decompress(data))


''' frida-server '''
SERVER_MACHINE = dict({
    "amd64": "x86_64",
}).get(platform.machine().lower(), platform.machine().lower())
SERVER_TARGET = dict({
    "windows": "frida-server-{tagVer}-windows-" + SERVER_MACHINE + ".exe",
    "linux": "frida-server-{tagVer}-linux-" + SERVER_MACHINE,
    "darwin": "frida-server-{tagVer}-macos-" + SERVER_MACHINE,
})[platform.system().lower()]


GITHUB_PROJ = "https://github.com/" + "frida/frida"
GITHUB_FILES = [
    SERVER_TARGET + ".xz",
]

res = HTTPGET( "/".join( [GITHUB_PROJ, "releases", "latest"] ) )
tagVer = str(res.url).split("tag/")[-1]

for program in GITHUB_FILES:
    target = program.format(tagVer=tagVer)

    downUrl = "/".join([GITHUB_PROJ, "releases", "download", tagVer, target])
    res = HTTPGET( downUrl )

    if 200 == res.status:
        EXTRACT(target, res.read()), print( "downloaded %s" % target)
    else:
        print( "downloading %s failed, %d" % (target, res.status ) )
