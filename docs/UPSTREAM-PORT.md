# BackPack port provenance

Based on BackPack by Amin Mohammadi (AminMGMT)
https://github.com/AminMGMT/BackPack

Source commit: 132467bfdfb2698d74ada2992413e75bfccbfbd3
License: AGPL-3.0. Original additional notices are in BACKPACK-NOTICE.

Ported: direct layer-4 engine (TCP, Noise, WS, WSS), forwarding, admission
limits, HTTP/2 Naive and XHTTP/TLS / REALITY/Vision managed wrappers.
Adaptations: module imports, config dispatch, Linux MSS build tags, existing
metrics/framing, no transport fallback chains, secure direct default.
This is not the upstream layer-3 engine. No upstream logo is used.
