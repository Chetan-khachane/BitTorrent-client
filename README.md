# PeerWire

PeerWire is a minimal BitTorrent client implemented from scratch in C++.  
The purpose of this project was to understand the BitTorrent protocol and distributed file transfer at a low level.

This is a learning-focused implementation, not a production-ready client.

---

## Features

- Bencode parser for `.torrent` files
- HTTP/HTTPS tracker communication
- Compact peer list parsing
- BitTorrent peer handshake (68-byte protocol message)
- Interested / Unchoke message handling
- Piece and block-based download scheduling (16 KB blocks)
- SHA-1 piece verification
- Multithreaded peer workers
- Basic multi-torrent management

---

## Technical Details

- Language: C++
- Networking: WinSock2 (TCP sockets)
- Hashing: SHA-1 (Wincrypt / OpenSSL)
- Concurrency: `std::thread`, mutex-based synchronization
- Platform: Windows (Visual Studio 2022, x64)

The implementation handles:

- Tracker requests and response parsing
- Peer connection lifecycle
- Piece state management (missing / downloading / complete)
- Block-level requests with offset tracking
- Disk writes at correct file offsets
- Verification of downloaded pieces against torrent metadata

---

## Limitations

PeerWire is intentionally minimal and has the following limitations:

- HTTP/HTTPS trackers only (no UDP tracker support)
- No DHT support
- No PEX (Peer Exchange)
- No magnet link support
- IPv4 only
- Limited failure recovery
- Not optimized for large public swarms
- Windows-focused build setup

It works reliably in controlled swarm environments and for protocol experimentation.

---

## Build

- Open the solution in Visual Studio 2022
- Select `Release | x64`
- Build Solution

---

## Status

The project builds successfully and demonstrates a working end-to-end download flow.  
It is kept as a completed systems-learning project rather than an actively maintained torrent client.
