# secmsg

**secmsg** – a lightweight encrypted message relay, based on a layered cryptographic stack.

## What this is
secmsg is a minimal, ICB/IRC-inspired messaging relay designed for terminal use and end-to-end encrypted payloads.
The server (`secmsgd`) is intentionally “dumb”: it routes opaque ciphertext frames and never decrypts message bodies.

## Quick start (OpenBSD)
Assuming you have Perl available (base) and a working toolchain:

```sh
# from repo root
perl -Ilib bin/secmsgd -l 127.0.0.1 -p 7337
```

In another terminal:

```sh
perl -Ilib bin/secmsg -s 127.0.0.1:7337 -u alice
```

And another:

```sh
perl -Ilib bin/secmsg -s 127.0.0.1:7337 -u bob
```

Then type messages like:

```
/msg bob hello there
```

## Protocol
For the initial POC we use **Base64 line frames**:

```
<TYPE> SP <VERSION> SP <BASE64(BYTES)> LF
```

See `doc/protocol.md` and `doc/man/*`.

## Status
- v0.0 scaffold: framing + minimal relay + minimal client I/O.
- Crypto and robust auth are intentionally not implemented yet.
