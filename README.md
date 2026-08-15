# GLINT

Encrypted personal storage that needs a passphrase **and** a hardware key to
open, splits its recovery key so no single loss is fatal, and depends on no
libraries at all.

Built for the small number of things that would genuinely hurt to lose or to
leak.

## Properties

- **Two factors that both matter.** The security key's secret is mixed into
  the key derivation, so without the key the encryption key does not exist.
  This is not a presence check an attacker skips by not running our code —
  the dry run proves it by showing the correct passphrase alone is refused.
- **Memory-hard derivation.** scrypt at up to N=2²⁰ costs ~1 GB per guess,
  which is what removes the GPU and ASIC advantage against your passphrase.
- **2-of-3 recovery.** The recovery key is Shamir-split; any two shares open
  the file with no passphrase and no hardware key. One share reveals nothing,
  and that is information-theoretic — no amount of compute changes it.
- **Cipher cascade.** ChaCha20 then AES-256-GCM under independent subkeys, so
  a break in one primitive is not a break of the file.
- **Any file size.** Chunked STREAM construction: truncation, reordering and
  chunk removal all fail authentication.
- **Post-quantum by construction.** Every key is symmetric. The token's PRF is
  HMAC-SHA256, not ECDSA, so nothing in the key path is quantum-vulnerable.
- **No dependencies.** Every primitive is here or in WebCrypto.

## Try it before you trust it

Serve the folder and open `selftest.html` — WebAuthn needs HTTPS or localhost:

```bash
python3 -m http.server 8000   # then http://localhost:8000/selftest.html
```

It enrols your key, seals a throwaway payload, and then opens it three ways:
passphrase + key, and each pair of recovery shares. It also checks the
failures: passphrase alone must be refused, and one share must open nothing.

**Run this before storing anything real.** An untested recovery path is
indistinguishable from no recovery path.

## Layers

```
passphrase ─→ scrypt (memory-hard)        kills GPU/ASIC guessing
                  │
security key ─→ PRF(salt) ─→ 32 bytes     key needs the physical token
                  │
            HKDF(both) = K_master         neither factor alone suffices
                  │
            wraps random K_data           re-key without re-encrypting
                  │
      ChaCha20 → AES-256-GCM              cascade under separate subkeys
                  │
            header as AAD                 blocks downgrade attacks
                  │
            Reed-Solomon (image mode)     bit rot ≠ data loss
```

Two details worth knowing:

**Cascade order is deliberate.** AES-GCM seals last, so on the way back
WebCrypto's hardware AES verifies the tag *before* any hand-written
JavaScript touches the bytes. The JS layer never processes unauthenticated
input.

**The header is authenticated.** Cost parameters, flags, nonce prefix and
length are fed as AAD to both the key wrapping and every chunk. Without this,
an attacker rewrites `N=2²⁰` to `N=2` and your own tool opens the file with a
trivially crackable key.

## Files

| File | Purpose |
| --- | --- |
| `container.js` | The `.glintbox` format: key slots, streaming cascade |
| `crypto.js` | scrypt and ChaCha20-Poly1305 (what WebCrypto lacks) |
| `shamir.js` | Secret sharing over GF(256) |
| `webauthn.js` | Hardware key material via the PRF extension |
| `glint.js` | Image transport: data in DCT blocks, Reed-Solomon protected |
| `selftest.html` | End-to-end dry run against a real key |

## Testing

```bash
node test/vectors.js     # RFC 7914 + RFC 8439 test vectors
node test/shamir.js      # secret sharing
node test/container.js   # round-trip, tamper, recovery
node test/bench.js       # throughput on your hardware
```

```bash
node test/image.js       # image codec round-trip
```

Current status: **2147 checks passing** — 10 official RFC vectors, 2111
Shamir checks, 21 container tests, 5 image tests. The PRF path is verified
against a Chrome virtual authenticator with `hasPrf` and confirmed on real
hardware (YubiKey 5), covering enrolment, determinism, salt separation,
seal, open, and both refusal cases.

Four bugs found this way, none of which a round-trip test would have caught,
because in each case the code agreed with itself:

- **Poly1305 with 26-bit limbs** overflows JavaScript's 53-bit floats and
  produces plausible but wrong tags. Only the RFC vectors caught it.
- **The header binding was documented but not implemented.** The downgrade
  test passed only because the edited profile was not on a whitelist.
- **The image encoder and decoder disagreed on framing.** The encoder wrote
  one continuous Reed-Solomon stream; the decoder read the header as a
  standalone codeword. Nothing decoded until the header got its own codeword.
- **Correction counts only reported the body.** Damage to the header was
  repaired silently, so a badly degraded image looked like a clean read.

A note on the hardware run: real YubiKey credential ids are 48 bytes, while
the virtual authenticator issued 32. The slot field is length-prefixed, so
this passed unnoticed — a hard-coded 32 would have worked perfectly in
emulation and corrupted every real file.

## Image transport, measured

`glint.js` hides the payload in mid-frequency DCT coefficients on JPEG's own
8×8 block grid, so quantisation blurs the signal instead of erasing it.
Measured with a real JPEG codec at 224×224 (parity 64, so 32 correctable
bytes per codeword):

| Channel | Result |
| --- | --- |
| JPEG quality 90 → 20 | recovered, **zero** corrections needed |
| Saved twice (q85 then q75) | recovered, zero corrections |
| Downscaled 50% and back | recovered, zero corrections |
| Top 18% blacked out | recovered, 31 corrections |
| 0.5% of pixels blown white | recovered, 44 corrections |
| JPEG quality 15 | lost |
| Top 36% blacked out | lost |
| 2% of pixels blown white | lost |
| Shifted by 3px | lost — the block grid must line up |

Two things worth knowing. **Contiguous damage is survivable; sprinkled damage
is worse than it looks** — a blown pixel perturbs its whole block, so noise
scattered at 2% touches nearly every codeword at once, which no amount of
interleaving fixes. And **the grid must be aligned**: a crop that is not a
multiple of 8 pixels destroys the payload, so this rides through
recompression but not through arbitrary cropping.

## Speed

Measured with `test/bench.js`; the KDF is a fixed cost per file, the ciphers
scale with size.

| Profile | scrypt | Memory | Cascade |
| --- | --- | --- | --- |
| `fast` | N=2¹⁴ | 16 MB | no |
| `strong` | N=2¹⁷ | 128 MB | yes |
| `paranoid` | N=2²⁰ | 1 GB | yes |

For small files the derivation dominates — a one-second unlock is the point,
not a defect. For large archives the cascade dominates: ChaCha20 runs around
275 MB/s here against hardware AES-GCM's 500+ MB/s.

## What this does not protect against

Stated plainly, because the layers above can create false confidence:

- **The browser is the weakest link.** Every guarantee assumes the code
  running is the code in this repo. XSS, a malicious extension, or a tampered
  page defeats all of it. For genuinely irreplaceable material, use this
  alongside something with a smaller trusted base (age, VeraCrypt), not
  instead of it.
- **JavaScript cannot promise constant time.** The scrypt and ChaCha here are
  timing-observable in principle. AES-256-GCM from WebCrypto — hardware-backed
  and constant-time — is therefore always in the chain, so this code only ever
  adds protection.
- **Losing enough factors is final.** Passphrase plus key, or two shares.
  Below that the data is gone, and nobody can recover it. That is the intended
  behaviour.
- **Not independently audited.** Standard primitives, verified against their
  published vectors, assembled carefully — but one author and no external
  review.

## Storing the shares

Put the three shares in three different failure domains. If two of them can
be destroyed by one fire, one theft, or one clear-out, the threshold is
decorative: keep them apart, and keep at least one away from the machine
holding the encrypted files.

## Licence

MIT — see [LICENSE](LICENSE).
