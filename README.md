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
- **Streams to disk.** Files are encrypted a chunk at a time and written
  straight out, so memory stays flat regardless of size — 512 MB streams with
  16 MB of memory growth. The STREAM construction means truncation,
  reordering and chunk removal all fail authentication.
- **Strong passphrases by default.** A built-in generator produces 90-bit
  passphrases with provable entropy, and anything under 40 bits is refused
  outright.
- **Checkable recovery shares.** Each share carries a checksum and a tag
  identifying its file, so a typo is caught immediately rather than at the
  moment you need it.
- **Post-quantum by construction.** Every key is symmetric. The token's PRF is
  HMAC-SHA256, not ECDSA, so nothing in the key path is quantum-vulnerable.
- **No dependencies.** Every primitive is here or in WebCrypto.

## Using it

Serve the folder — WebAuthn needs HTTPS or localhost, so opening the files
directly will not work:

```bash
python3 -m http.server 8000
```

- **http://localhost:8000/** — lock and unlock files
- **http://localhost:8000/selftest.html** — the dry run described below

The interface has four tabs. **Lock** encrypts a file or a typed message and
downloads a `.glintbox`, then shows the three recovery shares as text and as
QR codes (printable). **Unlock** takes a `.glintbox` and opens it with either
your passphrase and key, or any two recovery shares. **Image** hides an encrypted message
in a picture — either as a standalone code or inside a photo you supply.
**Speed** measures key derivation and cipher throughput on your own machine.

The original filename travels inside the encrypted payload, so it is not
visible on the sealed file either.

## Try it before you trust it

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
| `shamir.js` | Secret sharing over GF(256), plus share encoding |
| `passphrase.js` | Passphrase generation and strength estimation |
| `webauthn.js` | Hardware key material via the PRF extension |
| `glint.js` | Image transport: data in DCT blocks, Reed-Solomon protected |
| `selftest.html` | End-to-end dry run against a real key |
| `conceal.html` | Hide encrypted data inside a photograph |
| `index.html`, `app.js`, `app.css` | The interface |
| `qrcode.js` | QR encoder, for printing recovery shares |

## Testing

```bash
node test/vectors.js     # RFC 7914 + RFC 8439 test vectors
node test/shamir.js      # secret sharing
node test/container.js   # round-trip, tamper, recovery
node test/bench.js       # throughput on your hardware
```

```bash
node test/image.js       # image codec round-trip
node test/shares.js      # share checksums and file tags
node test/passphrase.js  # generator entropy and distribution
node test/stream.js      # streaming, format compatibility, memory
node test/coverage.js    # every suite is actually wired into CI
```

That last one exists because of a real failure: for two commits the workflow
ran four suites while seven were present, so CI was green while enforcing
2147 of 2188 checks. A missing test cannot fail, which makes it invisible in
a pass/fail signal. The guard turns an unwired suite into a build failure,
and it runs first.

The interface itself is driven end to end in a real browser with a virtual
authenticator: enrol, lock a file, unlock it with passphrase and key, unlock
it again with two recovery shares alone, and confirm a wrong passphrase is
refused — checking each time that the recovered bytes are identical to the
original.

Image mode is exercised in the browser too: a code is made, round-tripped
through canvas JPEG encoding at quality 90/70/50/30, and decoded back — plus
the same for a payload hidden in a carrier photo at quality 80.

Current status: **2188 checks passing** — 10 official RFC vectors, 2111
Shamir checks, 21 container tests, 9 image tests, 9 share tests, 13
passphrase tests, 15 streaming tests. The PRF path is verified
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

### Hiding data in a photograph

`conceal.html` is the focused tool for this: drop a photo, hide an encrypted
message or file inside it, and see exactly what changed before you save.

Two things keep it clean. **Perceptual masking** sets the amplitude per block
from how busy that block is — quiet in flat sky where the eye would notice,
louder in texture that hides it. And because the decoder only reads the *sign*
of each coefficient, any block that already has the right sign with enough
magnitude is **left completely untouched**, which is roughly half of them.

Measured on a 1024×768 image with a large flat sky, at the balanced setting:

| | Fixed amplitude | Masked + leave-alone |
| --- | --- | --- |
| Flat areas | mean 2.6, worst 8 | **mean 1.3, worst 5** |
| Textured areas | mean 4.2 | mean 4.8 (more signal where it hides) |
| PSNR | 35.5 dB | **39.2 dB** |
| Survives | JPEG q50 | **JPEG q40** |

Cleaner and more robust at once — the masking moves signal out of the places
that betray it and into places that both hide it better and compress better.

One honest limit: the worst single change in a nominally flat block was 16 of
255 on a dithered gradient. Flipping a coefficient that already leans the wrong
way means crossing zero, which costs its full magnitude plus the amplitude.
That is a property of sign-based encoding, not something tuning fixes. The
"Subtle" setting lowers it at the cost of needing a higher-quality save.

Capacity scales with the picture: about 2.2 KB in a 1024×768 image, about
35 KB in a 4000×3000 phone photo.

**This is concealment, not undetectability.** The payload is encrypted with
AES-256-GCM regardless, so the content is safe either way — but someone who
suspects a payload and runs statistics over the DCT coefficients will see the
modulation. It hides from a person looking at a photo, not from an analyst
looking for a payload.

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

## Passphrases

Every other layer defends a secret a human chose, so the generator matters
more than the cascade does. It builds words from syllables rather than a
dictionary — 16 consonants x 4 vowels = exactly 64 syllables = 6 bits each,
three syllables per word, five words = **90 bits**. Sampling is unbiased
because 64 divides 256 evenly.

A wordlist would be more memorable, but its entropy claim depends on the list
being exactly what it says it is. This claim is provable from the code, and
the tests check it: all 64 syllables appear, the distribution passes a
chi-square test, and 5000 generated passphrases produce no collisions.

The strength meter for typed passphrases is deliberately pessimistic and is
**an estimate, not a promise** — real attackers use dictionaries and leaked
corpora that no client-side function models well. Treat it as a floor.

## Recovery shares

Shares look like `GLINT1:` followed by 55 characters, and carry:

- a **CRC** over the bytes — every single-character typo is caught, verified
  across every position in the encoded string
- a **6-byte file tag** — identifies which file the share belongs to

The Unlock tab has a *Check a single share* tool that validates both. What it
cannot do is confirm a share is cryptographically valid: one share carries no
information about the secret, which is precisely the property that makes
splitting worthwhile. Only assembling two proves that.

Shares issued before checksums existed still decode, and are flagged as
uncheckable.

## Memory and large files

Where the browser can write a file directly (Chrome and Edge, via the File
System Access API), encryption streams: one chunk is held at a time and the
ciphertext goes to disk as it is produced. Measured by watching resident
memory while sealing 512 MB — **peak growth 16 MB**. You are asked where to
save before it starts.

In browsers without that API (Firefox, Safari), the parts are collected into
a Blob, which the browser can page to disk. Better than one contiguous
array, but still memory-hungry; the interface says so above 200 MB.

Both paths produce the same format: a streamed file opens with the buffered
reader and vice versa, which the tests check explicitly.

**Earlier versions of this README claimed "any file size, bounded only by
disk".** That described the format rather than the implementation, and was
untrue until streaming landed. The buffered path — still used by the
fallback — peaks at roughly four times the file size.

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
