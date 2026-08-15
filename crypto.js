/*
 * crypto.js — the primitives WebCrypto does not provide.
 *
 * scrypt (RFC 7914) for memory-hard key derivation, and ChaCha20-Poly1305
 * (RFC 8439) for the second cipher in the cascade. Both are verified against
 * their RFC test vectors in test/vectors.js.
 *
 * AES-256-GCM comes from WebCrypto and stays in the chain at all times: it is
 * hardware-accelerated and constant-time, which JavaScript cannot promise.
 * Treat everything in this file as an ADDITIONAL layer, never the only one.
 */
(function (global) {
  'use strict';

  var subtle = global.crypto.subtle;

  /* ----------------------------------------------------------- PBKDF2 */

  function pbkdf2Sha256(password, salt, iterations, length) {
    return subtle.importKey('raw', password, 'PBKDF2', false, ['deriveBits'])
      .then(function (key) {
        return subtle.deriveBits(
          { name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'SHA-256' },
          key,
          length * 8
        );
      })
      .then(function (bits) { return new Uint8Array(bits); });
  }

  /* ------------------------------------------------------------ scrypt */

  function salsa20_8(block) {
    var x = new Uint32Array(16);
    var i;
    for (i = 0; i < 16; i++) x[i] = block[i];

    function R(a, b) { return (a << b) | (a >>> (32 - b)); }

    for (i = 0; i < 8; i += 2) {
      // Column rounds.
      x[4] ^= R(x[0] + x[12], 7);   x[8] ^= R(x[4] + x[0], 9);
      x[12] ^= R(x[8] + x[4], 13);  x[0] ^= R(x[12] + x[8], 18);
      x[9] ^= R(x[5] + x[1], 7);    x[13] ^= R(x[9] + x[5], 9);
      x[1] ^= R(x[13] + x[9], 13);  x[5] ^= R(x[1] + x[13], 18);
      x[14] ^= R(x[10] + x[6], 7);  x[2] ^= R(x[14] + x[10], 9);
      x[6] ^= R(x[2] + x[14], 13);  x[10] ^= R(x[6] + x[2], 18);
      x[3] ^= R(x[15] + x[11], 7);  x[7] ^= R(x[3] + x[15], 9);
      x[11] ^= R(x[7] + x[3], 13);  x[15] ^= R(x[11] + x[7], 18);
      // Row rounds.
      x[1] ^= R(x[0] + x[3], 7);    x[2] ^= R(x[1] + x[0], 9);
      x[3] ^= R(x[2] + x[1], 13);   x[0] ^= R(x[3] + x[2], 18);
      x[6] ^= R(x[5] + x[4], 7);    x[7] ^= R(x[6] + x[5], 9);
      x[4] ^= R(x[7] + x[6], 13);   x[5] ^= R(x[4] + x[7], 18);
      x[11] ^= R(x[10] + x[9], 7);  x[8] ^= R(x[11] + x[10], 9);
      x[9] ^= R(x[8] + x[11], 13);  x[10] ^= R(x[9] + x[8], 18);
      x[12] ^= R(x[15] + x[14], 7); x[13] ^= R(x[12] + x[15], 9);
      x[14] ^= R(x[13] + x[12], 13);x[15] ^= R(x[14] + x[13], 18);
    }
    for (i = 0; i < 16; i++) block[i] = (block[i] + x[i]) >>> 0;
  }

  function blockMix(input, output, r) {
    var X = new Uint32Array(16);
    var i, j;
    X.set(input.subarray((2 * r - 1) * 16, 2 * r * 16));
    for (i = 0; i < 2 * r; i++) {
      for (j = 0; j < 16; j++) X[j] ^= input[i * 16 + j];
      salsa20_8(X);
      // Even blocks land in the first half, odd blocks in the second.
      var target = (i % 2 === 0 ? i / 2 : r + (i - 1) / 2) * 16;
      output.set(X, target);
    }
  }

  function romix(block, N, r) {
    var blockWords = 32 * r;
    var V = new Uint32Array(blockWords * N);
    var X = new Uint32Array(block);
    var Y = new Uint32Array(blockWords);
    var i;

    for (i = 0; i < N; i++) {
      V.set(X, i * blockWords);
      blockMix(X, Y, r);
      X.set(Y);
    }
    for (i = 0; i < N; i++) {
      var j = X[(2 * r - 1) * 16] >>> 0;
      j = j % N;
      for (var k = 0; k < blockWords; k++) X[k] ^= V[j * blockWords + k];
      blockMix(X, Y, r);
      X.set(Y);
    }
    block.set(X);
  }

  /**
   * scrypt(password, salt, N, r, p, dkLen) -> Promise<Uint8Array>
   * N must be a power of two. Memory used is roughly 128 * N * r bytes.
   */
  function scrypt(password, salt, N, r, p, dkLen) {
    if (N < 2 || (N & (N - 1)) !== 0) throw new Error('scrypt: N must be a power of 2');
    var blockLen = 128 * r;
    return pbkdf2Sha256(password, salt, 1, p * blockLen).then(function (B) {
      var words = new Uint32Array(B.buffer, B.byteOffset, B.byteLength / 4);
      for (var i = 0; i < p; i++) {
        var slice = words.subarray(i * blockLen / 4, (i + 1) * blockLen / 4);
        var copy = new Uint32Array(slice);
        romix(copy, N, r);
        slice.set(copy);
      }
      return pbkdf2Sha256(password, new Uint8Array(words.buffer, words.byteOffset, words.byteLength), 1, dkLen);
    });
  }

  /* --------------------------------------------------------- ChaCha20 */

  // The state lives in local variables rather than an array: V8 keeps these
  // in registers, and the quarter-rounds are written out in full so no
  // closures are allocated per block. Both matter enormously here — this
  // function runs once per 64 bytes.
  var CHACHA_KEY = new Uint32Array(8);
  var CHACHA_NONCE = new Uint32Array(3);

  function chachaBlock(key32, counter, nonce12, out) {
    var i;
    for (i = 0; i < 8; i++) {
      CHACHA_KEY[i] = key32[i * 4] | (key32[i * 4 + 1] << 8) |
        (key32[i * 4 + 2] << 16) | (key32[i * 4 + 3] << 24);
    }
    for (i = 0; i < 3; i++) {
      CHACHA_NONCE[i] = nonce12[i * 4] | (nonce12[i * 4 + 1] << 8) |
        (nonce12[i * 4 + 2] << 16) | (nonce12[i * 4 + 3] << 24);
    }

    var j0 = 0x61707865, j1 = 0x3320646e, j2 = 0x79622d32, j3 = 0x6b206574;
    var j4 = CHACHA_KEY[0], j5 = CHACHA_KEY[1], j6 = CHACHA_KEY[2], j7 = CHACHA_KEY[3];
    var j8 = CHACHA_KEY[4], j9 = CHACHA_KEY[5], j10 = CHACHA_KEY[6], j11 = CHACHA_KEY[7];
    var j12 = counter >>> 0;
    var j13 = CHACHA_NONCE[0], j14 = CHACHA_NONCE[1], j15 = CHACHA_NONCE[2];

    var x0 = j0, x1 = j1, x2 = j2, x3 = j3, x4 = j4, x5 = j5, x6 = j6, x7 = j7;
    var x8 = j8, x9 = j9, x10 = j10, x11 = j11, x12 = j12, x13 = j13, x14 = j14, x15 = j15;
    var t;

    for (i = 0; i < 10; i++) {
      x0 = (x0 + x4) | 0;  t = x12 ^ x0;  x12 = (t << 16) | (t >>> 16);
      x8 = (x8 + x12) | 0; t = x4 ^ x8;   x4 = (t << 12) | (t >>> 20);
      x0 = (x0 + x4) | 0;  t = x12 ^ x0;  x12 = (t << 8) | (t >>> 24);
      x8 = (x8 + x12) | 0; t = x4 ^ x8;   x4 = (t << 7) | (t >>> 25);

      x1 = (x1 + x5) | 0;  t = x13 ^ x1;  x13 = (t << 16) | (t >>> 16);
      x9 = (x9 + x13) | 0; t = x5 ^ x9;   x5 = (t << 12) | (t >>> 20);
      x1 = (x1 + x5) | 0;  t = x13 ^ x1;  x13 = (t << 8) | (t >>> 24);
      x9 = (x9 + x13) | 0; t = x5 ^ x9;   x5 = (t << 7) | (t >>> 25);

      x2 = (x2 + x6) | 0;   t = x14 ^ x2;  x14 = (t << 16) | (t >>> 16);
      x10 = (x10 + x14) | 0; t = x6 ^ x10; x6 = (t << 12) | (t >>> 20);
      x2 = (x2 + x6) | 0;   t = x14 ^ x2;  x14 = (t << 8) | (t >>> 24);
      x10 = (x10 + x14) | 0; t = x6 ^ x10; x6 = (t << 7) | (t >>> 25);

      x3 = (x3 + x7) | 0;   t = x15 ^ x3;  x15 = (t << 16) | (t >>> 16);
      x11 = (x11 + x15) | 0; t = x7 ^ x11; x7 = (t << 12) | (t >>> 20);
      x3 = (x3 + x7) | 0;   t = x15 ^ x3;  x15 = (t << 8) | (t >>> 24);
      x11 = (x11 + x15) | 0; t = x7 ^ x11; x7 = (t << 7) | (t >>> 25);

      x0 = (x0 + x5) | 0;   t = x15 ^ x0;  x15 = (t << 16) | (t >>> 16);
      x10 = (x10 + x15) | 0; t = x5 ^ x10; x5 = (t << 12) | (t >>> 20);
      x0 = (x0 + x5) | 0;   t = x15 ^ x0;  x15 = (t << 8) | (t >>> 24);
      x10 = (x10 + x15) | 0; t = x5 ^ x10; x5 = (t << 7) | (t >>> 25);

      x1 = (x1 + x6) | 0;   t = x12 ^ x1;  x12 = (t << 16) | (t >>> 16);
      x11 = (x11 + x12) | 0; t = x6 ^ x11; x6 = (t << 12) | (t >>> 20);
      x1 = (x1 + x6) | 0;   t = x12 ^ x1;  x12 = (t << 8) | (t >>> 24);
      x11 = (x11 + x12) | 0; t = x6 ^ x11; x6 = (t << 7) | (t >>> 25);

      x2 = (x2 + x7) | 0;  t = x13 ^ x2;  x13 = (t << 16) | (t >>> 16);
      x8 = (x8 + x13) | 0; t = x7 ^ x8;   x7 = (t << 12) | (t >>> 20);
      x2 = (x2 + x7) | 0;  t = x13 ^ x2;  x13 = (t << 8) | (t >>> 24);
      x8 = (x8 + x13) | 0; t = x7 ^ x8;   x7 = (t << 7) | (t >>> 25);

      x3 = (x3 + x4) | 0;  t = x14 ^ x3;  x14 = (t << 16) | (t >>> 16);
      x9 = (x9 + x14) | 0; t = x4 ^ x9;   x4 = (t << 12) | (t >>> 20);
      x3 = (x3 + x4) | 0;  t = x14 ^ x3;  x14 = (t << 8) | (t >>> 24);
      x9 = (x9 + x14) | 0; t = x4 ^ x9;   x4 = (t << 7) | (t >>> 25);
    }

    var words = out;
    words[0] = (x0 + j0) >>> 0;    words[1] = (x1 + j1) >>> 0;
    words[2] = (x2 + j2) >>> 0;    words[3] = (x3 + j3) >>> 0;
    words[4] = (x4 + j4) >>> 0;    words[5] = (x5 + j5) >>> 0;
    words[6] = (x6 + j6) >>> 0;    words[7] = (x7 + j7) >>> 0;
    words[8] = (x8 + j8) >>> 0;    words[9] = (x9 + j9) >>> 0;
    words[10] = (x10 + j10) >>> 0; words[11] = (x11 + j11) >>> 0;
    words[12] = (x12 + j12) >>> 0; words[13] = (x13 + j13) >>> 0;
    words[14] = (x14 + j14) >>> 0; words[15] = (x15 + j15) >>> 0;
  }

  function chacha20(key, nonce, counter, data) {
    var out = new Uint8Array(data.length);
    var keystream = new Uint8Array(64);
    var words = new Uint32Array(keystream.buffer);
    // chachaBlock writes 16 little-endian words; on a big-endian host the
    // byte view would disagree, so serialise explicitly there.
    var littleEndian = new Uint8Array(new Uint32Array([1]).buffer)[0] === 1;
    if (!littleEndian) throw new Error('big-endian host unsupported');
    var length = data.length;
    var i = 0, j;

    // XOR a word at a time where alignment allows; the per-byte loop below
    // costs roughly four times as much.
    var wholeBlocks = length & ~63;
    if (wholeBlocks > 0 && (data.byteOffset & 3) === 0) {
      var dataWords = new Uint32Array(data.buffer, data.byteOffset, wholeBlocks >>> 2);
      var outWords = new Uint32Array(out.buffer, 0, wholeBlocks >>> 2);
      for (; i < wholeBlocks; i += 64) {
        chachaBlock(key, counter + (i / 64), nonce, words);
        var base = i >>> 2;
        for (j = 0; j < 16; j++) outWords[base + j] = dataWords[base + j] ^ words[j];
      }
    }

    for (; i < length; i += 64) {
      chachaBlock(key, counter + (i / 64), nonce, words);
      var chunk = Math.min(64, length - i);
      for (j = 0; j < chunk; j++) out[i + j] = data[i + j] ^ keystream[j];
    }
    return out;
  }

  /* --------------------------------------------------------- Poly1305 */

  // Follows the NaCl reference implementation: the accumulator is 17 bytes
  // and every intermediate stays under 2^29, which keeps JavaScript's 53-bit
  // floats exact. (A 26-bit limb version overflows and silently corrupts.)

  function polyAdd(h, c) {
    var u = 0;
    for (var j = 0; j < 17; j++) {
      u += h[j] + c[j];
      h[j] = u & 255;
      u >>>= 8;
    }
  }

  function polySqueeze(h) {
    var u = 0, j;
    for (j = 0; j < 16; j++) { u += h[j]; h[j] = u & 255; u >>>= 8; }
    u += h[16]; h[16] = u & 3;
    u = 5 * (u >>> 2);
    for (j = 0; j < 16; j++) { u += h[j]; h[j] = u & 255; u >>>= 8; }
    u += h[16]; h[16] = u;
  }

  var MINUS_P = [5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252];

  function polyFreeze(h) {
    var original = h.slice();
    polyAdd(h, MINUS_P);
    var negative = -(h[16] >>> 7);
    for (var j = 0; j < 17; j++) h[j] ^= negative & (original[j] ^ h[j]);
  }

  function polyMulmod(h, r) {
    var product = new Int32Array(17);
    for (var i = 0; i < 17; i++) {
      var u = 0, j;
      for (j = 0; j <= i; j++) u += h[j] * r[i - j];
      for (j = i + 1; j < 17; j++) u += 320 * h[j] * r[i + 17 - j];
      product[i] = u;
    }
    for (var k = 0; k < 17; k++) h[k] = product[k];
    polySqueeze(h);
  }

  function poly1305(key, message) {
    var r = new Int32Array(17);
    var h = new Int32Array(17);
    var c = new Int32Array(17);
    var j;

    for (j = 0; j < 16; j++) r[j] = key[j];
    r[3] &= 15; r[4] &= 252; r[7] &= 15; r[8] &= 252;
    r[11] &= 15; r[12] &= 252; r[15] &= 15; r[16] = 0;

    var offset = 0;
    var remaining = message.length;
    while (remaining > 0) {
      for (j = 0; j < 17; j++) c[j] = 0;
      for (j = 0; j < 16 && j < remaining; j++) c[j] = message[offset + j];
      c[j] = 1;
      offset += j;
      remaining -= j;
      polyAdd(h, c);
      polyMulmod(h, r);
    }

    polyFreeze(h);
    for (j = 0; j < 16; j++) c[j] = key[j + 16];
    c[16] = 0;
    polyAdd(h, c);

    var tag = new Uint8Array(16);
    for (j = 0; j < 16; j++) tag[j] = h[j] & 255;
    return tag;
  }

  /* ------------------------------------------- ChaCha20-Poly1305 AEAD */

  function pad16(length) { return length % 16 === 0 ? 0 : 16 - (length % 16); }

  function aeadTag(key, nonce, aad, ciphertext) {
    var polyKey = chacha20(key, nonce, 0, new Uint8Array(32));
    var aadPad = pad16(aad.length);
    var ctPad = pad16(ciphertext.length);
    var message = new Uint8Array(aad.length + aadPad + ciphertext.length + ctPad + 16);
    var at = 0;
    message.set(aad, at); at += aad.length + aadPad;
    message.set(ciphertext, at); at += ciphertext.length + ctPad;
    var view = new DataView(message.buffer);
    view.setUint32(at, aad.length, true);
    view.setUint32(at + 8, ciphertext.length, true);
    return poly1305(polyKey, message);
  }

  function timingSafeEqual(a, b) {
    if (a.length !== b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  function chachaSeal(key, nonce, plaintext, aad) {
    aad = aad || new Uint8Array(0);
    var ciphertext = chacha20(key, nonce, 1, plaintext);
    var tag = aeadTag(key, nonce, aad, ciphertext);
    var out = new Uint8Array(ciphertext.length + 16);
    out.set(ciphertext, 0);
    out.set(tag, ciphertext.length);
    return out;
  }

  function chachaOpen(key, nonce, sealed, aad) {
    aad = aad || new Uint8Array(0);
    if (sealed.length < 16) throw new Error('ciphertext too short');
    var ciphertext = sealed.subarray(0, sealed.length - 16);
    var tag = sealed.subarray(sealed.length - 16);
    var expected = aeadTag(key, nonce, aad, ciphertext);
    if (!timingSafeEqual(tag, expected)) throw new Error('authentication failed');
    return chacha20(key, nonce, 1, ciphertext);
  }

  global.GLINTCrypto = {
    scrypt: scrypt,
    chacha20: chacha20,
    poly1305: poly1305,
    chachaSeal: chachaSeal,
    chachaOpen: chachaOpen,
    timingSafeEqual: timingSafeEqual
  };
})(typeof window !== 'undefined' ? window : globalThis);
