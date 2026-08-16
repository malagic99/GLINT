/*
 * shamir.js — Shamir secret sharing over GF(256), byte by byte.
 *
 * Splits a key into `total` shares of which any `threshold` reconstruct it.
 * Fewer than `threshold` shares reveal nothing at all: for any candidate
 * secret there is exactly one polynomial through the held points, so every
 * secret remains equally likely. That is information-theoretic, not
 * computational — no amount of compute helps.
 *
 * Share format: [x, ...payload]. x is the non-zero evaluation point.
 */
(function (global) {
  'use strict';

  var EXP = new Uint8Array(512);
  var LOG = new Uint8Array(256);
  (function () {
    var x = 1;
    for (var i = 0; i < 255; i++) {
      EXP[i] = x;
      LOG[x] = i;
      x = (x << 1) ^ (x & 0x80 ? 0x11d : 0);
      x &= 0xff;
    }
    for (var j = 255; j < 512; j++) EXP[j] = EXP[j - 255];
  })();

  function mul(a, b) {
    if (a === 0 || b === 0) return 0;
    return EXP[LOG[a] + LOG[b]];
  }

  function div(a, b) {
    if (b === 0) throw new Error('shamir: divide by zero');
    if (a === 0) return 0;
    return EXP[LOG[a] + 255 - LOG[b]];
  }

  /**
   * split(secret, threshold, total) -> Uint8Array[]
   * Each share is 1 + secret.length bytes.
   */
  function split(secret, threshold, total) {
    if (threshold < 2 || threshold > 255) throw new Error('shamir: threshold out of range');
    if (total < threshold || total > 255) throw new Error('shamir: total out of range');

    var shares = [];
    for (var s = 0; s < total; s++) {
      var share = new Uint8Array(secret.length + 1);
      share[0] = s + 1;               // x = 0 would expose the secret directly
      shares.push(share);
    }

    // One random polynomial per byte, with the secret as the constant term.
    var coefficients = new Uint8Array(threshold - 1);
    for (var i = 0; i < secret.length; i++) {
      global.crypto.getRandomValues(coefficients);
      for (var k = 0; k < total; k++) {
        var x = shares[k][0];
        var y = secret[i];
        var power = 1;
        for (var c = 0; c < coefficients.length; c++) {
          power = mul(power, x);
          y ^= mul(coefficients[c], power);
        }
        shares[k][i + 1] = y;
      }
    }
    return shares;
  }

  /**
   * combine(shares) -> Uint8Array
   * Lagrange interpolation at x = 0. Duplicate x values are rejected: they
   * are not independent points and would silently produce a wrong secret.
   */
  function combine(shares) {
    if (!shares || shares.length < 2) throw new Error('shamir: need at least two shares');
    var length = shares[0].length;
    var seen = {};
    for (var i = 0; i < shares.length; i++) {
      if (shares[i].length !== length) throw new Error('shamir: shares have different lengths');
      var xi = shares[i][0];
      if (xi === 0) throw new Error('shamir: invalid share (x = 0)');
      if (seen[xi]) throw new Error('shamir: the same share was supplied twice');
      seen[xi] = true;
    }

    var secret = new Uint8Array(length - 1);
    for (var byte = 0; byte < secret.length; byte++) {
      var accumulator = 0;
      for (var j = 0; j < shares.length; j++) {
        var numerator = 1, denominator = 1;
        for (var m = 0; m < shares.length; m++) {
          if (m === j) continue;
          numerator = mul(numerator, shares[m][0]);
          denominator = mul(denominator, shares[j][0] ^ shares[m][0]);
        }
        accumulator ^= mul(shares[j][byte + 1], div(numerator, denominator));
      }
      secret[byte] = accumulator;
    }
    return secret;
  }

  /* ------------------------------------------------- share transcription */

  // A share is useless if it is mistyped and you cannot tell. Encoded shares
  // therefore carry a CRC over the bytes, plus a short tag identifying which
  // file they belong to, so a share can be checked on its own.
  //
  // What this proves: the text was transcribed correctly, and it was issued
  // for this file. What it cannot prove: that the share is cryptographically
  // valid. One share carries no information about the secret — that is the
  // whole point of Shamir — so nothing short of assembling two can confirm it.

  var SHARE_PREFIX = 'GLINT1:';
  var TAG_BYTES = 6;

  function crc16(bytes) {
    var crc = 0xffff;
    for (var i = 0; i < bytes.length; i++) {
      crc ^= bytes[i] << 8;
      for (var bit = 0; bit < 8; bit++) {
        crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
      }
    }
    return crc;
  }

  function toBase64Url(bytes) {
    var binary = '';
    for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return global.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function fromBase64Url(text) {
    var padded = text.replace(/-/g, '+').replace(/_/g, '/');
    while (padded.length % 4) padded += '=';
    var binary = global.atob(padded);
    var out = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  }

  /** Identifies the file a share belongs to. Derived from public header bytes. */
  function fileTag(headerCore) {
    return global.crypto.subtle.digest('SHA-256', headerCore).then(function (hash) {
      return new Uint8Array(hash).slice(0, TAG_BYTES);
    });
  }

  function encodeShare(share, tag) {
    tag = tag || new Uint8Array(TAG_BYTES);
    var body = new Uint8Array(share.length + TAG_BYTES);
    body.set(share, 0);
    body.set(tag, share.length);
    var sum = crc16(body);
    var full = new Uint8Array(body.length + 2);
    full.set(body, 0);
    full[body.length] = (sum >> 8) & 0xff;
    full[body.length + 1] = sum & 0xff;
    return SHARE_PREFIX + toBase64Url(full);
  }

  /**
   * decodeShare(text) -> {share, tag, index, legacy}
   * Throws with a plain-language reason when the text is damaged.
   */
  function decodeShare(text) {
    var trimmed = String(text).trim().replace(/\s+/g, '');
    if (trimmed.indexOf(SHARE_PREFIX) === 0) trimmed = trimmed.slice(SHARE_PREFIX.length);
    if (!trimmed) throw new Error('That share is empty.');

    var bytes;
    try {
      bytes = fromBase64Url(trimmed);
    } catch (e) {
      throw new Error('That share contains characters that are not part of a share.');
    }

    // Shares written before checksums existed are the bare secret bytes.
    if (bytes.length > 2 && bytes.length !== 33 + TAG_BYTES + 2) {
      if (bytes.length === 33) return { share: bytes, tag: null, index: bytes[0], legacy: true };
      throw new Error('That share is the wrong length — it looks truncated or run together.');
    }
    if (bytes.length === 33) return { share: bytes, tag: null, index: bytes[0], legacy: true };

    var body = bytes.subarray(0, bytes.length - 2);
    var expected = (bytes[bytes.length - 2] << 8) | bytes[bytes.length - 1];
    if (crc16(body) !== expected) {
      throw new Error('That share has a typo in it — the checksum does not match.');
    }
    return {
      share: body.slice(0, body.length - TAG_BYTES),
      tag: body.slice(body.length - TAG_BYTES),
      index: body[0],
      legacy: false
    };
  }

  function sameTag(a, b) {
    if (!a || !b || a.length !== b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  global.GLINTShamir = {
    split: split,
    combine: combine,
    encodeShare: encodeShare,
    decodeShare: decodeShare,
    fileTag: fileTag,
    sameTag: sameTag,
    crc16: crc16
  };
})(typeof window !== 'undefined' ? window : globalThis);
