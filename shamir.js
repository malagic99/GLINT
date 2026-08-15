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

  global.GLINTShamir = { split: split, combine: combine };
})(typeof window !== 'undefined' ? window : globalThis);
