/*
 * glint.js — encrypted data hidden in the DCT blocks of an image.
 *
 * Pipeline:  plaintext -> deflate -> AES-256-GCM -> Reed-Solomon -> 8x8 blocks
 *
 * Each 8x8 pixel block carries bits in a mid-frequency DCT basis function.
 * The grid is aligned to JPEG's own block grid, so quantisation blurs the
 * signal rather than destroying it, and the codes survive screenshots and
 * recompression.
 *
 * Exposes: GLINT.encode(bytes, passphrase, opts) -> {width, height, rgba}
 *          GLINT.decode(imageData, passphrase)   -> bytes
 * plus the text/byte and compression helpers the UI needs.
 */
(function (global) {
  'use strict';

  var MAGIC = 0x474c4e54;      // "GLNT"
  var VERSION = 1;
  var BLOCK = 8;               // JPEG's DCT block size — do not change
  var HEADER_BYTES = 40;       // magic, version, flags, length, salt, iv
  var PBKDF2_ITERATIONS = 600000;

  /* ------------------------------------------------------ GF(256) / RS */

  var EXP = new Uint8Array(256);
  var LOG = new Uint8Array(256);
  (function () {
    var x = 1;
    for (var i = 0; i < 255; i++) {
      EXP[i] = x;
      LOG[x] = i;
      x <<= 1;
      if (x & 0x100) x ^= 0x11d;
    }
    EXP[255] = EXP[0];
  })();

  function gfMul(a, b) {
    if (a === 0 || b === 0) return 0;
    return EXP[(LOG[a] + LOG[b]) % 255];
  }

  function gfDiv(a, b) {
    if (b === 0) throw new Error('divide by zero');
    if (a === 0) return 0;
    return EXP[(LOG[a] + 255 - LOG[b]) % 255];
  }

  function rsGenerator(degree) {
    var result = new Uint8Array(degree);
    result[degree - 1] = 1;
    var root = 1;
    for (var i = 0; i < degree; i++) {
      for (var j = 0; j < degree; j++) {
        result[j] = gfMul(result[j], root);
        if (j + 1 < degree) result[j] ^= result[j + 1];
      }
      root = gfMul(root, 2);
    }
    return result;
  }

  function rsParity(data, degree) {
    var divisor = rsGenerator(degree);
    var result = new Uint8Array(degree);
    for (var i = 0; i < data.length; i++) {
      var factor = data[i] ^ result[0];
      result.copyWithin(0, 1);
      result[result.length - 1] = 0;
      for (var j = 0; j < degree; j++) result[j] ^= gfMul(divisor[j], factor);
    }
    return result;
  }

  // Syndrome-based decoder: Berlekamp-Massey, Chien search, Forney.
  // The generator's roots are alpha^0..alpha^(parity-1), so Forney needs the
  // extra X_k factor. Corrects up to parity/2 byte errors per codeword.
  function rsCorrect(codeword, degree) {
    var n = codeword.length;
    var i, j;

    var syndromes = new Uint8Array(degree);
    var hasError = false;
    for (i = 0; i < degree; i++) {
      var s = 0;
      var root = EXP[i % 255];
      for (j = 0; j < n; j++) s = gfMul(s, root) ^ codeword[j];
      syndromes[i] = s;
      if (s !== 0) hasError = true;
    }
    if (!hasError) return codeword;

    // Berlekamp-Massey. Polynomials are little-endian: index == degree.
    var sigma = new Uint8Array(degree + 1); sigma[0] = 1;
    var prev = new Uint8Array(degree + 1); prev[0] = 1;
    var L = 0, m = 1, b = 1;

    for (var r = 0; r < degree; r++) {
      var delta = syndromes[r];
      for (i = 1; i <= L; i++) delta ^= gfMul(sigma[i], syndromes[r - i]);

      if (delta === 0) {
        m++;
      } else if (2 * L <= r) {
        var copy = sigma.slice();
        var scale = gfDiv(delta, b);
        for (i = 0; i + m <= degree; i++) sigma[i + m] ^= gfMul(scale, prev[i]);
        L = r + 1 - L;
        prev = copy;
        b = delta;
        m = 1;
      } else {
        var scale2 = gfDiv(delta, b);
        for (i = 0; i + m <= degree; i++) sigma[i + m] ^= gfMul(scale2, prev[i]);
        m++;
      }
    }

    if (L === 0 || L * 2 > degree) throw new Error('too many errors');

    // Chien search: position p is in error when sigma(X^-1) == 0,
    // where X = alpha^(n-1-p).
    var positions = [];
    for (var p2 = 0; p2 < n && positions.length <= L; p2++) {
      var xInv = EXP[(255 - ((n - 1 - p2) % 255)) % 255];
      var acc = 0, term = 1;
      for (i = 0; i <= L; i++) {
        acc ^= gfMul(sigma[i], term);
        term = gfMul(term, xInv);
      }
      if (acc === 0) positions.push(p2);
    }
    if (positions.length !== L) throw new Error('error locations not found');

    // omega(x) = S(x) * sigma(x) mod x^degree
    var omega = new Uint8Array(degree);
    for (i = 0; i < degree; i++) {
      var sum = 0;
      for (j = 0; j <= i && j <= L; j++) sum ^= gfMul(sigma[j], syndromes[i - j]);
      omega[i] = sum;
    }

    var out = Uint8Array.from(codeword);
    for (var k = 0; k < positions.length; k++) {
      var pos = positions[k];
      var xi = EXP[(n - 1 - pos) % 255];
      var xiInv = gfDiv(1, xi);

      var num = 0, power = 1;
      for (i = 0; i < degree; i++) {
        num ^= gfMul(omega[i], power);
        power = gfMul(power, xiInv);
      }

      // Formal derivative: only odd-degree terms survive in GF(2^m).
      var den = 0, odd = 1;
      for (i = 1; i <= L; i += 2) {
        den ^= gfMul(sigma[i], odd);
        odd = gfMul(odd, gfMul(xiInv, xiInv));
      }
      if (den === 0) throw new Error('forney denominator zero');
      out[pos] ^= gfMul(xi, gfDiv(num, den));
    }
    return out;
  }

  /* -------------------------------------------------- codeword framing */

  // Split into RS(255, 255-parity) codewords; the tail is a shorter block.
  function rsEncode(data, parity) {
    var chunk = 255 - parity;
    var out = [];
    for (var i = 0; i < data.length; i += chunk) {
      var piece = data.subarray(i, Math.min(i + chunk, data.length));
      var block = new Uint8Array(piece.length + parity);
      block.set(piece, 0);
      block.set(rsParity(piece, parity), piece.length);
      out.push(block);
    }
    var total = out.reduce(function (n, b) { return n + b.length; }, 0);
    var joined = new Uint8Array(total);
    var at = 0;
    out.forEach(function (b) { joined.set(b, at); at += b.length; });
    return joined;
  }

  function rsDecode(data, parity, expectedLength) {
    var chunk = 255 - parity;
    var out = new Uint8Array(expectedLength);
    var written = 0;
    var read = 0;
    var corrected = 0;
    while (written < expectedLength) {
      var dataLen = Math.min(chunk, expectedLength - written);
      var blockLen = dataLen + parity;
      var block = data.subarray(read, read + blockLen);
      read += blockLen;
      var fixed;
      try {
        fixed = rsCorrect(block, parity);
        for (var i = 0; i < blockLen; i++) if (fixed[i] !== block[i]) corrected++;
      } catch (e) {
        throw new Error('Too much damage to recover this image.');
      }
      out.set(fixed.subarray(0, dataLen), written);
      written += dataLen;
    }
    return { data: out, corrected: corrected };
  }

  /* ------------------------------------------------- DCT basis carrier */

  // Precomputed 8x8 spatial patterns for two mid-frequency DCT basis
  // functions. Adding +-amplitude * pattern moves exactly one coefficient.
  function basisPattern(u, v) {
    var pattern = new Float32Array(BLOCK * BLOCK);
    var cu = u === 0 ? Math.SQRT1_2 : 1;
    var cv = v === 0 ? Math.SQRT1_2 : 1;
    for (var y = 0; y < BLOCK; y++) {
      for (var x = 0; x < BLOCK; x++) {
        pattern[y * BLOCK + x] = 0.25 * cu * cv *
          Math.cos((2 * x + 1) * u * Math.PI / 16) *
          Math.cos((2 * y + 1) * v * Math.PI / 16);
      }
    }
    return pattern;
  }

  // (1,2) and (2,1): high enough to be visually quiet, low enough to
  // survive the quantisation tables used at normal JPEG qualities.
  var CARRIERS = [basisPattern(1, 2), basisPattern(2, 1)];

  function projectBlock(luma, stride, ox, oy, carrier) {
    var sum = 0;
    for (var y = 0; y < BLOCK; y++) {
      for (var x = 0; x < BLOCK; x++) {
        sum += luma[(oy + y) * stride + ox + x] * carrier[y * BLOCK + x];
      }
    }
    return sum;
  }

  function modulateBlock(luma, stride, ox, oy, carrier, amount) {
    for (var y = 0; y < BLOCK; y++) {
      for (var x = 0; x < BLOCK; x++) {
        var index = (oy + y) * stride + ox + x;
        luma[index] += amount * carrier[y * BLOCK + x];
      }
    }
  }

  /* ------------------------------------------------------ layout maths */

  function layout(width, height) {
    var cols = Math.floor(width / BLOCK);
    var rows = Math.floor(height / BLOCK);
    return { cols: cols, rows: rows, cells: cols * rows, bits: cols * rows * CARRIERS.length };
  }

  // How many payload bytes fit, given the RS overhead and the header.
  function capacity(width, height, parity) {
    var bits = layout(width, height).bits;
    var codewordBytes = Math.floor(bits / 8);
    var chunk = 255 - parity;
    var fullBlocks = Math.floor(codewordBytes / 255);
    var remainder = codewordBytes - fullBlocks * 255;
    var usable = fullBlocks * chunk + Math.max(0, remainder - parity);
    return Math.max(0, usable - HEADER_BYTES);
  }

  /* ------------------------------------------------------------ crypto */

  function randomBytes(n) {
    var out = new Uint8Array(n);
    global.crypto.getRandomValues(out);
    return out;
  }

  function deriveKey(passphrase, salt) {
    var encoder = new TextEncoder();
    return global.crypto.subtle
      .importKey('raw', encoder.encode(passphrase), 'PBKDF2', false, ['deriveKey'])
      .then(function (material) {
        return global.crypto.subtle.deriveKey(
          { name: 'PBKDF2', salt: salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
          material,
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt', 'decrypt']
        );
      });
  }

  function deflate(bytes) {
    if (typeof global.CompressionStream !== 'function') return Promise.resolve(bytes);
    var stream = new global.CompressionStream('deflate-raw');
    var writer = stream.writable.getWriter();
    writer.write(bytes);
    writer.close();
    return new Response(stream.readable).arrayBuffer().then(function (b) {
      return new Uint8Array(b);
    });
  }

  function inflate(bytes) {
    if (typeof global.DecompressionStream !== 'function') return Promise.resolve(bytes);
    var stream = new global.DecompressionStream('deflate-raw');
    var writer = stream.writable.getWriter();
    writer.write(bytes);
    writer.close();
    return new Response(stream.readable).arrayBuffer().then(function (b) {
      return new Uint8Array(b);
    });
  }

  /* ------------------------------------------------------------ header */

  function buildHeader(flags, payloadLength, salt, iv) {
    var header = new Uint8Array(HEADER_BYTES);
    var view = new DataView(header.buffer);
    view.setUint32(0, MAGIC);
    header[4] = VERSION;
    header[5] = flags;
    view.setUint32(6, payloadLength);
    header.set(salt, 10);   // 16 bytes
    header.set(iv, 26);     // 12 bytes
    // bytes 38-39 reserved
    return header;
  }

  function parseHeader(bytes) {
    var view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (view.getUint32(0) !== MAGIC) throw new Error('No GLINT data found in this image.');
    if (bytes[4] !== VERSION) throw new Error('Made by a different version of GLINT.');
    return {
      flags: bytes[5],
      length: view.getUint32(6),
      salt: bytes.slice(10, 26),
      iv: bytes.slice(26, 38)
    };
  }

  /* ------------------------------------------------------ bit plumbing */

  function bytesToBits(bytes) {
    var bits = new Uint8Array(bytes.length * 8);
    for (var i = 0; i < bytes.length; i++) {
      for (var b = 0; b < 8; b++) bits[i * 8 + b] = (bytes[i] >> (7 - b)) & 1;
    }
    return bits;
  }

  function bitsToBytes(bits, count) {
    var bytes = new Uint8Array(count);
    for (var i = 0; i < count; i++) {
      var value = 0;
      for (var b = 0; b < 8; b++) value = (value << 1) | bits[i * 8 + b];
      bytes[i] = value;
    }
    return bytes;
  }

  /* --------------------------------------------------- colour helpers */

  function rgbaToLuma(rgba, width, height) {
    var luma = new Float32Array(width * height);
    var chroma = new Float32Array(width * height * 2);
    for (var i = 0, p = 0; i < luma.length; i++, p += 4) {
      var r = rgba[p], g = rgba[p + 1], b = rgba[p + 2];
      luma[i] = 0.299 * r + 0.587 * g + 0.114 * b;
      chroma[i * 2] = -0.168736 * r - 0.331264 * g + 0.5 * b + 128;
      chroma[i * 2 + 1] = 0.5 * r - 0.418688 * g - 0.081312 * b + 128;
    }
    return { luma: luma, chroma: chroma };
  }

  function lumaToRgba(luma, chroma, width, height) {
    var rgba = new Uint8ClampedArray(width * height * 4);
    for (var i = 0, p = 0; i < luma.length; i++, p += 4) {
      var y = luma[i];
      var cb = chroma[i * 2] - 128;
      var cr = chroma[i * 2 + 1] - 128;
      rgba[p] = y + 1.402 * cr;
      rgba[p + 1] = y - 0.344136 * cb - 0.714136 * cr;
      rgba[p + 2] = y + 1.772 * cb;
      rgba[p + 3] = 255;
    }
    return rgba;
  }

  /* ------------------------------------------------------------ encode */

  /**
   * @param {Uint8Array} bytes      payload
   * @param {string}     passphrase
   * @param {object}     opts       {width, height, parity, amplitude,
   *                                 carrier: {rgba,width,height} for quiet mode}
   */
  function encode(bytes, passphrase, opts) {
    opts = opts || {};
    var parity = opts.parity || 64;
    var amplitude = opts.amplitude || 18;

    return deflate(bytes)
      .then(function (compressed) {
        var salt = randomBytes(16);
        var iv = randomBytes(12);
        return deriveKey(passphrase, salt).then(function (key) {
          return global.crypto.subtle
            .encrypt({ name: 'AES-GCM', iv: iv }, key, compressed)
            .then(function (buffer) {
              return { cipher: new Uint8Array(buffer), salt: salt, iv: iv };
            });
        });
      })
      .then(function (sealed) {
        var header = buildHeader(0, sealed.cipher.length, sealed.salt, sealed.iv);

        // The header gets its OWN Reed-Solomon codeword rather than sharing
        // the first one with the ciphertext. The decoder must recover it
        // before it knows how long anything else is, so it cannot be spread
        // across a codeword whose length is only knowable afterwards.
        var codedHeader = rsEncode(header, parity);
        var codedBody = rsEncode(sealed.cipher, parity);
        var coded = new Uint8Array(codedHeader.length + codedBody.length);
        coded.set(codedHeader, 0);
        coded.set(codedBody, codedHeader.length);
        var needed = coded.length * 8;

        var width, height, source;
        if (opts.carrier) {
          width = opts.carrier.width;
          height = opts.carrier.height;
          source = opts.carrier.rgba;
          if (layout(width, height).bits < needed) {
            throw new Error('That image is too small for this much data. ' +
              'Use a larger image, or shorten the message.');
          }
        } else {
          // Square grid big enough for the payload, rounded to whole blocks.
          var cells = Math.ceil(needed / CARRIERS.length);
          var side = Math.ceil(Math.sqrt(cells));
          width = height = side * BLOCK;
          source = new Uint8ClampedArray(width * height * 4);
          for (var i = 0; i < width * height; i++) {
            source[i * 4] = source[i * 4 + 1] = source[i * 4 + 2] = 128;
            source[i * 4 + 3] = 255;
          }
        }

        var planes = rgbaToLuma(source, width, height);
        var bits = bytesToBits(coded);
        var grid = layout(width, height);

        for (var cell = 0; cell < grid.cells; cell++) {
          var ox = (cell % grid.cols) * BLOCK;
          var oy = Math.floor(cell / grid.cols) * BLOCK;
          for (var c = 0; c < CARRIERS.length; c++) {
            var bitIndex = cell * CARRIERS.length + c;
            // Pad past the payload with alternating bits so the texture stays
            // uniform and gives no clue where the data ends.
            var bit = bitIndex < bits.length ? bits[bitIndex] : (bitIndex & 1);
            var current = projectBlock(planes.luma, width, ox, oy, CARRIERS[c]);
            var target = (bit ? 1 : -1) * amplitude;
            modulateBlock(planes.luma, width, ox, oy, CARRIERS[c], target - current);
          }
        }

        return {
          width: width,
          height: height,
          rgba: lumaToRgba(planes.luma, planes.chroma, width, height),
          parity: parity,
          payloadBytes: bytes.length
        };
      });
  }

  /* ------------------------------------------------------------ decode */

  function readBits(imageData, parity) {
    var width = imageData.width, height = imageData.height;
    var planes = rgbaToLuma(imageData.data, width, height);
    var grid = layout(width, height);
    var bits = new Uint8Array(grid.bits);
    for (var cell = 0; cell < grid.cells; cell++) {
      var ox = (cell % grid.cols) * BLOCK;
      var oy = Math.floor(cell / grid.cols) * BLOCK;
      for (var c = 0; c < CARRIERS.length; c++) {
        var value = projectBlock(planes.luma, width, ox, oy, CARRIERS[c]);
        bits[cell * CARRIERS.length + c] = value > 0 ? 1 : 0;
      }
    }
    return bits;
  }

  function decode(imageData, passphrase, opts) {
    opts = opts || {};
    var parity = opts.parity || 64;
    var bits = readBits(imageData, parity);
    var available = Math.floor(bits.length / 8);
    var raw = bitsToBytes(bits, available);

    // The header sits in the first codeword, so recover that alone first.
    var headerBlockLen = HEADER_BYTES + parity;
    if (raw.length < headerBlockLen) throw new Error('Image too small to hold GLINT data.');
    var headerBlock = rsDecode(raw.subarray(0, headerBlockLen), parity, HEADER_BYTES);
    var header = parseHeader(headerBlock.data);

    var chunk = 255 - parity;
    var bodyCodedLength = 0;
    for (var remaining = header.length; remaining > 0; remaining -= chunk) {
      bodyCodedLength += Math.min(chunk, remaining) + parity;
    }
    if (headerBlockLen + bodyCodedLength > raw.length) {
      throw new Error('This image is missing part of the data.');
    }

    var recovered = rsDecode(
      raw.subarray(headerBlockLen, headerBlockLen + bodyCodedLength), parity, header.length);
    var cipher = recovered.data;
    // Header repairs count too: reporting only the body made damage to the
    // header look like a clean read.
    var totalCorrected = headerBlock.corrected + recovered.corrected;

    return deriveKey(passphrase, header.salt)
      .then(function (key) {
        return global.crypto.subtle.decrypt({ name: 'AES-GCM', iv: header.iv }, key, cipher);
      })
      .catch(function () {
        throw new Error('Wrong passphrase, or the data has been tampered with.');
      })
      .then(function (buffer) {
        return inflate(new Uint8Array(buffer));
      })
      .then(function (plain) {
        return { bytes: plain, corrected: totalCorrected };
      });
  }

  global.GLINT = {
    encode: encode,
    decode: decode,
    capacity: capacity,
    layout: layout,
    HEADER_BYTES: HEADER_BYTES,
    _internal: { rsEncode: rsEncode, rsDecode: rsDecode, rsCorrect: rsCorrect, gfMul: gfMul }
  };
})(typeof window !== 'undefined' ? window : globalThis);
