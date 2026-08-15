/*
 * qrcode.js — a dependency-free QR Code encoder (model 2, versions 1-40).
 *
 * Produces the raw module matrix for a piece of data. The data itself is
 * baked into the symbol, so a code made here keeps working forever: there
 * is no redirect, no short link and no server in the loop.
 *
 * Exposes a single global: QRCode.encode(text, { ecc }) -> { size, modules, version, ecc }
 * `modules` is a size*size array of booleans (true = dark).
 */
(function (global) {
  'use strict';

  var ECC_LEVELS = { L: 0, M: 1, Q: 2, H: 3 };
  // Format-info bit patterns, indexed by the ECC ordinals above.
  var ECC_FORMAT_BITS = [1, 0, 3, 2];

  // Error correction codewords per block, [level][version].
  var ECC_CODEWORDS_PER_BLOCK = [
    // L
    [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28,
      28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
    // M
    [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26,
      26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
    // Q
    [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26,
      30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
    // H
    [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26,
      28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30]
  ];

  // Number of error correction blocks, [level][version].
  var NUM_ECC_BLOCKS = [
    [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7,
      8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
    [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14,
      16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
    [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21,
      20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
    [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25,
      25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81]
  ];

  var ALNUM_CHARSET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';

  /* ---------------------------------------------------------------- bits */

  function BitBuffer() {
    this.bits = [];
  }
  BitBuffer.prototype.append = function (value, length) {
    for (var i = length - 1; i >= 0; i--) {
      this.bits.push((value >>> i) & 1);
    }
  };

  /* ------------------------------------------------------ GF(256) arith */

  var EXP = new Uint8Array(256);
  var LOG = new Uint8Array(256);
  (function buildTables() {
    var x = 1;
    for (var i = 0; i < 255; i++) {
      EXP[i] = x;
      LOG[x] = i;
      x <<= 1;
      if (x & 0x100) x ^= 0x11d; // primitive polynomial x^8+x^4+x^3+x^2+1
    }
    EXP[255] = EXP[0];
  })();

  function gfMul(a, b) {
    if (a === 0 || b === 0) return 0;
    return EXP[(LOG[a] + LOG[b]) % 255];
  }

  // Generator polynomial for `degree` error correction codewords.
  function eccDivisor(degree) {
    var result = new Uint8Array(degree);
    result[degree - 1] = 1;
    var root = 1;
    for (var i = 0; i < degree; i++) {
      for (var j = 0; j < degree; j++) {
        result[j] = gfMul(result[j], root);
        if (j + 1 < degree) result[j] ^= result[j + 1];
      }
      root = gfMul(root, 0x02);
    }
    return result;
  }

  // Reed-Solomon remainder of `data` divided by `divisor`.
  function eccRemainder(data, divisor) {
    var result = new Uint8Array(divisor.length);
    for (var i = 0; i < data.length; i++) {
      var factor = data[i] ^ result[0];
      result.copyWithin(0, 1);
      result[result.length - 1] = 0;
      for (var j = 0; j < divisor.length; j++) {
        result[j] ^= gfMul(divisor[j], factor);
      }
    }
    return result;
  }

  /* ------------------------------------------------- capacity / geometry */

  function numRawDataModules(version) {
    var size = version * 4 + 17;
    var result = size * size;
    result -= 8 * 8 * 3;        // three finder patterns with separators/format areas
    result -= 15 * 2 + 1;       // format information and the dark module
    result -= (size - 16) * 2;  // timing patterns
    if (version >= 2) {
      var numAlign = Math.floor(version / 7) + 2;
      result -= (numAlign - 1) * (numAlign - 1) * 25;  // alignment patterns
      result -= (numAlign - 2) * 2 * 20;               // ones overlapping timing
      if (version >= 7) result -= 6 * 3 * 2;           // version information
    }
    return result;
  }

  function numDataCodewords(version, ecc) {
    return Math.floor(numRawDataModules(version) / 8) -
      ECC_CODEWORDS_PER_BLOCK[ecc][version] * NUM_ECC_BLOCKS[ecc][version];
  }

  function alignmentPositions(version) {
    if (version === 1) return [];
    var numAlign = Math.floor(version / 7) + 2;
    var size = version * 4 + 17;
    var step = version === 32 ? 26 : Math.ceil((version * 4 + 4) / (numAlign * 2 - 2)) * 2;
    var result = [6];
    for (var pos = size - 7; result.length < numAlign; pos -= step) {
      result.splice(1, 0, pos);
    }
    return result;
  }

  /* ------------------------------------------------------ data encoding */

  function toUtf8(text) {
    var out = [];
    var encoded = unescape(encodeURIComponent(text));
    for (var i = 0; i < encoded.length; i++) out.push(encoded.charCodeAt(i));
    return out;
  }

  function isNumeric(text) {
    return text.length > 0 && /^[0-9]*$/.test(text);
  }

  function isAlnum(text) {
    if (text.length === 0) return false;
    for (var i = 0; i < text.length; i++) {
      if (ALNUM_CHARSET.indexOf(text.charAt(i)) < 0) return false;
    }
    return true;
  }

  // Pick the tightest of the three common modes for this text.
  function chooseMode(text) {
    if (isNumeric(text)) return 'numeric';
    if (isAlnum(text)) return 'alnum';
    return 'byte';
  }

  function charCountBits(mode, version) {
    var group = version <= 9 ? 0 : version <= 26 ? 1 : 2;
    if (mode === 'numeric') return [10, 12, 14][group];
    if (mode === 'alnum') return [9, 11, 13][group];
    return [8, 16, 16][group];
  }

  function dataBitLength(mode, text, bytes) {
    if (mode === 'numeric') {
      var groups = Math.floor(text.length / 3);
      var rest = text.length % 3;
      return groups * 10 + (rest === 1 ? 4 : rest === 2 ? 7 : 0);
    }
    if (mode === 'alnum') {
      return Math.floor(text.length / 2) * 11 + (text.length % 2) * 6;
    }
    return bytes.length * 8;
  }

  function appendData(bb, mode, text, bytes) {
    var i;
    if (mode === 'numeric') {
      for (i = 0; i + 3 <= text.length; i += 3) {
        bb.append(parseInt(text.substr(i, 3), 10), 10);
      }
      var rest = text.length - i;
      if (rest === 1) bb.append(parseInt(text.substr(i, 1), 10), 4);
      else if (rest === 2) bb.append(parseInt(text.substr(i, 2), 10), 7);
    } else if (mode === 'alnum') {
      for (i = 0; i + 2 <= text.length; i += 2) {
        bb.append(ALNUM_CHARSET.indexOf(text.charAt(i)) * 45 +
          ALNUM_CHARSET.indexOf(text.charAt(i + 1)), 11);
      }
      if (i < text.length) bb.append(ALNUM_CHARSET.indexOf(text.charAt(i)), 6);
    } else {
      for (i = 0; i < bytes.length; i++) bb.append(bytes[i], 8);
    }
  }

  var MODE_INDICATOR = { numeric: 1, alnum: 2, byte: 4 };

  // Build the final, interleaved codeword sequence for the symbol.
  function buildCodewords(text, ecc) {
    var mode = chooseMode(text);
    var bytes = mode === 'byte' ? toUtf8(text) : null;
    var payloadBits = dataBitLength(mode, text, bytes);

    var version = 0;
    for (var v = 1; v <= 40; v++) {
      var capacity = numDataCodewords(v, ecc) * 8;
      if (4 + charCountBits(mode, v) + payloadBits <= capacity) {
        version = v;
        break;
      }
    }
    if (version === 0) {
      throw new Error('Too much data for a QR code — try shorter text or a lower error correction level.');
    }

    var total = numDataCodewords(version, ecc);
    var bb = new BitBuffer();
    bb.append(MODE_INDICATOR[mode], 4);
    bb.append(mode === 'byte' ? bytes.length : text.length, charCountBits(mode, version));
    appendData(bb, mode, text, bytes);

    // Terminator, then pad to a byte boundary, then alternating pad bytes.
    bb.append(0, Math.min(4, total * 8 - bb.bits.length));
    bb.append(0, (8 - bb.bits.length % 8) % 8);
    for (var pad = 0xec; bb.bits.length < total * 8; pad ^= 0xec ^ 0x11) {
      bb.append(pad, 8);
    }

    var data = new Uint8Array(total);
    for (var i = 0; i < bb.bits.length; i++) {
      data[i >>> 3] |= bb.bits[i] << (7 - (i & 7));
    }

    return { version: version, codewords: interleave(data, version, ecc) };
  }

  // Split into blocks, compute ECC per block, then interleave both halves.
  function interleave(data, version, ecc) {
    var numBlocks = NUM_ECC_BLOCKS[ecc][version];
    var blockEccLen = ECC_CODEWORDS_PER_BLOCK[ecc][version];
    var rawCodewords = Math.floor(numRawDataModules(version) / 8);
    var numShortBlocks = numBlocks - rawCodewords % numBlocks;
    var shortBlockLen = Math.floor(rawCodewords / numBlocks);

    var divisor = eccDivisor(blockEccLen);
    var blocks = [];
    for (var i = 0, k = 0; i < numBlocks; i++) {
      var dataLen = shortBlockLen - blockEccLen + (i < numShortBlocks ? 0 : 1);
      var dat = Array.prototype.slice.call(data.subarray(k, k + dataLen));
      k += dataLen;
      var parity = Array.prototype.slice.call(eccRemainder(dat, divisor));
      // Pad short blocks so every block has the same length; the placeholder
      // column is skipped during interleaving below.
      if (i < numShortBlocks) dat.push(0);
      blocks.push(dat.concat(parity));
    }

    var result = [];
    for (var col = 0; col < blocks[0].length; col++) {
      for (var b = 0; b < blocks.length; b++) {
        if (col === shortBlockLen - blockEccLen && b < numShortBlocks) continue;
        result.push(blocks[b][col]);
      }
    }
    return result;
  }

  /* ------------------------------------------------------------- matrix */

  function Matrix(size) {
    this.size = size;
    this.modules = [];
    this.reserved = [];
    for (var y = 0; y < size; y++) {
      this.modules.push(new Array(size).fill(false));
      this.reserved.push(new Array(size).fill(false));
    }
  }
  Matrix.prototype.set = function (x, y, dark, isFunction) {
    this.modules[y][x] = dark;
    if (isFunction) this.reserved[y][x] = true;
  };

  function drawFinder(m, cx, cy) {
    for (var dy = -4; dy <= 4; dy++) {
      for (var dx = -4; dx <= 4; dx++) {
        var x = cx + dx, y = cy + dy;
        if (x < 0 || x >= m.size || y < 0 || y >= m.size) continue;
        var dist = Math.max(Math.abs(dx), Math.abs(dy));
        m.set(x, y, dist !== 2 && dist <= 3, true);
      }
    }
  }

  function drawAlignment(m, cx, cy) {
    for (var dy = -2; dy <= 2; dy++) {
      for (var dx = -2; dx <= 2; dx++) {
        m.set(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1, true);
      }
    }
  }

  function drawFunctionPatterns(m, version, ecc) {
    var size = m.size;
    var i;

    // Timing patterns.
    for (i = 0; i < size; i++) {
      m.set(6, i, i % 2 === 0, true);
      m.set(i, 6, i % 2 === 0, true);
    }

    drawFinder(m, 3, 3);
    drawFinder(m, size - 4, 3);
    drawFinder(m, 3, size - 4);

    var positions = alignmentPositions(version);
    for (i = 0; i < positions.length; i++) {
      for (var j = 0; j < positions.length; j++) {
        // Skip the three corners already occupied by finder patterns.
        var corner = (i === 0 && j === 0) ||
          (i === 0 && j === positions.length - 1) ||
          (i === positions.length - 1 && j === 0);
        if (!corner) drawAlignment(m, positions[i], positions[j]);
      }
    }

    drawFormatBits(m, ecc, 0);   // placeholder; rewritten once a mask is chosen
    drawVersionBits(m, version);
  }

  // BCH-encoded format information, written twice for redundancy.
  function drawFormatBits(m, ecc, mask) {
    var data = ECC_FORMAT_BITS[ecc] << 3 | mask;
    var rem = data;
    for (var i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    var bits = ((data << 10) | rem) ^ 0x5412;
    var size = m.size;
    var i2;

    for (i2 = 0; i2 <= 5; i2++) m.set(8, i2, bit(bits, i2), true);
    m.set(8, 7, bit(bits, 6), true);
    m.set(8, 8, bit(bits, 7), true);
    m.set(7, 8, bit(bits, 8), true);
    for (i2 = 9; i2 < 15; i2++) m.set(14 - i2, 8, bit(bits, i2), true);

    for (i2 = 0; i2 < 8; i2++) m.set(size - 1 - i2, 8, bit(bits, i2), true);
    for (i2 = 8; i2 < 15; i2++) m.set(8, size - 15 + i2, bit(bits, i2), true);
    m.set(8, size - 8, true, true); // the always-dark module
  }

  function drawVersionBits(m, version) {
    if (version < 7) return;
    var rem = version;
    for (var i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    var bits = (version << 12) | rem;
    var size = m.size;
    for (var k = 0; k < 18; k++) {
      var dark = bit(bits, k);
      var a = size - 11 + k % 3;
      var b = Math.floor(k / 3);
      m.set(a, b, dark, true);
      m.set(b, a, dark, true);
    }
  }

  function bit(value, index) {
    return ((value >>> index) & 1) !== 0;
  }

  // Zigzag the codeword bits into the non-reserved modules.
  function drawCodewords(m, codewords) {
    var size = m.size;
    var i = 0;
    for (var right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5; // the vertical timing pattern column
      for (var vert = 0; vert < size; vert++) {
        for (var j = 0; j < 2; j++) {
          var x = right - j;
          var upward = ((right + 1) & 2) === 0;
          var y = upward ? size - 1 - vert : vert;
          if (!m.reserved[y][x] && i < codewords.length * 8) {
            m.modules[y][x] = bit(codewords[i >>> 3], 7 - (i & 7));
            i++;
          }
        }
      }
    }
  }

  var MASK_FNS = [
    function (x, y) { return (x + y) % 2 === 0; },
    function (x, y) { return y % 2 === 0; },
    function (x) { return x % 3 === 0; },
    function (x, y) { return (x + y) % 3 === 0; },
    function (x, y) { return (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0; },
    function (x, y) { return (x * y) % 2 + (x * y) % 3 === 0; },
    function (x, y) { return ((x * y) % 2 + (x * y) % 3) % 2 === 0; },
    function (x, y) { return ((x + y) % 2 + (x * y) % 3) % 2 === 0; }
  ];

  function applyMask(m, mask) {
    var fn = MASK_FNS[mask];
    for (var y = 0; y < m.size; y++) {
      for (var x = 0; x < m.size; x++) {
        if (!m.reserved[y][x] && fn(x, y)) m.modules[y][x] = !m.modules[y][x];
      }
    }
  }

  // Penalty score per the spec: the lowest-scoring mask wins.
  function penalty(m) {
    var size = m.size;
    var score = 0;
    var x, y;

    // A rolling history of the last seven run lengths, newest first, used to
    // spot finder-like 1:1:3:1:1 patterns as each line is scanned.
    function addHistory(runLength, history) {
      if (history[0] === 0) runLength += size; // the quiet zone borders the first run
      history.pop();
      history.unshift(runLength);
    }

    function countPatterns(history) {
      var n = history[1];
      var core = n > 0 && history[2] === n && history[3] === n * 3 &&
        history[4] === n && history[5] === n;
      return (core && history[0] >= n * 4 && history[6] >= n ? 1 : 0) +
        (core && history[6] >= n * 4 && history[0] >= n ? 1 : 0);
    }

    // Rules 1 and 3: same-colour runs, and finder-like patterns, along every
    // row and then every column.
    for (var pass = 0; pass < 2; pass++) {
      for (var line = 0; line < size; line++) {
        var history = [0, 0, 0, 0, 0, 0, 0];
        var runColor = false;
        var runLength = 0;
        for (var i = 0; i < size; i++) {
          var cell = pass === 0 ? m.modules[line][i] : m.modules[i][line];
          if (cell === runColor) {
            runLength++;
            if (runLength === 5) score += 3;
            else if (runLength > 5) score += 1;
          } else {
            addHistory(runLength, history);
            if (!runColor) score += countPatterns(history) * 40;
            runColor = cell;
            runLength = 1;
          }
        }
        // Terminate the line: the quiet zone counts as a trailing light run.
        if (runColor) {
          addHistory(runLength, history);
          runLength = 0;
        }
        addHistory(runLength + size, history);
        score += countPatterns(history) * 40;
      }
    }

    // Rule 2: 2x2 blocks of one colour.
    for (y = 0; y < size - 1; y++) {
      for (x = 0; x < size - 1; x++) {
        var c = m.modules[y][x];
        if (c === m.modules[y][x + 1] && c === m.modules[y + 1][x] && c === m.modules[y + 1][x + 1]) {
          score += 3;
        }
      }
    }

    // Rule 4: deviation from an even balance of dark and light modules.
    var darkCount = 0;
    for (y = 0; y < size; y++) {
      for (x = 0; x < size; x++) if (m.modules[y][x]) darkCount++;
    }
    var totalModules = size * size;
    var k = Math.ceil(Math.abs(darkCount * 20 - totalModules * 10) / totalModules) - 1;
    score += Math.max(k, 0) * 10;

    return score;
  }

  /* ---------------------------------------------------------------- API */

  function encode(text, options) {
    options = options || {};
    var eccName = (options.ecc || 'M').toUpperCase();
    if (!(eccName in ECC_LEVELS)) throw new Error('Unknown error correction level: ' + eccName);
    if (typeof text !== 'string' || text.length === 0) throw new Error('Nothing to encode.');
    var ecc = ECC_LEVELS[eccName];

    var built = buildCodewords(text, ecc);
    var version = built.version;
    var size = version * 4 + 17;

    var best = null;
    for (var mask = 0; mask < 8; mask++) {
      var m = new Matrix(size);
      drawFunctionPatterns(m, version, ecc);
      drawCodewords(m, built.codewords);
      drawFormatBits(m, ecc, mask);
      applyMask(m, mask);
      var score = penalty(m);
      if (!best || score < best.score) best = { score: score, matrix: m, mask: mask };
    }

    return {
      size: size,
      version: version,
      ecc: eccName,
      mask: best.mask,
      modules: best.matrix.modules
    };
  }

  global.QRCode = { encode: encode };
})(typeof window !== 'undefined' ? window : globalThis);
