/*
 * container.js — the .glintbox format: key slots plus a streaming cascade.
 *
 *   K_data (random 256-bit) encrypts the payload.
 *   K_data is wrapped independently by each slot, LUKS style, so factors can
 *   be added or replaced without re-encrypting a byte of the file.
 *
 *   Slot 0  passphrase (scrypt) [+ YubiKey PRF when present]
 *   Slot 1  recovery key, itself Shamir-split k-of-n outside this file
 *
 * The payload is chunked so file size is bounded only by disk. Each chunk is
 * sealed with a distinct nonce derived from a per-file prefix and the chunk
 * index, and the final chunk is flagged — so truncating, reordering or
 * dropping chunks all fail authentication (the STREAM construction).
 *
 * Cascade order is deliberate: ChaCha20 encrypts first, AES-256-GCM seals
 * last. On the way back, WebCrypto's hardware AES verifies the tag BEFORE
 * any hand-written JavaScript touches the bytes, so the JS layer never
 * processes unauthenticated input.
 */
(function (global) {
  'use strict';

  var MAGIC = [0x47, 0x4c, 0x4e, 0x54, 0x42, 0x4f, 0x58]; // "GLNTBOX"
  var FORMAT = 2;
  var TAG_BYTES = 16;
  var KEY_BYTES = 32;

  var SLOT_PASSPHRASE = 1;
  var SLOT_RECOVERY = 2;

  var FLAG_CASCADE = 1;
  var FLAG_TOKEN = 2;

  // Cost profiles. Memory is 128 * N * r bytes, so r=8 gives:
  //   fast 16 MB, strong 128 MB, paranoid 1 GB.
  var PROFILES = {
    fast:     { logN: 14, r: 8, p: 1, cascade: false, chunkLog: 20 },
    strong:   { logN: 17, r: 8, p: 1, cascade: true,  chunkLog: 20 },
    paranoid: { logN: 20, r: 8, p: 1, cascade: true,  chunkLog: 20 }
  };

  var subtle = global.crypto.subtle;
  var C = global.GLINTCrypto;

  function randomBytes(n) {
    var out = new Uint8Array(n);
    global.crypto.getRandomValues(out);
    return out;
  }

  function concat(pieces) {
    var total = pieces.reduce(function (n, p) { return n + p.length; }, 0);
    var out = new Uint8Array(total);
    var at = 0;
    pieces.forEach(function (p) { out.set(p, at); at += p.length; });
    return out;
  }

  /* --------------------------------------------------------------- KDF */

  function hkdf(secret, salt, info, length) {
    return subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits'])
      .then(function (key) {
        return subtle.deriveBits(
          { name: 'HKDF', hash: 'SHA-256', salt: salt, info: new TextEncoder().encode(info) },
          key,
          length * 8
        );
      })
      .then(function (bits) { return new Uint8Array(bits); });
  }

  // Slot key = HKDF(scrypt(passphrase) || tokenSecret). Both factors feed one
  // derivation, so neither alone produces the key — the token is not a gate
  // that could simply be bypassed.
  function deriveSlotKey(passphrase, tokenSecret, salt, profile) {
    var params = PROFILES[profile];
    var encoded = new TextEncoder().encode(passphrase || '');
    return C.scrypt(encoded, salt, 1 << params.logN, params.r, params.p, KEY_BYTES)
      .then(function (stretched) {
        var material = tokenSecret ? concat([stretched, tokenSecret]) : stretched;
        return hkdf(material, salt, 'glintbox/slot', KEY_BYTES);
      });
  }

  function importAes(raw) {
    return subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  }

  /* ------------------------------------------------------- chunk nonces */

  // 7-byte per-file prefix, 4-byte counter, 1 byte marking the final chunk.
  function chunkNonce(prefix, index, isFinal) {
    var nonce = new Uint8Array(12);
    nonce.set(prefix, 0);
    new DataView(nonce.buffer).setUint32(7, index);
    nonce[11] = isFinal ? 1 : 0;
    return nonce;
  }

  function sealChunk(keys, prefix, index, isFinal, plaintext, cascade, aad) {
    var staged = cascade
      ? C.chacha20(keys.chacha, chunkNonce(prefix, index, isFinal), 1, plaintext)
      : plaintext;
    return subtle.encrypt(
      {
        name: 'AES-GCM', iv: chunkNonce(prefix, index, isFinal),
        additionalData: aad, tagLength: TAG_BYTES * 8
      },
      keys.aes,
      staged
    ).then(function (buffer) { return new Uint8Array(buffer); });
  }

  function openChunk(keys, prefix, index, isFinal, sealed, cascade, aad) {
    return subtle.decrypt(
      {
        name: 'AES-GCM', iv: chunkNonce(prefix, index, isFinal),
        additionalData: aad, tagLength: TAG_BYTES * 8
      },
      keys.aes,
      sealed
    ).then(function (buffer) {
      var staged = new Uint8Array(buffer);
      return cascade
        ? C.chacha20(keys.chacha, chunkNonce(prefix, index, isFinal), 1, staged)
        : staged;
    });
  }

  function payloadKeys(dataKey, cascade) {
    return hkdf(dataKey, new Uint8Array(0), 'glintbox/aes', KEY_BYTES)
      .then(function (aesRaw) {
        return importAes(aesRaw).then(function (aes) {
          if (!cascade) return { aes: aes, chacha: null };
          return hkdf(dataKey, new Uint8Array(0), 'glintbox/chacha', KEY_BYTES)
            .then(function (chacha) { return { aes: aes, chacha: chacha }; });
        });
      });
  }

  /* ------------------------------------------------------------ header */

  // The core is every parameter that governs decryption, without the wrapped
  // keys. It is fed as AAD to both the slot wrapping and every chunk, so any
  // edit to the cost parameters, flags, nonce prefix or length fails
  // authentication instead of quietly weakening the file.
  function buildCore(profile, flags, slotMeta, prefix, payloadLength) {
    var params = PROFILES[profile];
    var fixed = new Uint8Array(7 + 1 + 1 + 1 + 1 + 1 + 1 + 7 + 8 + 1);
    var view = new DataView(fixed.buffer);
    var at = 0;
    fixed.set(MAGIC, at); at += MAGIC.length;
    fixed[at++] = FORMAT;
    fixed[at++] = params.logN;
    fixed[at++] = params.r;
    fixed[at++] = params.p;
    fixed[at++] = params.chunkLog;
    fixed[at++] = flags;
    fixed.set(prefix, at); at += 7;
    view.setUint32(at, Math.floor(payloadLength / 4294967296)); at += 4;
    view.setUint32(at, payloadLength >>> 0); at += 4;
    fixed[at++] = slotMeta.length;
    return concat([fixed].concat(slotMeta.map(function (m) { return m; })));
  }

  // type | salt | nonce | credential id length | credential id
  // The credential id is not secret; the file carries it so the browser knows
  // which security key to ask for. Length-prefixed, so it may be absent.
  function slotMetaBytes(slot) {
    var id = slot.credentialId || new Uint8Array(0);
    var meta = new Uint8Array(1 + 16 + 12 + 2 + id.length);
    meta[0] = slot.type;
    meta.set(slot.salt, 1);
    meta.set(slot.nonce, 17);
    new DataView(meta.buffer).setUint16(29, id.length);
    meta.set(id, 31);
    return meta;
  }

  function buildHeader(profile, flags, slots, prefix, payloadLength) {
    var params = PROFILES[profile];
    var fixed = new Uint8Array(7 + 1 + 1 + 1 + 1 + 1 + 1 + 7 + 8 + 1);
    var view = new DataView(fixed.buffer);
    var at = 0;
    fixed.set(MAGIC, at); at += MAGIC.length;
    fixed[at++] = FORMAT;
    fixed[at++] = params.logN;
    fixed[at++] = params.r;
    fixed[at++] = params.p;
    fixed[at++] = params.chunkLog;
    fixed[at++] = flags;
    fixed.set(prefix, at); at += 7;
    view.setUint32(at, Math.floor(payloadLength / 4294967296)); at += 4;
    view.setUint32(at, payloadLength >>> 0); at += 4;
    fixed[at++] = slots.length;

    var parts = [fixed];
    slots.forEach(function (slot) {
      parts.push(slotMetaBytes(slot), slot.wrapped);
    });
    return concat(parts);
  }

  function parseHeader(bytes) {
    for (var i = 0; i < MAGIC.length; i++) {
      if (bytes[i] !== MAGIC[i]) throw new Error('Not a .glintbox file.');
    }
    var at = MAGIC.length;
    var format = bytes[at++];
    if (format !== FORMAT) throw new Error('Made by a different version of the format.');

    var logN = bytes[at++], r = bytes[at++], p = bytes[at++];
    var chunkLog = bytes[at++];
    var flags = bytes[at++];
    var prefix = bytes.slice(at, at + 7); at += 7;
    var view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    var payloadLength = view.getUint32(at) * 4294967296 + view.getUint32(at + 4); at += 8;
    var slotCount = bytes[at++];

    var profile = null;
    Object.keys(PROFILES).forEach(function (name) {
      var candidate = PROFILES[name];
      if (candidate.logN === logN && candidate.r === r && candidate.p === p &&
          candidate.cascade === !!(flags & FLAG_CASCADE)) {
        profile = name;
      }
    });
    if (!profile) throw new Error('Unrecognised cost parameters in this file.');

    var slots = [];
    for (var s = 0; s < slotCount; s++) {
      var type = bytes[at++];
      var salt = bytes.slice(at, at + 16); at += 16;
      var nonce = bytes.slice(at, at + 12); at += 12;
      var idLength = view.getUint16(at); at += 2;
      var credentialId = bytes.slice(at, at + idLength); at += idLength;
      var wrapped = bytes.slice(at, at + KEY_BYTES + TAG_BYTES); at += KEY_BYTES + TAG_BYTES;
      slots.push({
        type: type, salt: salt, nonce: nonce,
        credentialId: credentialId, wrapped: wrapped
      });
    }

    return {
      profile: profile, flags: flags, prefix: prefix, chunkLog: chunkLog,
      payloadLength: payloadLength, slots: slots, headerLength: at,
      core: buildCore(profile, flags, slots.map(slotMetaBytes), prefix, payloadLength)
    };
  }

  /* ------------------------------------------------------------- seal */

  /**
   * seal(payload, {passphrase, tokenSecret, profile, onProgress})
   * -> {file: Uint8Array, recoveryKey: Uint8Array}
   *
   * The recovery key is returned once and never stored: split it with
   * GLINTShamir and distribute the shares.
   */
  // tokenSecret may be raw bytes or a function(slotSalt) -> Promise<bytes>.
  // The salt is generated in here, so the function form is what callers want:
  // it lets the token be touched at exactly the right moment.
  function resolveToken(tokenSecret, slotSalt) {
    if (typeof tokenSecret === 'function') return Promise.resolve(tokenSecret(slotSalt));
    return Promise.resolve(tokenSecret || null);
  }

  function seal(payload, options) {
    options = options || {};
    var profile = options.profile || 'strong';
    if (!PROFILES[profile]) throw new Error('Unknown profile: ' + profile);
    if (!options.passphrase && !options.tokenSecret) {
      throw new Error('A passphrase or a security key is required.');
    }

    var params = PROFILES[profile];
    var cascade = params.cascade;
    var dataKey = randomBytes(KEY_BYTES);
    var recoveryKey = randomBytes(KEY_BYTES);
    var prefix = randomBytes(7);
    var flags = (cascade ? FLAG_CASCADE : 0) | (options.tokenSecret ? FLAG_TOKEN : 0);

    // Salts and nonces are drawn first so the core exists before anything is
    // wrapped: the core is the AAD that binds all of it together.
    var pending = [
      {
        type: SLOT_PASSPHRASE, salt: randomBytes(16), nonce: randomBytes(12),
        credentialId: options.credentialId || new Uint8Array(0)
      },
      { type: SLOT_RECOVERY, salt: randomBytes(16), nonce: randomBytes(12) }
    ];
    var core = buildCore(profile, flags, pending.map(slotMetaBytes), prefix, payload.length);

    function wrap(slot, keyMaterialPromise) {
      return keyMaterialPromise(slot.salt).then(function (raw) {
        return importAes(raw).then(function (key) {
          return subtle.encrypt(
            { name: 'AES-GCM', iv: slot.nonce, additionalData: core }, key, dataKey
          );
        });
      }).then(function (buffer) {
        return {
          type: slot.type, salt: slot.salt, nonce: slot.nonce,
          credentialId: slot.credentialId, wrapped: new Uint8Array(buffer)
        };
      });
    }

    return Promise.all([
      wrap(pending[0], function (salt) {
        return resolveToken(options.tokenSecret, salt).then(function (secret) {
          return deriveSlotKey(options.passphrase, secret, salt, profile);
        });
      }),
      wrap(pending[1], function (salt) {
        return hkdf(recoveryKey, salt, 'glintbox/recovery', KEY_BYTES);
      })
    ]).then(function (slots) {
      var header = buildHeader(profile, flags, slots, prefix, payload.length);
      return payloadKeys(dataKey, cascade).then(function (keys) {
        var chunkSize = 1 << params.chunkLog;
        var chunkCount = Math.max(1, Math.ceil(payload.length / chunkSize));
        var pieces = [header];

        function step(index) {
          if (index >= chunkCount) return Promise.resolve();
          var start = index * chunkSize;
          var slice = payload.subarray(start, Math.min(start + chunkSize, payload.length));
          var isFinal = index === chunkCount - 1;
          return sealChunk(keys, prefix, index, isFinal, slice, cascade, core).then(function (sealed) {
            pieces.push(sealed);
            if (options.onProgress) options.onProgress((index + 1) / chunkCount);
            return step(index + 1);
          });
        }

        return step(0).then(function () {
          return { file: concat(pieces), recoveryKey: recoveryKey, profile: profile };
        });
      });
    });
  }

  /* ------------------------------------------------------------- open */

  /**
   * open(file, {passphrase, tokenSecret, recoveryKey, onProgress}) -> Uint8Array
   * Supply either the passphrase (plus token, if the file used one) or a
   * recovery key reassembled from Shamir shares.
   */
  function open(file, options) {
    options = options || {};
    var header;
    try {
      header = parseHeader(file);
    } catch (e) {
      return Promise.reject(e);
    }

    var cascade = !!(header.flags & FLAG_CASCADE);
    if ((header.flags & FLAG_TOKEN) && !options.tokenSecret && !options.recoveryKey) {
      return Promise.reject(new Error('This file needs its security key.'));
    }

    var slot, material;
    if (options.recoveryKey) {
      slot = header.slots.filter(function (s) { return s.type === SLOT_RECOVERY; })[0];
      if (!slot) return Promise.reject(new Error('This file has no recovery slot.'));
      material = hkdf(options.recoveryKey, slot.salt, 'glintbox/recovery', KEY_BYTES);
    } else {
      slot = header.slots.filter(function (s) { return s.type === SLOT_PASSPHRASE; })[0];
      if (!slot) return Promise.reject(new Error('This file has no passphrase slot.'));
      material = resolveToken(options.tokenSecret, slot.salt).then(function (secret) {
        return deriveSlotKey(options.passphrase, secret, slot.salt, header.profile);
      });
    }

    return material
      .then(function (raw) { return importAes(raw); })
      .then(function (key) {
        return subtle.decrypt(
          { name: 'AES-GCM', iv: slot.nonce, additionalData: header.core }, key, slot.wrapped
        );
      })
      .catch(function () {
        throw new Error(options.recoveryKey
          ? 'That recovery key does not open this file.'
          : 'Wrong passphrase or security key.');
      })
      .then(function (buffer) {
        var dataKey = new Uint8Array(buffer);
        return payloadKeys(dataKey, cascade);
      })
      .then(function (keys) {
        var chunkSize = 1 << header.chunkLog;
        var sealedSize = chunkSize + TAG_BYTES;
        var body = file.subarray(header.headerLength);
        var chunkCount = Math.max(1, Math.ceil(header.payloadLength / chunkSize));
        var out = new Uint8Array(header.payloadLength);
        var written = 0;

        function step(index) {
          if (index >= chunkCount) return Promise.resolve();
          var start = index * sealedSize;
          var isFinal = index === chunkCount - 1;
          var end = isFinal ? body.length : start + sealedSize;
          var sealed = body.subarray(start, end);
          return openChunk(keys, header.prefix, index, isFinal, sealed, cascade, header.core)
            .catch(function () {
              throw new Error('This file has been altered or damaged (chunk ' + index + ').');
            })
            .then(function (plain) {
              out.set(plain, written);
              written += plain.length;
              if (options.onProgress) options.onProgress((index + 1) / chunkCount);
              return step(index + 1);
            });
        }

        return step(0).then(function () {
          if (written !== header.payloadLength) {
            throw new Error('This file is truncated.');
          }
          return out;
        });
      });
  }

  /* --------------------------------------------------------- streaming */

  /*
   * The functions above hold the whole payload in memory. These stream it a
   * chunk at a time, so peak use is one chunk regardless of file size.
   *
   * The payload length still has to be known up front, because it is part of
   * the authenticated header — which is fine for a File, whose size is known.
   */

  // Re-cut an arbitrary stream into pieces of exactly `size` bytes, with a
  // possibly-shorter final piece. Sources deliver whatever sizes they like.
  async function* exactChunks(stream, size) {
    var reader = stream.getReader();
    var buffer = new Uint8Array(size);
    var filled = 0;
    while (true) {
      var step = await reader.read();
      if (step.done) break;
      var input = step.value;
      var offset = 0;
      while (offset < input.length) {
        var take = Math.min(size - filled, input.length - offset);
        buffer.set(input.subarray(offset, offset + take), filled);
        filled += take;
        offset += take;
        if (filled === size) {
          yield buffer.slice(0, size);
          filled = 0;
        }
      }
    }
    if (filled > 0) yield buffer.slice(0, filled);
  }

  // Prepend bytes to a stream without copying the stream's contents.
  function withPrefix(prefix, stream) {
    var emitted = false;
    var reader = stream.getReader();
    return new ReadableStream({
      async pull(controller) {
        if (!emitted) {
          emitted = true;
          if (prefix && prefix.length) { controller.enqueue(prefix); return; }
        }
        var step = await reader.read();
        if (step.done) controller.close();
        else controller.enqueue(step.value);
      },
      cancel(reason) { return reader.cancel(reason); }
    });
  }

  /**
   * sealStream({stream, length}, sink, options) -> {recoveryKey, profile, bytesWritten}
   *
   * `sink` needs a write(chunk) and a close(); a FileSystemWritableFileStream
   * satisfies it directly, so the ciphertext goes to disk as it is produced.
   */
  async function sealStream(source, sink, options) {
    options = options || {};
    var profile = options.profile || 'strong';
    if (!PROFILES[profile]) throw new Error('Unknown profile: ' + profile);
    if (!options.passphrase && !options.tokenSecret) {
      throw new Error('A passphrase or a security key is required.');
    }

    var params = PROFILES[profile];
    var cascade = params.cascade;
    var dataKey = randomBytes(KEY_BYTES);
    var recoveryKey = randomBytes(KEY_BYTES);
    var prefix = randomBytes(7);
    var flags = (cascade ? FLAG_CASCADE : 0) | (options.tokenSecret ? FLAG_TOKEN : 0);

    var pending = [
      {
        type: SLOT_PASSPHRASE, salt: randomBytes(16), nonce: randomBytes(12),
        credentialId: options.credentialId || new Uint8Array(0)
      },
      { type: SLOT_RECOVERY, salt: randomBytes(16), nonce: randomBytes(12) }
    ];
    var core = buildCore(profile, flags, pending.map(slotMetaBytes), prefix, source.length);

    async function wrap(slot, material) {
      var raw = await material;
      var key = await importAes(raw);
      var wrapped = await subtle.encrypt(
        { name: 'AES-GCM', iv: slot.nonce, additionalData: core }, key, dataKey);
      return {
        type: slot.type, salt: slot.salt, nonce: slot.nonce,
        credentialId: slot.credentialId, wrapped: new Uint8Array(wrapped)
      };
    }

    var slots = await Promise.all([
      wrap(pending[0], resolveToken(options.tokenSecret, pending[0].salt)
        .then(function (secret) {
          return deriveSlotKey(options.passphrase, secret, pending[0].salt, profile);
        })),
      wrap(pending[1], hkdf(recoveryKey, pending[1].salt, 'glintbox/recovery', KEY_BYTES))
    ]);

    var header = buildHeader(profile, flags, slots, prefix, source.length);
    await sink.write(header);
    var written = header.length;

    var keys = await payloadKeys(dataKey, cascade);
    var chunkSize = 1 << params.chunkLog;
    var chunkCount = Math.max(1, Math.ceil(source.length / chunkSize));
    var index = 0;

    for await (var piece of exactChunks(source.stream, chunkSize)) {
      var isFinal = index === chunkCount - 1;
      var sealed = await sealChunk(keys, prefix, index, isFinal, piece, cascade, core);
      await sink.write(sealed);
      written += sealed.length;
      piece.fill(0);
      index++;
      if (options.onProgress) options.onProgress(index / chunkCount);
    }

    // An empty payload still gets one (empty) final chunk, so that every file
    // carries an authentication tag and the buffered reader agrees.
    if (index === 0 && chunkCount === 1) {
      var empty = await sealChunk(keys, prefix, 0, true, new Uint8Array(0), cascade, core);
      await sink.write(empty);
      written += empty.length;
      index = 1;
    }

    if (index !== chunkCount) {
      throw new Error('The file changed size while it was being encrypted.');
    }

    await sink.close();
    return { recoveryKey: recoveryKey, profile: profile, bytesWritten: written };
  }

  /**
   * openStream(file, sink, options) -> {bytesWritten}
   * `file` is a Blob or File; only one chunk is held at a time.
   */
  async function openStream(file, sink, options) {
    options = options || {};

    // The header is small but variable; 8 KB covers any slot layout.
    var front = new Uint8Array(await file.slice(0, Math.min(8192, file.size)).arrayBuffer());
    var header = parseHeader(front);
    var cascade = !!(header.flags & FLAG_CASCADE);

    if ((header.flags & FLAG_TOKEN) && !options.tokenSecret && !options.recoveryKey) {
      throw new Error('This file needs its security key.');
    }

    var slot, material;
    if (options.recoveryKey) {
      slot = header.slots.filter(function (s) { return s.type === SLOT_RECOVERY; })[0];
      if (!slot) throw new Error('This file has no recovery slot.');
      material = hkdf(options.recoveryKey, slot.salt, 'glintbox/recovery', KEY_BYTES);
    } else {
      slot = header.slots.filter(function (s) { return s.type === SLOT_PASSPHRASE; })[0];
      if (!slot) throw new Error('This file has no passphrase slot.');
      material = resolveToken(options.tokenSecret, slot.salt).then(function (secret) {
        return deriveSlotKey(options.passphrase, secret, slot.salt, header.profile);
      });
    }

    var dataKey;
    try {
      var key = await importAes(await material);
      dataKey = new Uint8Array(await subtle.decrypt(
        { name: 'AES-GCM', iv: slot.nonce, additionalData: header.core }, key, slot.wrapped));
    } catch (e) {
      throw new Error(options.recoveryKey
        ? 'That recovery key does not open this file.'
        : 'Wrong passphrase or security key.');
    }

    var keys = await payloadKeys(dataKey, cascade);
    var chunkSize = 1 << header.chunkLog;
    var chunkCount = Math.max(1, Math.ceil(header.payloadLength / chunkSize));
    var body = file.slice(header.headerLength);
    var index = 0;
    var written = 0;

    for await (var sealed of exactChunks(body.stream(), chunkSize + TAG_BYTES)) {
      var isFinal = index === chunkCount - 1;
      var plain;
      try {
        plain = await openChunk(keys, header.prefix, index, isFinal, sealed, cascade, header.core);
      } catch (e) {
        throw new Error('This file has been altered or damaged (chunk ' + index + ').');
      }
      await sink.write(plain);
      written += plain.length;
      index++;
      if (options.onProgress) options.onProgress(index / chunkCount);
    }

    if (written !== header.payloadLength) throw new Error('This file is truncated.');
    await sink.close();
    return { bytesWritten: written };
  }

  /**
   * What does this file require? Readable without any secret, so the UI can
   * prompt correctly (and ask for the right security key) before decrypting.
   */
  function inspect(file) {
    var header = parseHeader(file);
    var passphraseSlot = header.slots.filter(function (s) {
      return s.type === SLOT_PASSPHRASE;
    })[0];
    return {
      profile: header.profile,
      cascade: !!(header.flags & FLAG_CASCADE),
      needsToken: !!(header.flags & FLAG_TOKEN),
      credentialId: passphraseSlot ? passphraseSlot.credentialId : new Uint8Array(0),
      slotSalt: passphraseSlot ? passphraseSlot.salt : null,
      payloadLength: header.payloadLength,
      hasRecoverySlot: header.slots.some(function (s) { return s.type === SLOT_RECOVERY; })
    };
  }

  global.GLINTBox = {
    seal: seal,
    open: open,
    sealStream: sealStream,
    openStream: openStream,
    withPrefix: withPrefix,
    inspect: inspect,
    parseHeader: parseHeader,
    PROFILES: PROFILES
  };
})(typeof window !== 'undefined' ? window : globalThis);
