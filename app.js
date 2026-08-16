/*
 * app.js — the GLINT interface.
 *
 * Everything here is presentation and plumbing; all cryptography lives in
 * container.js, crypto.js, shamir.js and webauthn.js.
 */
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };

  var state = {
    plainFile: null,      // {name, bytes} staged for locking
    sealedFile: null,     // {name, bytes} staged for unlocking
    credential: null,     // enrolled security key
    lastResult: null      // most recent seal, for the shares panel
  };

  /* ------------------------------------------------------ payload envelope */

  // The container stores raw bytes, so the original filename rides along in a
  // tiny envelope inside the encrypted payload — which means the name is
  // encrypted too, not sitting in the clear.
  var ENVELOPE_MAGIC = 0x47463101; // "GF1\x01"

  function wrapPayload(name, bytes) {
    var nameBytes = new TextEncoder().encode(name || '');
    var out = new Uint8Array(4 + 2 + nameBytes.length + bytes.length);
    var view = new DataView(out.buffer);
    view.setUint32(0, ENVELOPE_MAGIC);
    view.setUint16(4, nameBytes.length);
    out.set(nameBytes, 6);
    out.set(bytes, 6 + nameBytes.length);
    return out;
  }

  function unwrapPayload(bytes) {
    if (bytes.length < 6) return { name: 'recovered.bin', bytes: bytes };
    var view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (view.getUint32(0) !== ENVELOPE_MAGIC) return { name: 'recovered.bin', bytes: bytes };
    var nameLength = view.getUint16(4);
    var name = new TextDecoder().decode(bytes.subarray(6, 6 + nameLength));
    return { name: name || 'recovered.bin', bytes: bytes.slice(6 + nameLength) };
  }

  /* ------------------------------------------------------------- helpers */

  function bytesToBase64Url(bytes) {
    var binary = '';
    for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function base64UrlToBytes(text) {
    var padded = text.trim().replace(/-/g, '+').replace(/_/g, '/');
    while (padded.length % 4) padded += '=';
    var binary = atob(padded);
    var out = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  }

  function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
    return (bytes / 1073741824).toFixed(2) + ' GB';
  }

  function download(bytes, name) {
    var blob = new Blob([bytes], { type: 'application/octet-stream' });
    var url = URL.createObjectURL(blob);
    var link = document.createElement('a');
    link.href = url;
    link.download = name;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  function readFile(file) {
    return new Promise(function (resolve, reject) {
      var reader = new FileReader();
      reader.onload = function () { resolve(new Uint8Array(reader.result)); };
      reader.onerror = function () { reject(new Error('Could not read that file.')); };
      reader.readAsArrayBuffer(file);
    });
  }

  function status(element, text, kind) {
    element.textContent = text;
    element.className = 'status' + (kind ? ' ' + kind : '');
  }

  /* --------------------------------------------------------- security key */

  // Returns a function the container calls with its slot salt, so the key is
  // touched at the exact moment its output is needed.
  function tokenProvider(credentialId) {
    return function (slotSalt) {
      return GLINTToken.prfSalt(slotSalt).then(function (salt) {
        return GLINTToken.evaluate(credentialId, salt);
      });
    };
  }

  function updateKeyUi() {
    var enrolled = !!state.credential;
    $('key-state').textContent = enrolled
      ? 'Enrolled (' + state.credential.credentialId.length + '-byte credential)'
      : 'No key enrolled';
    $('key-state').className = 'key-state' + (enrolled ? ' good' : '');
    $('enrol').textContent = enrolled ? 'Enrol a different key' : 'Enrol security key';
  }

  $('enrol').addEventListener('click', function () {
    status($('lock-status'), 'Touch your security key…');
    GLINTToken.register({ userName: 'glint' })
      .then(function (result) {
        if (!result.prfEnabled) {
          throw new Error('That key does not support PRF, so it cannot derive keys. ' +
            'A FIDO2 key with hmac-secret is required (YubiKey 5 or later).');
        }
        state.credential = result;
        updateKeyUi();
        status($('lock-status'), 'Security key enrolled.', 'good');
      })
      .catch(function (error) { status($('lock-status'), error.message, 'bad'); });
  });

  /* --------------------------------------------------------- passphrases */

  function refreshStrength() {
    var result = GLINTPassphrase.estimate($('lock-pass').value);
    var el = $('strength-read');
    el.textContent = result.verdict === 'empty'
      ? result.advice
      : '~' + result.bits + ' bits · ' + result.verdict + ' — ' + result.advice;
    el.className = 'strength ' + (result.verdict === 'very strong' ? 'very' : result.verdict);
  }

  $('lock-pass').addEventListener('input', refreshStrength);

  $('generate-pass').addEventListener('click', function () {
    var generated = GLINTPassphrase.generate(5);
    $('lock-pass').value = generated.text;
    $('lock-pass').type = 'text';
    $('show-pass').textContent = 'Hide';
    refreshStrength();

    // Show it plainly, once: it has to be written down before it is used.
    var existing = document.querySelector('.generated-pass');
    if (existing) existing.remove();
    var box = document.createElement('p');
    box.className = 'generated-pass';
    box.textContent = generated.text +
      '  —  write this down now, it is not stored anywhere';
    $('lock-pass').parentNode.insertAdjacentElement('afterend', box);
  });

  $('show-pass').addEventListener('click', function () {
    var field = $('lock-pass');
    field.type = field.type === 'password' ? 'text' : 'password';
    this.textContent = field.type === 'password' ? 'Show' : 'Hide';
  });

  /* ------------------------------------------------------------- locking */

  // Where the browser can save a file directly, encryption streams to disk a
  // chunk at a time and memory stays flat. Without that API the whole file is
  // held in the tab, so size becomes a memory question.
  var canStreamToDisk = typeof window.showSaveFilePicker === 'function';

  function warnAboutSize(bytes) {
    var warning = $('size-warning');
    if (bytes < 200 * 1024 * 1024) { warning.hidden = true; return; }
    warning.hidden = false;
    warning.textContent = canStreamToDisk
      ? 'Large file — it will be written straight to disk as it encrypts, so ' +
        'memory stays flat. You will be asked where to save it.'
      : 'This browser cannot save straight to disk, so the whole file is held ' +
        'in the tab and needs roughly ' + formatSize(bytes * 4) + ' of free ' +
        'memory. Chrome or Edge will stream it instead.';
  }

  function stagePlain(file) {
    // Keep the File itself: streaming reads from it directly, and reading the
    // bytes now would defeat the point for anything large.
    state.plainFile = { name: file.name, file: file, bytes: null };
    $('lock-drop').textContent = file.name + ' · ' + formatSize(file.size);
    $('lock-drop').classList.add('loaded');
    warnAboutSize(file.size);
    status($('lock-status'), '');
  }

  $('lock-file').addEventListener('change', function (event) {
    if (event.target.files[0]) stagePlain(event.target.files[0]);
  });

  $('lock').addEventListener('click', function () {
    var passphrase = $('lock-pass').value;
    var text = $('lock-text').value;

    if (!state.plainFile && !text) {
      return status($('lock-status'), 'Choose a file or type a message first.', 'bad');
    }
    var strength = GLINTPassphrase.estimate(passphrase);
    if (strength.bits < 40) {
      return status($('lock-status'),
        'That passphrase is too weak (about ' + strength.bits + ' bits). ' +
        strength.advice, 'bad');
    }

    var source = state.plainFile ||
      { name: 'message.txt', bytes: new TextEncoder().encode(text), file: null };
    var useKey = $('use-key').checked;

    if (useKey && !state.credential) {
      return status($('lock-status'), 'Enrol a security key first, or untick the box.', 'bad');
    }

    $('lock').disabled = true;
    var started = performance.now();
    status($('lock-status'), useKey ? 'Touch your security key…' : 'Deriving key…');

    var options = {
      passphrase: passphrase,
      profile: $('profile').value,
      onProgress: function (fraction) {
        status($('lock-status'), 'Encrypting… ' + Math.round(fraction * 100) + '%');
      }
    };
    if (useKey) {
      options.credentialId = state.credential.credentialId;
      options.tokenSecret = tokenProvider(state.credential.credentialId);
    }

    var finish = function () { $('lock').disabled = false; };
    var report = function (result, bytes, headerBytes) {
      var elapsed = (performance.now() - started) / 1000;
      showShares(result.recoveryKey, headerBytes);
      status($('lock-status'),
        'Sealed ' + formatSize(bytes) + ' in ' + elapsed.toFixed(1) + ' s.', 'good');
    };

    lockWith(options, source, report).catch(function (error) {
      if (error && error.name === 'AbortError') {
        status($('lock-status'), 'Cancelled.');
      } else {
        status($('lock-status'), error.message, 'bad');
      }
    }).then(finish);
  });

  // Streams the file through the encryptor and onto disk. The filename
  // envelope is prepended to the stream rather than copied in front of the
  // whole payload.
  async function lockWith(options, source, report) {
    var envelope = wrapPayload(source.name, new Uint8Array(0));
    var length = envelope.length + (source.file ? source.file.size : source.bytes.length);
    var body = source.file ? source.file.stream() : new Blob([source.bytes]).stream();
    var input = { stream: GLINTBox.withPrefix(envelope, body), length: length };

    if (canStreamToDisk) {
      var handle = await window.showSaveFilePicker({
        suggestedName: source.name + '.glintbox',
        types: [{ description: 'GLINT container', accept: { 'application/octet-stream': ['.glintbox'] } }]
      });
      var writable = await handle.createWritable();

      // The header is needed afterwards to tag the recovery shares, so keep a
      // copy of the first write — it is a couple of hundred bytes.
      var headerBytes = null;
      var sink = {
        write: function (chunk) {
          if (!headerBytes) headerBytes = Uint8Array.from(chunk);
          return writable.write(chunk);
        },
        close: function () { return writable.close(); }
      };
      var result = await GLINTBox.sealStream(input, sink, options);
      report(result, result.bytesWritten, headerBytes);
      return;
    }

    // Fallback: collect the parts as a Blob, which browsers can page to disk,
    // rather than one enormous contiguous array.
    var parts = [];
    var first = null;
    var collected = {
      write: function (chunk) {
        var copy = Uint8Array.from(chunk);
        if (!first) first = copy;
        parts.push(copy);
        return Promise.resolve();
      },
      close: function () { return Promise.resolve(); }
    };
    var streamed = await GLINTBox.sealStream(input, collected, options);
    var blob = new Blob(parts, { type: 'application/octet-stream' });
    var url = URL.createObjectURL(blob);
    var link = document.createElement('a');
    link.href = url;
    link.download = source.name + '.glintbox';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
    report(streamed, streamed.bytesWritten, first);
  }

  /* -------------------------------------------------------------- shares */

  function renderQr(text) {
    var qr = QRCode.encode(text, { ecc: 'Q' });
    var scale = 3;
    var quiet = 4;
    var size = (qr.size + quiet * 2) * scale;
    var canvas = document.createElement('canvas');
    canvas.width = canvas.height = size;
    var ctx = canvas.getContext('2d');
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, size, size);
    ctx.fillStyle = '#000000';
    for (var y = 0; y < qr.size; y++) {
      for (var x = 0; x < qr.size; x++) {
        if (qr.modules[y][x]) {
          ctx.fillRect((x + quiet) * scale, (y + quiet) * scale, scale, scale);
        }
      }
    }
    return canvas;
  }

  function showShares(recoveryKey, fileBytes) {
    var shares = GLINTShamir.split(recoveryKey, 2, 3);
    var container = $('shares');
    container.innerHTML = '';

    var core = GLINTBox.parseHeader(fileBytes).core;   // header bytes suffice
    GLINTShamir.fileTag(core).then(function (tag) { renderShares(shares, tag); });
  }

  function renderShares(shares, tag) {
    var container = $('shares');
    shares.forEach(function (share, index) {
      var text = GLINTShamir.encodeShare(share, tag);
      var card = document.createElement('div');
      card.className = 'share';

      var title = document.createElement('h4');
      title.textContent = 'Share ' + (index + 1) + ' of 3';
      card.appendChild(title);
      card.appendChild(renderQr(text));

      var code = document.createElement('textarea');
      code.readOnly = true;
      code.rows = 2;
      code.value = text;
      card.appendChild(code);

      container.appendChild(card);
    });

    $('shares-panel').hidden = false;
    $('shares-panel').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  $('print-shares').addEventListener('click', function () { window.print(); });

  /* ----------------------------------------------------------- unlocking */

  function stageSealed(file) {
    readFile(file).then(function (bytes) {
      state.sealedFile = { name: file.name, bytes: bytes, file: file };
      var info;
      try {
        info = GLINTBox.inspect(bytes);
      } catch (error) {
        return status($('unlock-status'), error.message, 'bad');
      }
      $('unlock-drop').textContent = file.name + ' · ' + formatSize(bytes.length);
      $('unlock-drop').classList.add('loaded');
      $('file-facts').hidden = false;
      $('file-facts').textContent =
        'Profile: ' + info.profile +
        ' · cascade: ' + (info.cascade ? 'yes' : 'no') +
        ' · security key: ' + (info.needsToken ? 'required' : 'not used') +
        ' · payload: ' + formatSize(info.payloadLength);
      status($('unlock-status'), '');
    }).catch(function (error) { status($('unlock-status'), error.message, 'bad'); });
  }

  $('unlock-file').addEventListener('change', function (event) {
    if (event.target.files[0]) stageSealed(event.target.files[0]);
  });

  $('recovery-toggle').addEventListener('change', function () {
    $('recovery-fields').hidden = !this.checked;
    $('passphrase-fields').hidden = this.checked;
  });

  $('unlock').addEventListener('click', function () {
    if (!state.sealedFile) {
      return status($('unlock-status'), 'Choose a .glintbox file first.', 'bad');
    }

    var options = {};
    var info = GLINTBox.inspect(state.sealedFile.bytes);

    if ($('recovery-toggle').checked) {
      var entries = [$('share-a').value, $('share-b').value]
        .map(function (v) { return v.trim(); })
        .filter(Boolean);
      if (entries.length < 2) {
        return status($('unlock-status'), 'Two different shares are needed.', 'bad');
      }
      try {
        var shares = entries.map(function (entry) {
          return GLINTShamir.decodeShare(entry).share;
        });
        options.recoveryKey = GLINTShamir.combine(shares);
      } catch (error) {
        return status($('unlock-status'), error.message, 'bad');
      }
    } else {
      options.passphrase = $('unlock-pass').value;
      if (info.needsToken) {
        if (!info.credentialId.length) {
          return status($('unlock-status'),
            'This file needs a security key but records no credential.', 'bad');
        }
        options.tokenSecret = tokenProvider(info.credentialId);
      }
    }

    $('unlock').disabled = true;
    var started = performance.now();
    status($('unlock-status'),
      info.needsToken && !options.recoveryKey ? 'Touch your security key…' : 'Deriving key…');

    options.onProgress = function (fraction) {
      status($('unlock-status'), 'Decrypting… ' + Math.round(fraction * 100) + '%');
    };

    unlockWith(options, started).catch(function (error) {
      if (error && error.name === 'AbortError') status($('unlock-status'), 'Cancelled.');
      else status($('unlock-status'), error.message, 'bad');
    }).then(function () { $('unlock').disabled = false; });
  });

  /* --------------------------------------------------------- image mode */

  var imageState = { carrier: null, sealed: null, toRead: null };

  $('img-amp').addEventListener('input', function () {
    $('amp-value').textContent = this.value;
  });

  // Draw an image file onto a canvas so we can read its pixels.
  function loadImagePixels(file) {
    return new Promise(function (resolve, reject) {
      var url = URL.createObjectURL(file);
      var image = new Image();
      image.onload = function () {
        var canvas = document.createElement('canvas');
        canvas.width = image.naturalWidth;
        canvas.height = image.naturalHeight;
        canvas.getContext('2d').drawImage(image, 0, 0);
        var data = canvas.getContext('2d').getImageData(0, 0, canvas.width, canvas.height);
        URL.revokeObjectURL(url);
        resolve(data);
      };
      image.onerror = function () {
        URL.revokeObjectURL(url);
        reject(new Error('That file is not an image this browser can read.'));
      };
      image.src = url;
    });
  }

  function stageCarrier(file) {
    loadImagePixels(file).then(function (data) {
      imageState.carrier = data;
      $('img-carrier-drop').textContent =
        file.name + ' · ' + data.width + '×' + data.height + ' — data will hide inside it';
      $('img-carrier-drop').classList.add('loaded');
    }).catch(function (error) { status($('img-status'), error.message, 'bad'); });
  }

  function stageToRead(file) {
    loadImagePixels(file).then(function (data) {
      imageState.toRead = data;
      $('img-read-drop').textContent = file.name + ' · ' + data.width + '×' + data.height;
      $('img-read-drop').classList.add('loaded');
    }).catch(function (error) { status($('img-read-status'), error.message, 'bad'); });
  }

  $('img-carrier').addEventListener('change', function (e) {
    if (e.target.files[0]) stageCarrier(e.target.files[0]);
  });
  $('img-read').addEventListener('change', function (e) {
    if (e.target.files[0]) stageToRead(e.target.files[0]);
  });

  $('img-encode').addEventListener('click', function () {
    var text = $('img-text').value;
    var passphrase = $('img-pass').value;
    if (!text) return status($('img-status'), 'Type the message to hide first.', 'bad');
    if (passphrase.length < 8) {
      return status($('img-status'), 'Use a passphrase of at least 8 characters.', 'bad');
    }

    var options = { amplitude: Number($('img-amp').value) };
    if (imageState.carrier) {
      options.carrier = {
        rgba: imageState.carrier.data,
        width: imageState.carrier.width,
        height: imageState.carrier.height
      };
    }

    $('img-encode').disabled = true;
    status($('img-status'), 'Encrypting and modulating…');

    GLINT.encode(new TextEncoder().encode(text), passphrase, options)
      .then(function (result) {
        var canvas = $('img-canvas');
        canvas.width = result.width;
        canvas.height = result.height;
        canvas.getContext('2d').putImageData(
          new ImageData(result.rgba, result.width, result.height), 0, 0);
        imageState.sealed = result;
        $('img-result').hidden = false;
        status($('img-status'),
          result.width + '×' + result.height + ' — ' +
          (imageState.carrier ? 'hidden inside your photo' : 'standalone code') +
          '. Save as PNG; it survives being re-saved as JPEG afterwards.', 'good');
      })
      .catch(function (error) { status($('img-status'), error.message, 'bad'); })
      .then(function () { $('img-encode').disabled = false; });
  });

  $('img-download').addEventListener('click', function () {
    $('img-canvas').toBlob(function (blob) {
      var reader = new FileReader();
      reader.onload = function () {
        download(new Uint8Array(reader.result), 'glint-image.png');
      };
      reader.readAsArrayBuffer(blob);
    }, 'image/png');
  });

  $('img-decode').addEventListener('click', function () {
    if (!imageState.toRead) {
      return status($('img-read-status'), 'Drop a GLINT image first.', 'bad');
    }
    $('img-decode').disabled = true;
    status($('img-read-status'), 'Reading…');

    GLINT.decode(imageState.toRead, $('img-read-pass').value)
      .then(function (result) {
        $('img-out').hidden = false;
        $('img-out').value = new TextDecoder().decode(result.bytes);
        status($('img-read-status'),
          result.corrected
            ? 'Recovered, repairing ' + result.corrected + ' damaged bytes along the way.'
            : 'Recovered cleanly — no damage to repair.', 'good');
      })
      .catch(function (error) {
        $('img-out').hidden = true;
        status($('img-read-status'), error.message, 'bad');
      })
      .then(function () { $('img-decode').disabled = false; });
  });

  // The original filename is the first few bytes of the decrypted stream, but
  // the save dialog needs a name before decryption starts — so the envelope is
  // stripped on the way through and the suggested name comes from the
  // container's own filename.
  function envelopeStrippingSink(inner) {
    var pending = new Uint8Array(0);
    var skipped = false;
    var toSkip = 0;

    function append(a, b) {
      var out = new Uint8Array(a.length + b.length);
      out.set(a, 0); out.set(b, a.length);
      return out;
    }

    return {
      write: function (chunk) {
        if (skipped) return inner.write(chunk);
        pending = append(pending, chunk);
        if (pending.length < 6) return Promise.resolve();
        if (!toSkip) {
          var view = new DataView(pending.buffer, pending.byteOffset, pending.byteLength);
          toSkip = view.getUint32(0) === ENVELOPE_MAGIC ? 6 + view.getUint16(4) : 0;
          if (!toSkip) { skipped = true; var all = pending; pending = null; return inner.write(all); }
        }
        if (pending.length < toSkip) return Promise.resolve();
        skipped = true;
        var rest = pending.slice(toSkip);
        pending = null;
        return rest.length ? inner.write(rest) : Promise.resolve();
      },
      close: function () { return inner.close(); }
    };
  }

  async function unlockWith(options, started) {
    var sealedName = state.sealedFile.name.replace(/\.glintbox$/i, '') || 'recovered';

    if (canStreamToDisk) {
      var handle = await window.showSaveFilePicker({ suggestedName: sealedName });
      var writable = await handle.createWritable();
      var sink = envelopeStrippingSink({
        write: function (chunk) { return writable.write(chunk); },
        close: function () { return writable.close(); }
      });
      var result = await GLINTBox.openStream(state.sealedFile.file, sink, options);
      status($('unlock-status'),
        'Opened ' + formatSize(result.bytesWritten) + ' in ' +
        ((performance.now() - started) / 1000).toFixed(1) + ' s.', 'good');
      return;
    }

    var payload = await GLINTBox.open(state.sealedFile.bytes, options);
    var original = unwrapPayload(payload);
    download(original.bytes, original.name);
    status($('unlock-status'),
      'Opened in ' + ((performance.now() - started) / 1000).toFixed(1) +
      ' s. Downloaded as ' + original.name, 'good');
  }

  /* -------------------------------------------------------- share checker */

  $('check-share-btn').addEventListener('click', function () {
    var text = $('check-share').value;
    if (!text.trim()) return status($('check-status'), 'Paste a share to check.', 'bad');

    var decoded;
    try {
      decoded = GLINTShamir.decodeShare(text);
    } catch (error) {
      return status($('check-status'), error.message, 'bad');
    }

    if (decoded.legacy) {
      return status($('check-status'),
        'Readable, but made before checksums existed — so a typo in it cannot be ' +
        'detected. Re-issue your shares to get checkable ones.', 'fair');
    }

    if (!state.sealedFile) {
      return status($('check-status'),
        'Share ' + decoded.index + ' is intact. Load a .glintbox above to also check ' +
        'that it belongs to that file.', 'good');
    }

    GLINTShamir.fileTag(GLINTBox.parseHeader(state.sealedFile.bytes).core)
      .then(function (tag) {
        if (GLINTShamir.sameTag(tag, decoded.tag)) {
          status($('check-status'),
            'Share ' + decoded.index + ' is intact and belongs to this file.', 'good');
        } else {
          status($('check-status'),
            'Share ' + decoded.index + ' is intact, but it was issued for a different ' +
            'file. Check you have the right one.', 'bad');
        }
      });
  });

  /* ----------------------------------------------------------- benchmark */

  $('bench').addEventListener('click', function () {
    $('bench').disabled = true;
    var output = $('bench-out');
    output.hidden = false;
    output.textContent = 'Measuring on this machine…\n';

    var payload = new Uint8Array(2 * 1024 * 1024);
    crypto.getRandomValues(payload.subarray(0, 65536));
    var profiles = ['fast', 'strong'];

    profiles.reduce(function (chain, profile) {
      return chain.then(function () {
        var started = performance.now();
        return GLINTBox.seal(payload, { passphrase: 'benchmark', profile: profile })
          .then(function (result) {
            var sealed = performance.now();
            return GLINTBox.open(result.file, { passphrase: 'benchmark' })
              .then(function () {
                var opened = performance.now();
                var mb = payload.length / 1048576;
                output.textContent +=
                  profile.padEnd(8) +
                  ' lock ' + ((sealed - started) / 1000).toFixed(2) + ' s' +
                  ' (' + (mb / ((sealed - started) / 1000)).toFixed(1) + ' MB/s)' +
                  '   unlock ' + ((opened - sealed) / 1000).toFixed(2) + ' s' +
                  ' (' + (mb / ((opened - sealed) / 1000)).toFixed(1) + ' MB/s)\n';
              });
          });
      });
    }, Promise.resolve())
      .then(function () {
        output.textContent += '\n2 MB payload. Most of the time is key derivation, ' +
          'which is a fixed cost per file — larger files are proportionally faster.';
      })
      .catch(function (error) { output.textContent += '\nFailed: ' + error.message; })
      .then(function () { $('bench').disabled = false; });
  });

  /* ---------------------------------------------------------------- tabs */

  Array.prototype.forEach.call(document.querySelectorAll('.tab'), function (tab) {
    tab.addEventListener('click', function () {
      Array.prototype.forEach.call(document.querySelectorAll('.tab'), function (other) {
        var on = other === tab;
        other.classList.toggle('is-active', on);
        other.setAttribute('aria-selected', on ? 'true' : 'false');
        $('pane-' + other.dataset.pane).hidden = !on;
      });
    });
  });

  // Drag and drop onto either panel.
  [['lock-drop', stagePlain], ['unlock-drop', stageSealed],
   ['img-carrier-drop', stageCarrier], ['img-read-drop', stageToRead]].forEach(function (pair) {
    var zone = $(pair[0]);
    var handler = pair[1];
    ['dragenter', 'dragover'].forEach(function (name) {
      zone.addEventListener(name, function (event) {
        event.preventDefault();
        zone.classList.add('over');
      });
    });
    ['dragleave', 'drop'].forEach(function (name) {
      zone.addEventListener(name, function (event) {
        event.preventDefault();
        zone.classList.remove('over');
      });
    });
    zone.addEventListener('drop', function (event) {
      if (event.dataTransfer.files[0]) handler(event.dataTransfer.files[0]);
    });
  });

  if (!GLINTToken.isAvailable()) {
    $('enrol').disabled = true;
    $('key-state').textContent = 'Security keys need HTTPS or localhost';
  }
  updateKeyUi();
})();
