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

  /* ------------------------------------------------------------- locking */

  function stagePlain(file) {
    readFile(file).then(function (bytes) {
      state.plainFile = { name: file.name, bytes: bytes };
      $('lock-drop').textContent = file.name + ' · ' + formatSize(bytes.length);
      $('lock-drop').classList.add('loaded');
      status($('lock-status'), '');
    }).catch(function (error) { status($('lock-status'), error.message, 'bad'); });
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
    if (passphrase.length < 8) {
      return status($('lock-status'), 'Use a passphrase of at least 8 characters — ' +
        'several random words beats one clever word.', 'bad');
    }

    var source = state.plainFile ||
      { name: 'message.txt', bytes: new TextEncoder().encode(text) };
    var payload = wrapPayload(source.name, source.bytes);
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

    GLINTBox.seal(payload, options)
      .then(function (result) {
        var elapsed = (performance.now() - started) / 1000;
        state.lastResult = result;
        download(result.file, source.name + '.glintbox');
        showShares(result.recoveryKey);
        status($('lock-status'),
          'Sealed ' + formatSize(result.file.length) + ' in ' + elapsed.toFixed(1) + ' s. ' +
          'Downloaded as ' + source.name + '.glintbox', 'good');
      })
      .catch(function (error) { status($('lock-status'), error.message, 'bad'); })
      .then(function () { $('lock').disabled = false; });
  });

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

  function showShares(recoveryKey) {
    var shares = GLINTShamir.split(recoveryKey, 2, 3);
    var container = $('shares');
    container.innerHTML = '';

    shares.forEach(function (share, index) {
      var text = 'GLINT1:' + bytesToBase64Url(share);
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
      state.sealedFile = { name: file.name, bytes: bytes };
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
          return base64UrlToBytes(entry.replace(/^GLINT1:/, ''));
        });
        options.recoveryKey = GLINTShamir.combine(shares);
      } catch (error) {
        return status($('unlock-status'), 'Those shares are not valid: ' + error.message, 'bad');
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

    GLINTBox.open(state.sealedFile.bytes, options)
      .then(function (payload) {
        var elapsed = (performance.now() - started) / 1000;
        var original = unwrapPayload(payload);
        download(original.bytes, original.name);
        status($('unlock-status'),
          'Opened in ' + elapsed.toFixed(1) + ' s. Downloaded as ' + original.name, 'good');
      })
      .catch(function (error) { status($('unlock-status'), error.message, 'bad'); })
      .then(function () { $('unlock').disabled = false; });
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
  [['lock-drop', stagePlain], ['unlock-drop', stageSealed]].forEach(function (pair) {
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
