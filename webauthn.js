/*
 * webauthn.js — deriving key material from a hardware token.
 *
 * Uses the WebAuthn PRF extension (CTAP2's hmac-secret underneath): the
 * authenticator returns HMAC-SHA256(secret_in_key, salt) for a salt we
 * choose. The secret never leaves the token's secure element, and the same
 * credential with the same salt returns the same 32 bytes forever.
 *
 * Two properties make this the right primitive here:
 *
 *   1. It is SYMMETRIC. The token's signing keys are ECDSA, which a
 *      cryptographically relevant quantum computer would break; HMAC-SHA256
 *      is not affected. Key material stays post-quantum safe.
 *
 *   2. It BINDS rather than gates. The output is mixed into the KDF, so
 *      without the token the key does not exist. Compare a check like
 *      "did the token respond? then proceed", which any attacker with the
 *      file simply skips by not running our code.
 *
 * If the PRF extension is unavailable we fail loudly. Silently falling back
 * to a presence check would look identical to the user while providing no
 * cryptographic protection whatsoever.
 */
(function (global) {
  'use strict';

  var RP_NAME = 'GLINT';
  var CREDENTIAL_TIMEOUT = 60000;

  function randomBytes(n) {
    var out = new Uint8Array(n);
    global.crypto.getRandomValues(out);
    return out;
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

  function isAvailable() {
    return !!(global.PublicKeyCredential && global.navigator.credentials &&
      global.isSecureContext);
  }

  /**
   * Enrol a token. Must be called from a user gesture (a click).
   * Returns {credentialId, prfEnabled}. Store credentialId — it is not
   * secret, and the file needs it to know which credential to ask for.
   */
  function register(options) {
    options = options || {};
    if (!isAvailable()) {
      return Promise.reject(new Error(
        'Security keys need a browser with WebAuthn over HTTPS (or localhost).'));
    }

    var request = {
      challenge: randomBytes(32),
      rp: { name: options.rpName || RP_NAME },
      user: {
        id: randomBytes(16),
        name: options.userName || 'glint',
        displayName: options.userName || 'GLINT key'
      },
      // ES256, EdDSA, RS256 — the credential's signature algorithm is
      // irrelevant to us (we only use PRF) but one must be offered.
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -8 },
        { type: 'public-key', alg: -257 }
      ],
      authenticatorSelection: {
        // A roaming key can move between machines; a platform authenticator
        // would tie the data to one device.
        authenticatorAttachment: options.attachment || 'cross-platform',
        residentKey: 'preferred',
        userVerification: 'preferred'
      },
      timeout: CREDENTIAL_TIMEOUT,
      attestation: 'none',
      extensions: { prf: {} }
    };

    return global.navigator.credentials.create({ publicKey: request })
      .then(function (credential) {
        if (!credential) throw new Error('Enrolment was cancelled.');
        var results = credential.getClientExtensionResults();
        var enabled = !!(results && results.prf && results.prf.enabled);
        return {
          credentialId: new Uint8Array(credential.rawId),
          credentialIdText: toBase64Url(new Uint8Array(credential.rawId)),
          prfEnabled: enabled
        };
      });
  }

  /**
   * Ask the token for 32 bytes derived from `salt`. Must be called from a
   * user gesture. The same credential and salt always return the same bytes.
   */
  function evaluate(credentialId, salt, options) {
    options = options || {};
    if (!isAvailable()) {
      return Promise.reject(new Error('Security keys are not available in this browser.'));
    }
    if (!(salt instanceof Uint8Array) || salt.length < 32) {
      return Promise.reject(new Error('PRF salt must be at least 32 bytes.'));
    }

    var request = {
      challenge: randomBytes(32),
      timeout: CREDENTIAL_TIMEOUT,
      userVerification: 'preferred',
      extensions: { prf: { eval: { first: salt } } }
    };
    // With no credential id we rely on a discoverable credential, which keeps
    // the id out of the file at the cost of the user picking the right key.
    if (credentialId && credentialId.length) {
      request.allowCredentials = [{ type: 'public-key', id: credentialId }];
    }

    return global.navigator.credentials.get({ publicKey: request })
      .then(function (assertion) {
        if (!assertion) throw new Error('The security key did not respond.');
        var results = assertion.getClientExtensionResults();
        var first = results && results.prf && results.prf.results && results.prf.results.first;
        if (!first) {
          throw new Error(
            'This security key does not support the PRF extension, so it cannot ' +
            'derive encryption keys. A key with FIDO2 hmac-secret is required ' +
            '(YubiKey 5 series and later).');
        }
        var secret = new Uint8Array(first);
        if (secret.length < 32) throw new Error('The security key returned too little material.');
        return secret;
      });
  }

  /**
   * The PRF salt is derived from the slot salt so it is stable for a file and
   * different across files: the same token yields unrelated keys per file.
   */
  function prfSalt(slotSalt) {
    var prefix = new TextEncoder().encode('glintbox/prf/v1');
    var combined = new Uint8Array(prefix.length + slotSalt.length);
    combined.set(prefix, 0);
    combined.set(slotSalt, prefix.length);
    return global.crypto.subtle.digest('SHA-256', combined).then(function (hash) {
      return new Uint8Array(hash);
    });
  }

  global.GLINTToken = {
    isAvailable: isAvailable,
    register: register,
    evaluate: evaluate,
    prfSalt: prfSalt,
    toBase64Url: toBase64Url,
    fromBase64Url: fromBase64Url
  };
})(typeof window !== 'undefined' ? window : globalThis);
