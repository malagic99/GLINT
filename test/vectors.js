/* Test vectors from RFC 7914 (scrypt) and RFC 8439 (ChaCha20-Poly1305). */
require('../crypto.js');
const C = GLINTCrypto;
const enc = new TextEncoder();
const hex = (a) => Array.from(a).map(b => b.toString(16).padStart(2, '0')).join('');
const unhex = (s) => Uint8Array.from(s.replace(/[^0-9a-f]/gi, '').match(/../g).map(b => parseInt(b, 16)));

let pass = 0, fail = 0;
function check(name, got, want) {
  if (got === want) { pass++; console.log('  PASS  ' + name); }
  else { fail++; console.log('  FAIL  ' + name + '\n    got  ' + got + '\n    want ' + want); }
}

(async () => {
  console.log('RFC 7914 — scrypt');
  check('scrypt("","",N=16,r=1,p=1)',
    hex(await C.scrypt(enc.encode(''), enc.encode(''), 16, 1, 1, 64)),
    '77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906');

  check('scrypt("password","NaCl",N=1024,r=8,p=16)',
    hex(await C.scrypt(enc.encode('password'), enc.encode('NaCl'), 1024, 8, 16, 64)),
    'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640');

  check('scrypt("pleaseletmein","SodiumChloride",N=16384,r=8,p=1)',
    hex(await C.scrypt(enc.encode('pleaseletmein'), enc.encode('SodiumChloride'), 16384, 8, 1, 64)),
    '7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887');

  console.log('RFC 8439 — ChaCha20');
  const key = unhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const nonce = unhex('000000000000004a00000000');
  const plain = enc.encode("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
  check('ChaCha20 encryption (2.4.2)',
    hex(C.chacha20(key, nonce, 1, plain)),
    '6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d');

  console.log('RFC 8439 — Poly1305');
  check('Poly1305 tag (2.5.2)',
    hex(C.poly1305(unhex('85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b'),
                   enc.encode('Cryptographic Forum Research Group'))),
    'a8061dc1305136c6c22b8baf0c0127a9');

  console.log('RFC 8439 — ChaCha20-Poly1305 AEAD');
  const aeadKey = unhex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
  const aeadNonce = unhex('070000004041424344454647');
  const aad = unhex('50515253c0c1c2c3c4c5c6c7');
  const sealed = C.chachaSeal(aeadKey, aeadNonce, plain, aad);
  check('AEAD ciphertext (2.8.2)',
    hex(sealed.subarray(0, sealed.length - 16)),
    'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116');
  check('AEAD tag (2.8.2)',
    hex(sealed.subarray(sealed.length - 16)),
    '1ae10b594f09e26a7e902ecbd0600691');

  const opened = C.chachaOpen(aeadKey, aeadNonce, sealed, aad);
  check('AEAD round-trip', hex(opened), hex(plain));

  let rejected = false;
  const tampered = Uint8Array.from(sealed); tampered[3] ^= 1;
  try { C.chachaOpen(aeadKey, aeadNonce, tampered, aad); } catch (e) { rejected = true; }
  check('AEAD rejects tampering', String(rejected), 'true');

  let aadRejected = false;
  try { C.chachaOpen(aeadKey, aeadNonce, sealed, unhex('50515253c0c1c2c3c4c5c6c8')); } catch (e) { aadRejected = true; }
  check('AEAD rejects wrong AAD', String(aadRejected), 'true');

  console.log('\n' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail ? 1 : 0);
})();
