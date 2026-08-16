require('../shamir.js');
const S = GLINTShamir;
const hex = a => Array.from(a).map(b => b.toString(16).padStart(2, '0')).join('');
let pass = 0, fail = 0;
const check = (n, c) => { if (c) { pass++; console.log('  PASS  ' + n); } else { fail++; console.log('  FAIL  ' + n); } };

(async () => {
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const shares = S.split(secret, 2, 3);
  const tag = await S.fileTag(new TextEncoder().encode('pretend header core'));

  // round-trip
  const encoded = shares.map(s => S.encodeShare(s, tag));
  check('encoded shares carry the GLINT1 prefix', encoded.every(t => t.startsWith('GLINT1:')));
  const decoded = encoded.map(t => S.decodeShare(t));
  check('decode returns the original share bytes',
    decoded.every((d, i) => hex(d.share) === hex(shares[i])));
  check('decode returns the file tag', decoded.every(d => S.sameTag(d.tag, tag)));
  check('reconstructs from decoded shares',
    hex(S.combine([decoded[0].share, decoded[2].share])) === hex(secret));

  // typos: flip one character, in many positions
  let caught = 0, missed = 0;
  for (let i = 7; i < encoded[0].length; i++) {
    const ch = encoded[0][i];
    const swap = ch === 'A' ? 'B' : 'A';
    const typo = encoded[0].slice(0, i) + swap + encoded[0].slice(i + 1);
    try {
      const d = S.decodeShare(typo);
      if (hex(d.share) !== hex(shares[0])) missed++; else caught++;   // same bytes = harmless
    } catch (e) { caught++; }
  }
  check(`every single-character typo caught (${caught} caught, ${missed} missed)`, missed === 0);

  // truncation
  let truncCaught = false;
  try { S.decodeShare(encoded[1].slice(0, encoded[1].length - 4)); } catch (e) { truncCaught = true; }
  check('truncated share rejected', truncCaught);

  // wrong file
  const otherTag = await S.fileTag(new TextEncoder().encode('a different file'));
  check('a share from another file is detectable',
    !S.sameTag(S.decodeShare(S.encodeShare(shares[0], otherTag)).tag, tag));

  // legacy shares (no checksum) still readable
  const legacyText = 'GLINT1:' + Buffer.from(shares[0]).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const legacy = S.decodeShare(legacyText);
  check('shares made before checksums still decode', hex(legacy.share) === hex(shares[0]) && legacy.legacy);

  // whitespace and line breaks from a print-out
  const messy = ' ' + encoded[0].slice(0, 20) + '\n  ' + encoded[0].slice(20) + ' ';
  check('handles line breaks and stray spaces', hex(S.decodeShare(messy).share) === hex(shares[0]));

  console.log('\n' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail ? 1 : 0);
})();
