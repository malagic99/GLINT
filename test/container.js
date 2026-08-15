require('../crypto.js'); require('../shamir.js'); require('../container.js');
const B = GLINTBox, S = GLINTShamir;
const hex = a => Array.from(a).map(b=>b.toString(16).padStart(2,'0')).join('');
let pass=0, fail=0;
const check=(n,c)=>{ if(c){pass++; console.log('  PASS  '+n);} else {fail++; console.log('  FAIL  '+n);} };
// getRandomValues caps at 64 KiB per call, so fill big buffers in slices.
const randomBuffer = (n) => {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 65536) crypto.getRandomValues(out.subarray(i, Math.min(i + 65536, n)));
  return out;
};

(async () => {
  const pass1 = 'correct horse battery staple';

  // round-trip across sizes and chunk boundaries (chunk = 1 MiB)
  console.log('Round-trip, profile=fast');
  for (const size of [0, 1, 255, 4096, 1048575, 1048576, 1048577, 3*1048576+7]) {
    const payload = randomBuffer(size);
    const { file } = await B.seal(payload, { passphrase: pass1, profile: 'fast' });
    const out = await B.open(file, { passphrase: pass1 });
    check(`size ${size} (${file.length - size} bytes overhead)`, hex(out) === hex(payload));
  }

  // cascade profile
  console.log('Cascade (profile=strong)');
  const payload = randomBuffer(200000);
  const strong = await B.seal(payload, { passphrase: pass1, profile: 'strong' });
  check('cascade round-trip', hex(await B.open(strong.file, { passphrase: pass1 })) === hex(payload));

  // wrong passphrase
  let rejected = false;
  try { await B.open(strong.file, { passphrase: 'wrong' }); } catch (e) { rejected = /Wrong passphrase/.test(e.message); }
  check('wrong passphrase rejected', rejected);

  // recovery via Shamir: any 2 of 3
  console.log('Shamir recovery path');
  const shares = S.split(strong.recoveryKey, 2, 3);
  for (const [a,b] of [[0,1],[0,2],[1,2]]) {
    const key = S.combine([shares[a], shares[b]]);
    const out = await B.open(strong.file, { recoveryKey: key });
    check(`recovered with shares ${a+1}+${b+1} (no passphrase)`, hex(out) === hex(payload));
  }
  let oneShareFails = false;
  try {
    await B.open(strong.file, { recoveryKey: shares[0].subarray(1) });
  } catch (e) { oneShareFails = true; }
  check('a single share does not open it', oneShareFails);

  // tamper detection at several offsets
  console.log('Tamper detection');
  for (const spot of ['header-flags', 'slot', 'body', 'last-byte']) {
    const bad = Uint8Array.from(strong.file);
    const idx = { 'header-flags': 12, 'slot': 40, 'body': 2000, 'last-byte': bad.length - 1 }[spot];
    bad[idx] ^= 0x01;
    let caught = false;
    try { await B.open(bad, { passphrase: pass1 }); } catch (e) { caught = true; }
    check('flip at ' + spot + ' rejected', caught);
  }

  // truncation
  let truncCaught = false;
  try { await B.open(strong.file.subarray(0, strong.file.length - 100), { passphrase: pass1 }); }
  catch (e) { truncCaught = true; }
  check('truncation rejected', truncCaught);

  // downgrade attack: rewrite scrypt cost in the header
  const downgraded = Uint8Array.from(strong.file);
  downgraded[8] = 2;              // logN 17 -> 2
  let downgradeCaught = false;
  try { await B.open(downgraded, { passphrase: pass1 }); } catch (e) { downgradeCaught = true; }
  check('KDF downgrade rejected', downgradeCaught);

  // Header binding: a correct recovery key must NOT open a file whose header
  // was edited. Without AAD the unwrap would succeed and only fail later.
  const edited = Uint8Array.from(strong.file);
  edited[21] ^= 0x01;             // inside the nonce prefix / length region
  let bindingHeld = false;
  try {
    await B.open(edited, { recoveryKey: S.combine([shares[0], shares[1]]) });
  } catch (e) { bindingHeld = true; }
  check('header edit breaks a VALID recovery key (AAD binding)', bindingHeld);

  console.log('\n' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail ? 1 : 0);
})();
