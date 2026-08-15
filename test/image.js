require('../glint.js');
const hex = a => Array.from(a).map(b=>b.toString(16).padStart(2,'0')).join('');
let pass=0, fail=0;
const check=(n,c)=>{ if(c){pass++; console.log('  PASS  '+n);} else {fail++; console.log('  FAIL  '+n);} };

(async () => {
  const enc = new TextEncoder(), dec = new TextDecoder();
  const secret = 'passphrase for the image layer';

  for (const text of ['hello', 'x'.repeat(500)]) {
    const payload = enc.encode(text);
    let img;
    try {
      img = await GLINT.encode(payload, secret, {});
    } catch (e) { check(`encode ${text.length}B`, false); console.log('    ' + e.message); continue; }
    check(`encode ${text.length}B -> ${img.width}x${img.height}`, img.width > 0);

    try {
      const out = await GLINT.decode({ width: img.width, height: img.height, data: img.rgba }, secret);
      check(`round-trip ${text.length}B`, dec.decode(out.bytes) === text);
    } catch (e) { check(`round-trip ${text.length}B`, false); console.log('    ' + e.message); }
  }

  // wrong passphrase must be rejected
  const img = await GLINT.encode(enc.encode('secret note'), secret, {});
  try {
    await GLINT.decode({ width: img.width, height: img.height, data: img.rgba }, 'wrong');
    check('wrong passphrase rejected', false);
  } catch (e) { check('wrong passphrase rejected', /passphrase|tamper/i.test(e.message)); }

  console.log('\n' + pass + ' passed, ' + fail + ' failed');
})();
