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

  // Quiet mode: the payload rides on a carrier image instead of a blank one.
  const W = 256, H = 256;
  const carrier = new Uint8ClampedArray(W * H * 4);
  for (let y = 0; y < H; y++) {
    for (let x = 0; x < W; x++) {
      const i = (y * W + x) * 4;
      carrier[i]     = 90 + 60 * Math.sin(x / 40) + 30 * Math.sin(y / 13);
      carrier[i + 1] = 110 + 50 * Math.cos(y / 30) + 20 * Math.sin(x / 7);
      carrier[i + 2] = 130 + 40 * Math.sin((x + y) / 50);
      carrier[i + 3] = 255;
    }
  }
  const hidden = 'hidden in a photograph';
  const quiet = await GLINT.encode(enc.encode(hidden), secret, {
    carrier: { rgba: carrier, width: W, height: H }, amplitude: 18
  });
  check('quiet mode keeps the carrier size', quiet.width === W && quiet.height === H);

  let maxDelta = 0, total = 0;
  for (let i = 0; i < carrier.length; i += 4) {
    const d = Math.abs(quiet.rgba[i] - carrier[i]);
    if (d > maxDelta) maxDelta = d;
    total += d;
  }
  const meanDelta = total / (carrier.length / 4);
  check('carrier barely changes (mean ' + meanDelta.toFixed(2) + ' < 6)', meanDelta < 6);

  const revealed = await GLINT.decode({ width: W, height: H, data: quiet.rgba }, secret);
  check('quiet mode round-trip', dec.decode(revealed.bytes) === hidden);

  // A carrier too small for the payload must be refused, not silently
  // truncated. The payload has to be incompressible to actually be large:
  // 4000 repeated bytes deflate to almost nothing and would fit.
  const bulky = new Uint8Array(4000);
  for (let i = 0; i < bulky.length; i += 65536 / 65536) bulky[i] = (Math.random() * 256) | 0;
  try {
    await GLINT.encode(bulky, secret, { carrier: { rgba: carrier, width: W, height: H } });
    check('carrier too small is refused', false);
  } catch (e) { check('carrier too small is refused', /too small/i.test(e.message)); }

  console.log('\n' + pass + ' passed, ' + fail + ' failed');
})();
