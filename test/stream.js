/* Streaming seal/open: correctness, format compatibility, and memory. */
require('../crypto.js');
require('../shamir.js');
require('../container.js');

const B = GLINTBox;
const PASS = 'streaming test passphrase';
let pass = 0, fail = 0;
const check = (n, c) => { if (c) { pass++; console.log('  PASS  ' + n); } else { fail++; console.log('  FAIL  ' + n); } };

// Collects everything written — fine for correctness tests, not for the
// memory test below, which discards instead.
function collectingSink() {
  const parts = [];
  return {
    parts,
    write(chunk) { parts.push(Uint8Array.from(chunk)); return Promise.resolve(); },
    close() { return Promise.resolve(); },
    bytes() {
      const total = parts.reduce((n, p) => n + p.length, 0);
      const out = new Uint8Array(total);
      let at = 0;
      for (const p of parts) { out.set(p, at); at += p.length; }
      return out;
    }
  };
}

function discardingSink() {
  let written = 0;
  return { write(c) { written += c.length; return Promise.resolve(); }, close() { return Promise.resolve(); },
           get written() { return written; } };
}

// A source that manufactures bytes on the fly, so the test itself never holds
// the whole payload — otherwise it could not measure streaming honestly.
function syntheticSource(length, chunkSize = 1 << 20) {
  let sent = 0;
  const stream = new ReadableStream({
    pull(controller) {
      if (sent >= length) { controller.close(); return; }
      const size = Math.min(chunkSize, length - sent);
      const piece = new Uint8Array(size);
      for (let i = 0; i < size; i += 512) piece[i] = (sent + i) & 0xff;
      sent += size;
      controller.enqueue(piece);
    }
  });
  return { stream, length };
}

const hex = a => Buffer.from(a).toString('hex');

(async () => {
  console.log('Round-trip across chunk boundaries (chunk = 1 MiB)');
  for (const size of [0, 1, 4096, 1048575, 1048576, 1048577, 2 * 1048576 + 33]) {
    const payload = new Uint8Array(size);
    for (let i = 0; i < size; i++) payload[i] = (i * 7 + 11) & 0xff;

    const sink = collectingSink();
    await B.sealStream({ stream: new Blob([payload]).stream(), length: size },
      sink, { passphrase: PASS, profile: 'fast' });

    const out = collectingSink();
    await B.openStream(new Blob([sink.bytes()]), out, { passphrase: PASS });
    check(`size ${size}`, hex(out.bytes()) === hex(payload));
  }

  console.log('Same format as the buffered path');
  const payload = new Uint8Array(3 * 1048576 + 7);
  for (let i = 0; i < payload.length; i++) payload[i] = (i * 13 + 5) & 0xff;

  const streamed = collectingSink();
  const sealed = await B.sealStream({ stream: new Blob([payload]).stream(), length: payload.length },
    streamed, { passphrase: PASS, profile: 'fast' });
  const viaBuffered = await B.open(streamed.bytes(), { passphrase: PASS });
  check('streamed file opens with the buffered reader', hex(viaBuffered) === hex(payload));

  const buffered = await B.seal(payload, { passphrase: PASS, profile: 'fast' });
  const viaStream = collectingSink();
  await B.openStream(new Blob([buffered.file]), viaStream, { passphrase: PASS });
  check('buffered file opens with the streaming reader', hex(viaStream.bytes()) === hex(payload));

  console.log('Recovery and failure paths still hold');
  const shares = GLINTShamir.split(sealed.recoveryKey, 2, 3);
  const recovered = collectingSink();
  await B.openStream(new Blob([streamed.bytes()]), recovered,
    { recoveryKey: GLINTShamir.combine([shares[0], shares[2]]) });
  check('opens with two recovery shares', hex(recovered.bytes()) === hex(payload));

  let refused = false;
  try {
    await B.openStream(new Blob([streamed.bytes()]), discardingSink(), { passphrase: 'wrong' });
  } catch (e) { refused = /Wrong passphrase/.test(e.message); }
  check('wrong passphrase refused', refused);

  let tamperCaught = false;
  const damaged = Uint8Array.from(streamed.bytes());
  damaged[damaged.length - 200] ^= 1;
  try {
    await B.openStream(new Blob([damaged]), discardingSink(), { passphrase: PASS });
  } catch (e) { tamperCaught = /altered or damaged/.test(e.message); }
  check('tampered chunk rejected', tamperCaught);

  let truncCaught = false;
  try {
    await B.openStream(new Blob([streamed.bytes().slice(0, streamed.bytes().length - 5000)]),
      discardingSink(), { passphrase: PASS });
  } catch (e) { truncCaught = true; }
  check('truncated file rejected', truncCaught);

  console.log('Memory — the point of the exercise');
  const SIZE = 512 * 1024 * 1024;   // 512 MB, never held in full by the test
  const before = process.memoryUsage().rss;
  let peak = before;
  const watch = setInterval(() => {
    const rss = process.memoryUsage().rss;
    if (rss > peak) peak = rss;
  }, 20);

  const nowhere = discardingSink();
  await B.sealStream(syntheticSource(SIZE), nowhere, { passphrase: PASS, profile: 'fast' });
  clearInterval(watch);

  const growthMb = (peak - before) / 1048576;
  console.log(`  sealed ${(SIZE / 1048576).toFixed(0)} MB, peak RSS growth ${growthMb.toFixed(1)} MB`);
  check(`memory stays flat while streaming 512 MB (grew ${growthMb.toFixed(1)} MB, limit 150)`,
    growthMb < 150);
  check('all bytes written', nowhere.written > SIZE);

  console.log('\n' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail ? 1 : 0);
})();
