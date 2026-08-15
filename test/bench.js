require('../crypto.js'); require('../shamir.js'); require('../container.js');
const B = GLINTBox;
const rand = n => { const a=new Uint8Array(n); for(let i=0;i<n;i+=65536) crypto.getRandomValues(a.subarray(i,Math.min(i+65536,n))); return a; };
const ms = t => (t).toFixed(0).padStart(6) + ' ms';

(async () => {
  console.log('KDF cost (once per file, independent of file size)');
  for (const name of ['fast','strong']) {
    const p = B.PROFILES[name];
    const t0 = performance.now();
    await GLINTCrypto.scrypt(new TextEncoder().encode('correct horse battery staple'),
      new Uint8Array(16), 1<<p.logN, p.r, p.p, 32);
    const dt = performance.now()-t0;
    console.log(`  ${name.padEnd(9)} N=2^${p.logN}  ${(128*(1<<p.logN)*p.r/1048576).toFixed(0).padStart(5)} MB  ${ms(dt)}`);
  }

  console.log('\nThroughput on an 8 MB payload');
  const payload = rand(8*1024*1024);
  for (const name of ['fast','strong']) {
    const t0 = performance.now();
    const { file } = await B.seal(payload, { passphrase: 'correct horse battery staple', profile: name });
    const t1 = performance.now();
    await B.open(file, { passphrase: 'correct horse battery staple' });
    const t2 = performance.now();
    const mb = payload.length/1048576;
    console.log(`  ${name.padEnd(9)} encode ${ms(t1-t0)} (${(mb/((t1-t0)/1000)).toFixed(1)} MB/s)   decode ${ms(t2-t1)} (${(mb/((t2-t1)/1000)).toFixed(1)} MB/s)`);
  }

  console.log('\nCipher-only throughput (KDF excluded)');
  const key = rand(32), nonce = rand(12);
  for (const size of [8*1024*1024]) {
    const data = rand(size);
    let t0 = performance.now(); GLINTCrypto.chacha20(key, nonce, 1, data); let dt = performance.now()-t0;
    console.log(`  ChaCha20 (hand-written JS)  ${(size/1048576/(dt/1000)).toFixed(1)} MB/s`);
    const aesKey = await crypto.subtle.importKey('raw', key, {name:'AES-GCM'}, false, ['encrypt']);
    t0 = performance.now(); await crypto.subtle.encrypt({name:'AES-GCM', iv:nonce}, aesKey, data); dt = performance.now()-t0;
    console.log(`  AES-256-GCM (WebCrypto)     ${(size/1048576/(dt/1000)).toFixed(1)} MB/s`);
  }
})();
