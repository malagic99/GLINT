require('../shamir.js');
const S = GLINTShamir;
const hex = a => Array.from(a).map(b=>b.toString(16).padStart(2,'0')).join('');
let pass=0, fail=0;
const check=(n,c)=>{ if(c){pass++;} else {fail++; console.log('  FAIL '+n);} };

// 2-of-3 across many random secrets, every possible pair
for (let t=0; t<300; t++) {
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const shares = S.split(secret, 2, 3);
  for (const [a,b] of [[0,1],[0,2],[1,2],[1,0],[2,0],[2,1]]) {
    check('pair '+a+b, hex(S.combine([shares[a],shares[b]]))===hex(secret));
  }
  check('all three', hex(S.combine(shares))===hex(secret));
}

// k-of-n generally
for (const [k,n] of [[2,2],[3,5],[4,4],[5,9],[2,255]]) {
  const secret = crypto.getRandomValues(new Uint8Array(16));
  const shares = S.split(secret, k, n);
  const picked = [];
  while (picked.length < k) {
    const i = Math.floor(Math.random()*n);
    if (!picked.includes(shares[i])) picked.push(shares[i]);
  }
  check(`${k}-of-${n}`, hex(S.combine(picked))===hex(secret));
  if (k > 2) {
    // k-1 shares must NOT reconstruct
    check(`${k}-of-${n} under-threshold`, hex(S.combine(picked.slice(0,k-1)))!==hex(secret));
  }
}

// duplicate shares rejected rather than silently wrong
try { const s=S.split(new Uint8Array(8),2,3); S.combine([s[0],s[0]]); check('duplicate rejected', false); }
catch(e){ check('duplicate rejected', true); }

// a single share must be independent of the secret: same share index,
// two different secrets -> payloads differ (no structure leaks through)
const s1 = S.split(new Uint8Array(32).fill(0), 2, 3);
const s2 = S.split(new Uint8Array(32).fill(255), 2, 3);
check('single share leaks nothing structural', hex(s1[0])!==hex(s2[0]));

// distribution sanity: first share bytes should look uniform over many splits
const counts = new Array(256).fill(0);
for (let i=0;i<20000;i++) counts[S.split(Uint8Array.of(0x42),2,3)[0][1]]++;
const expected = 20000/256;
const chi = counts.reduce((a,c)=>a+((c-expected)**2)/expected,0);
check('share bytes uniform (chi-square '+chi.toFixed(0)+' < 330)', chi < 330);

console.log(pass+' passed, '+fail+' failed');
process.exit(fail?1:0);
