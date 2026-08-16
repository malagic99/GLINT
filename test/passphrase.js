require('../passphrase.js');
const P = GLINTPassphrase;
let pass = 0, fail = 0;
const check = (n, c) => { if (c) { pass++; console.log('  PASS  ' + n); } else { fail++; console.log('  FAIL  ' + n); } };

check('64 syllables exactly (6 bits each)', P.SYLLABLE_COUNT === 64);

const g = P.generate(5);
check('5 words -> 90 bits (' + g.text + ')', g.bits === 90);
check('shape is words of 3 syllables', /^([a-z]{6})(-[a-z]{6}){4}$/.test(g.text));
check('generate(7) -> 126 bits', P.generate(7).bits === 126);

// Uniformity: every syllable should appear about equally often.
const counts = new Map();
let total = 0;
for (let i = 0; i < 20000; i++) {
  const word = P.generate(1).text;
  for (let s = 0; s < 3; s++) { const syl = word.substr(s * 2, 2); counts.set(syl, (counts.get(syl) || 0) + 1); total++; }
}
check('all 64 syllables occur', counts.size === 64);
const expected = total / 64;
const chi = [...counts.values()].reduce((a, c) => a + (c - expected) ** 2 / expected, 0);
check('syllables uniformly distributed (chi-square ' + chi.toFixed(0) + ' < 110)', chi < 110);

// Uniqueness: generated passphrases must not repeat
const seen = new Set();
for (let i = 0; i < 5000; i++) seen.add(P.generate(5).text);
check('no collisions in 5000 generated passphrases', seen.size === 5000);

// Estimates
check('generated passphrase is recognised as exact', P.estimate(g.text).verdict === 'generated');
check('"password" is weak', P.estimate('password').bits < 40);
check('"Summer2024!" is not called strong', P.estimate('Summer2024!').bits < 60);
check('"12345678" is weak', P.estimate('12345678').bits < 40);
check('a long random string is very strong', P.estimate('7#kQm!zP2vX@rL9wTn$4').bits >= 80);
check('empty is empty', P.estimate('').verdict === 'empty');

console.log('\n' + pass + ' passed, ' + fail + ' failed');
process.exit(fail ? 1 : 0);
