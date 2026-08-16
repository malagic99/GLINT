/*
 * passphrase.js — generating and judging passphrases.
 *
 * Every other layer in GLINT defends a secret that a human chose, so this is
 * where the real security of a file usually lives.
 *
 * Words are built from syllables rather than a dictionary, deliberately: a
 * 7776-word list would be more memorable, but its entropy claim rests on the
 * list being exactly what it claims (no duplicates, no near-duplicates, no
 * truncation in transit). Syllables give an entropy figure that is provable
 * from the code itself.
 *
 *   16 consonants x 4 vowels  = 64 syllables = exactly 6 bits each
 *   3 syllables per word                     = 18 bits per word
 *   5 words                                  = 90 bits
 *
 * 64 divides 256 exactly, so taking a random byte modulo 64 is unbiased.
 * Letters that are easily confused when read aloud or written down (c/k/q,
 * y, w, x) are left out.
 */
(function (global) {
  'use strict';

  var CONSONANTS = 'bdfghjklmnprstvz';   // 16
  var VOWELS = 'aeio';                   // 4
  var SYLLABLES_PER_WORD = 3;
  var BITS_PER_SYLLABLE = 6;

  function randomSyllable(byte) {
    // byte is 0..255; 64 syllables divide it evenly, so no modulo bias.
    var index = byte % 64;
    return CONSONANTS.charAt(index >> 2) + VOWELS.charAt(index & 3);
  }

  /**
   * generate(words) -> {text, bits}
   * Default 5 words, which is 90 bits — far beyond what any offline attack
   * reaches when it is also behind a memory-hard KDF.
   */
  function generate(words) {
    words = words || 5;
    var bytes = new Uint8Array(words * SYLLABLES_PER_WORD);
    global.crypto.getRandomValues(bytes);

    var out = [];
    for (var w = 0; w < words; w++) {
      var word = '';
      for (var s = 0; s < SYLLABLES_PER_WORD; s++) {
        word += randomSyllable(bytes[w * SYLLABLES_PER_WORD + s]);
      }
      out.push(word);
    }
    bytes.fill(0);
    return {
      text: out.join('-'),
      bits: words * SYLLABLES_PER_WORD * BITS_PER_SYLLABLE
    };
  }

  /**
   * estimate(text) -> {bits, verdict, advice}
   *
   * A deliberate under-estimate for anything that looks like language, and
   * honest about being a guess. Real attackers use dictionaries, leaked
   * password corpora and mangling rules; no client-side function models that
   * well. Treat it as a floor, never as a promise.
   */
  function estimate(text) {
    if (!text) return { bits: 0, verdict: 'empty', advice: 'Nothing entered yet.' };

    // Our own generated passphrases have a known, exact strength.
    if (/^([bdfghjklmnprstvz][aeio]){3}(-([bdfghjklmnprstvz][aeio]){3})+$/.test(text)) {
      var words = text.split('-').length;
      return {
        bits: words * SYLLABLES_PER_WORD * BITS_PER_SYLLABLE,
        verdict: 'generated',
        advice: 'Generated here — this figure is exact, not an estimate.'
      };
    }

    var classes = 0;
    if (/[a-z]/.test(text)) classes += 26;
    if (/[A-Z]/.test(text)) classes += 26;
    if (/[0-9]/.test(text)) classes += 10;
    if (/[^a-zA-Z0-9]/.test(text)) classes += 32;
    var raw = text.length * Math.log2(Math.max(2, classes));

    // Penalties for the shapes people actually choose.
    var penalty = 1;
    if (/^[a-zA-Z]+$/.test(text)) penalty *= 0.45;              // a word or words
    if (/^[A-Z][a-z]+[0-9!.]*$/.test(text)) penalty *= 0.5;     // Capitalised+suffix
    if (/(.)\1{2,}/.test(text)) penalty *= 0.7;                 // repeats
    if (/^\d+$/.test(text)) penalty *= 0.3;                     // digits only
    if (/(19|20)\d\d/.test(text)) penalty *= 0.7;               // a year
    var bits = Math.round(raw * penalty);

    var verdict, advice;
    if (bits < 40) {
      verdict = 'weak';
      advice = 'An attacker with your file can try billions of these. Generate one instead.';
    } else if (bits < 60) {
      verdict = 'fair';
      advice = 'Survives casual attack, not a determined one. Longer is better.';
    } else if (bits < 80) {
      verdict = 'strong';
      advice = 'Good. Beyond reach of an ordinary offline attack.';
    } else {
      verdict = 'very strong';
      advice = 'Beyond brute force by any realistic means.';
    }
    return { bits: bits, verdict: verdict, advice: advice };
  }

  global.GLINTPassphrase = {
    generate: generate,
    estimate: estimate,
    SYLLABLE_COUNT: CONSONANTS.length * VOWELS.length
  };
})(typeof window !== 'undefined' ? window : globalThis);
