/*
 * coverage.js — makes an unwired test suite a build failure.
 *
 * A workflow only runs the steps it knows about, so a test file that is never
 * referenced simply does not run, and CI stays green while verifying less
 * than it appears to. That happened twice in this repo: the workflow ran four
 * suites while seven existed, and nothing anywhere said so.
 *
 * This checks that every suite in test/ is wired into the workflow. Files that
 * are deliberately not suites must be named below, so adding one forces a
 * decision instead of silently shrinking coverage.
 */
const fs = require('fs');
const path = require('path');

const TEST_DIR = __dirname;
const WORKFLOW = path.join(__dirname, '..', '.github', 'workflows', 'test.yml');

// Not pass/fail suites. Anything here is excluded on purpose, with a reason.
const NOT_SUITES = {
  'coverage.js': 'this file',
  'bench.js': 'a benchmark — reports numbers, never fails'
};

let problems = [];

const suites = fs.readdirSync(TEST_DIR)
  .filter(name => name.endsWith('.js'))
  .sort();

if (!fs.existsSync(WORKFLOW)) {
  console.error('No workflow found at .github/workflows/test.yml');
  process.exit(1);
}
const workflow = fs.readFileSync(WORKFLOW, 'utf8');

// What the workflow actually runs.
const wired = new Set();
for (const match of workflow.matchAll(/run:\s*node\s+test\/([\w.-]+\.js)/g)) {
  wired.add(match[1]);
}

console.log('Test files found: ' + suites.length);
for (const name of suites) {
  if (NOT_SUITES[name]) {
    console.log('  skip  ' + name.padEnd(16) + NOT_SUITES[name]);
    continue;
  }
  if (wired.has(name)) {
    console.log('  wired ' + name);
  } else {
    console.log('  UNWIRED ' + name);
    problems.push('test/' + name + ' exists but no workflow step runs it');
  }
}

// And the reverse: a step pointing at a file that no longer exists would fail
// the build anyway, but say so clearly rather than as a module-not-found.
for (const name of wired) {
  if (!fs.existsSync(path.join(TEST_DIR, name))) {
    problems.push('the workflow runs test/' + name + ', which does not exist');
  }
}

if (problems.length) {
  console.error('\n' + problems.length + ' problem(s):');
  for (const p of problems) console.error('  - ' + p);
  console.error('\nAdd a step to .github/workflows/test.yml, or list the file in ' +
    'NOT_SUITES in test/coverage.js with a reason.');
  process.exit(1);
}

console.log('\nEvery suite is wired into CI.');
