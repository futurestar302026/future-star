// Run after npm install: node setup-owner.js
// This script does not save your plain-text password.
const readline = require('readline');
const bcrypt = require('bcryptjs');

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
function hiddenPrompt(prompt) {
  return new Promise(resolve => {
    process.stdout.write(prompt);
    const stdin = process.stdin;
    let value = '';
    if (stdin.isTTY) stdin.setRawMode(true);
    stdin.resume();
    const onData = ch => {
      ch = ch.toString();
      if (ch === '\u0003') process.exit(1);
      if (ch === '\r' || ch === '\n') {
        stdin.removeListener('data', onData);
        if (stdin.isTTY) stdin.setRawMode(false);
        process.stdout.write('\n');
        resolve(value);
      } else if (ch === '\u007f' || ch === '\b') value = value.slice(0, -1);
      else value += ch;
    };
    stdin.on('data', onData);
  });
}
(async () => {
  rl.close();
  const email = (process.env.ADMIN_EMAIL || 'futurestar302026@gmail.com').trim().toLowerCase();
  const password = await hiddenPrompt('Enter your owner password (minimum 12 characters): ');
  if (password.length < 12) {
    console.error('Password must be at least 12 characters.');
    process.exit(1);
  }
  const hash = await bcrypt.hash(password, 12);
  console.log('\nAdd these as PRIVATE environment variables in your hosting dashboard:');
  console.log(`ADMIN_EMAIL=${email}`);
  console.log(`ADMIN_PASSWORD_HASH=${hash}`);
  console.log('\nDo not put the plain password or this hash in public files, GitHub, or a shared repository.');
  process.exit(0);
})().catch(err => { console.error('Could not create password hash:', err.message); process.exit(1); });
