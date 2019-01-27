const fs = require('fs-extra');
const child_process = require('child_process');
const os = require('os');
const path = require('path');

const openSslCommand = os.platform() === 'win32' ? path.resolve('/bin/openssl') : 'openssl';

async function getCertFingerprint(cert) {
  return (await execWithInput(openSslCommand, ['x509', '-noout', '-fingerprint'], cert))
    .split('=')[1]
    .replace(/:/g, '')
    .slice(0, -1);
}

// Adapted from https://github.com/jmshal/pfx/ to allow for windows quirks
async function generatePfx({context, cert, privateKey, password}) {
  const tempPath = os.tmpdir();
  // context.log('Given temp path: ' + tempPath);
  context.log('Using temp path: ' + tempPath);

  const certPath = path.resolve(tempPath, 'cert.crt.tmp');
  const privateKeyPath = path.resolve(tempPath, 'private.pem.tmp');
  const outPath = path.resolve(tempPath, 'output.pfx.tmp');

  await fs.outputFile(certPath, cert);
  await fs.outputFile(privateKeyPath, privateKey);

  // context.log('Running exec!');
  // context.log('Cert size: ' + fs.statSync(certPath).size);
  const command = `${esc(openSslCommand)} pkcs12 -export \\
  -out "${esc(outPath)}" \\
  -inkey "${esc(privateKeyPath)}" \\
  -in "${esc(certPath)}" \\
  -password "pass:${password}"`;
  const pfxStdout = await exec(command);

  // context.log('PfxStdout' + pfxStdout);
  // context.log('Reading output');
  // context.log(fs.statSync(outPath));
  // context.log('Stat\'d');
  const pfx = await fs.readFile(outPath);
  // context.log('Cleaning up...');
  await fs.unlink(certPath);
  await fs.unlink(privateKeyPath);
  await fs.unlink(outPath);
  // context.log('Clean!');
  return pfx;
}

function exec(command) {
  return new Promise((resolve, reject) => {
    child_process.exec(command, (err, stdout, stderr) => {
      if (err) reject(new Error(stderr));
      else resolve(stdout);
    });
  });
}
function execWithInput(command, args, input) {
  return new Promise((resolve, reject) => {
    const proc = child_process.spawn(command, args);
    let output = '';
    proc.stdout.setEncoding('utf8');
    proc.stdout.on('data', chunk => {
      output += chunk;
      if (chunk.endsWith('\n')) {
        proc.stdin.end();
        return resolve(output);
      }
    });
    proc.stdin.write(input);
  })
}

function esc(str) {
  return str.replace('\\', '\\\\')
}

module.exports = {
  getCertFingerprint,
  generatePfx
};
