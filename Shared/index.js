// Sections adapted from https://git.coolaj86.com/coolaj86/le-challenge-dns.js

const tls = require('tls');
const crypto = require('crypto');
const {promisify} = require('util');
const LE = require('greenlock');
const azureRest = require('ms-rest-azure');
const AzWebsiteClient = require('azure-arm-website');
const {create: createPfx} = require('@jmshal/pfx');
const config = require('../config.json');
const CfChallenge = require('./challenge');
const StorageStore = require('./store');

const production = process.env.NODE_ENV === 'production';


async function run(context, appName, resourceGroup = config.resourceGroup) {
  // Get webapp
  const creds = await azureRest.loginWithServicePrincipalSecret(config.clientId, config.secret, config.domain);
  let websiteClient = new AzWebsiteClient(creds, config.subscriptionId);

  let app = await websiteClient.webApps.get(resourceGroup, appName);
  if (!app) throw new Error(`Failed to get web app "${appName}" in resource group "${resourceGroup}"`);
  context.log(`Retrieved app "${appName}", with hostnames ${app.enabledHostNames}`);

  // Get hostnames
  const hostnames = await getHostnamesToRenew(context, app.enabledHostNames); // TODO try here
  if(!hostnames.length) throw new Error('No hostnames were ready to be renewed!');

  // Get cert
  context.log(`Initialising certbot in ${production ? 'production' : 'development'} mode...`);
  const store = await StorageStore.create({
    storage: config.storage,
    context,
    configBlobName: `greenlock-${production ? 'prod' : 'dev'}.json`});
  const cfChallenge = CfChallenge.create({context, cloudflare: config.cloudflare});
  let le = LE.create({
    // debug: true,
    store,
    version: 'v02',
    server: production ?
      'https://acme-v02.api.letsencrypt.org/directory' :
      'https://acme-staging-v02.api.letsencrypt.org/directory',
    challenges: {'dns-01': cfChallenge},
    challengeType: 'dns-01'
  });

  context.log(`Creating cert with domains: ${hostnames}`);
  let cert = await le.register({
    domains: hostnames,
    email: config.le.email,
    agreeTos: true,
    rsaKeySize: 2048,
    challengeType: 'dns-01'
  });

  context.log(`Successfully created cert!`);
  context.log(cert.identifiers);

  // Convert to PFX
  const pfxPass = (await promisify(crypto.randomBytes)(20)).toString('hex'); // Generates a 40 character long string
  const pfxBuf = await createPfx({
    cert: cert.cert,
    privateKey: cert.privkey,
    password: pfxPass
  });
  const thumbprint = (await execWithInput('openssl', ['x509', '-noout', '-fingerprint'], cert.cert))
    .split('=')[1]
    .replace(/:/g, '')
    .slice(0, -1); // Why does this function even exist
  // require('fs').writeFile('/Users/asher/Desktop/FunctionPfx.pfx', pfxBuf);

  // Upload to webapp
  const name = app.defaultHostName + '-' + thumbprint;

  context.log(`Uploading Certificate ${name}`);
  try {
    const resp = await websiteClient.certificates.createOrUpdate(resourceGroup, name, {
      pfxBlob: pfxBuf,
      serverFarmId: app.serverFarmId,
      location: app.location,
      password: pfxPass
    });
    context.log(resp.id);
  } catch(e) {
    context.log(e);
  }

  // Bind to webapp
  if(production) {
    // Update each hostname binding
    app.hostNameSslStates.forEach(sslState => {
      context.log(`${sslState.name} is in SSLState ${sslState.sslState}`);
      if(hostnames.includes(sslState.name)) {
        sslState.sslState = 'SniEnabled';
        sslState.thumbprint = thumbprint;
        sslState.toUpdate = true;
      }
    });
    // Save the changes
    await websiteClient.webApps.beginCreateOrUpdate(resourceGroup, app.name, app);
  } else { // Or delete, if in dev
    await websiteClient.certificates.deleteMethod(resourceGroup, name);
    context.log('Certificate successfully generated, uploaded, and removed! Dry run complete!');
  }
}

async function getHostnamesToRenew(context, hostnames) {
  let toRenew = [];
  hostnames = hostnames.filter(h => !h.endsWith('azurewebsites.net')); // Ignore Azure owned domains

  await Promise.all(hostnames.map(hostname => new Promise((resolve, reject) => {
    try {
      let socket = tls.connect(443, hostname, null, () => {
        const issuedAt = new Date(socket.getPeerCertificate().valid_from);
        const age = (new Date() - issuedAt) / (1000 * 60 * 60); // Age in hours
        if(age < (24 * 7)) { // If it's less than a week old
          context.log(`IGNORING ${hostname}: ${age} hours old`);
        } else {
          context.log(`RENEWING ${hostname}: ${age} hours old`);
          toRenew.push(hostname);
        }
        socket.end();
        resolve();
      });
      socket.on('error', e => {
        if(e.code === 'ERR_TLS_CERT_ALTNAME_INVALID') { // Doesn't have a valid cert, setup first one
          toRenew.push(hostname);
          resolve();
        } else {
          reject(e);
        }
      });
    } catch (e) {
      // Failed to connect for some reason, let's try giving it a new cert.
      if(!toRenew.includes(hostname))
        toRenew.push(hostname);
      resolve();
    }
  })));

  return toRenew;
}

function execWithInput(command, args, input) {
  return new Promise((resolve, reject) => {
    const proc = require('child_process').spawn(command, args);
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


module.exports = run;
