// Sections adapted from https://git.coolaj86.com/coolaj86/le-challenge-dns.js
const crypto = require('crypto');
const {promisify} = require('util');
const LE = require('greenlock');
const azureRest = require('ms-rest-azure');
const AzWebsiteClient = require('azure-arm-website');
const config = require('../config.json');
const {getCertFingerprint, generatePfx} = require('./shell-tools');
const CfChallenge = require('./challenge');
const StorageStore = require('./store');

const production = process.env.NODE_ENV === 'production';

const LEServer = production ?
  'https://acme-v02.api.letsencrypt.org/directory' :
  'https://acme-staging-v02.api.letsencrypt.org/directory';

async function run(context, appName, resourceGroup = config.resourceGroup) {
  context.log(`Starting renewal! Node ${process.version}`);

  // *********************
  // Get webapp and info
  // *********************
  const creds = await azureRest.loginWithServicePrincipalSecret(config.clientId, config.secret, config.domain);
  let websiteClient = new AzWebsiteClient(creds, config.subscriptionId);

  let app = await websiteClient.webApps.get(resourceGroup, appName);
  if (!app) throw new Error(`Failed to get web app "${appName}" in resource group "${resourceGroup}"`);
  context.log(`Retrieved app "${appName}", with hostnames ${app.enabledHostNames}`);

  const hostnames = app.enabledHostNames.filter(h => !h.endsWith('azurewebsites.net')); // Ignore Azure owned domains
  if(!hostnames.length) throw new Error('No hostnames were ready to be renewed!');


  // *********************
  // Create cert
  // *********************
  config.storage.configBlobName = config.storage[production ? 'prodConfigBlobName' : 'devConfigBlobName'] || config.storage.configBlobName || null;
  context.log(`Initialising certbot in ${production ? 'production' : 'development'} mode...`);
  context.log(`Config file: ${config.storage.configBlobName} in ${config.storage.container}, ACME server: ${LEServer}`);
  const store = await StorageStore.create({
    storage: config.storage,
    context
  });

  if(config.dnsServers) require('dns').setServers(config.dnsServers);

  const cfChallenge = CfChallenge.create({context, cloudflare: config.cloudflare});
  let le = LE.create({
    // debug: true,
    store,
    version: 'v02',
    server: LEServer,
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

  if(!cert || !cert.cert || !cert.privkey)
    throw new Error('Failed to successfully create cert.');

  context.log(`Successfully created cert!`);
  context.log(cert.identifiers);


  // *********************
  // Convert to PFX
  // *********************
  context.log('Generating PFX...');
  const pfxPass = (await promisify(crypto.randomBytes)(20)).toString('hex'); // Generates a 40 character long string
  const pfxBuf = await generatePfx({
    context,
    cert: cert.cert,
    privateKey: cert.privkey,
    password: pfxPass
  });
  const thumbprint = await getCertFingerprint(cert.cert);


  // *********************
  // Upload to webapp
  // *********************
  const name = (production ? 'prod-' : 'dev-') + app.defaultHostName + '-' + thumbprint;

  context.log(`Uploading Certificate ${name}`);
  let existingCert;
  try {
    existingCert = await websiteClient.certificates.get(resourceGroup, name);
    context.log(existingCert);
  } catch(e) { }

  if (existingCert) {
    context.log(`Found existing cert ${existingCert.friendlyName}`);
    existingCert.expirationDate = cert.expiresAt;
    existingCert.issueDate = cert.issuedAt;
    existingCert.cerBlob = cert.cert;
    existingCert.pfxBlob = pfxBuf;
    existingCert.password = pfxPass;
    existingCert.thumbprint = thumbprint;
    const resp = await websiteClient.certificates.update(resourceGroup, name, existingCert);
    context.log(resp.id);
   } else {
    context.log('No existing cert found, creating new one');
    try {
      var resp = await websiteClient.certificates.createOrUpdate(resourceGroup, name, {
        pfxBlob: pfxBuf,
        serverFarmId: app.serverFarmId,
        location: app.location,
        password: pfxPass
      });
    } catch(e) {
      context.log('Failed to upload certificate!');
      context.log(e.response.body.message);
      throw e;
    }
    context.log(resp.id);
  }


  // *********************
  // Bind to webapp
  // *********************
  if(production) {
    // Update each hostname binding
    app.hostNameSslStates.forEach(sslState => {
      if(hostnames.includes(sslState.name)) {
        context.log(`${sslState.name} is currently in SSLState ${sslState.sslState}`);
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

module.exports = run;
