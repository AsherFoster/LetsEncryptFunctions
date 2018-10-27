// Sections adapted from https://git.coolaj86.com/coolaj86/le-challenge-dns.js

const AzWebsiteClient = require('azure-arm-website');
const azureRest = require('ms-rest-azure');
const config = require('../config.json');
const tls = require('tls');
const crypto = require('crypto');
const {promisify} = require('util');
const Cloudflare = require('cloudflare');
const psl = require('psl');
const LE = require('greenlock');
const dns = require('dns');

const production = process.env.NODE_ENV === 'production';
const acmePrefix = '_acme-challenge';

class Renewerer {
  // context = null;
  // websiteClient = null;
  // app = null;
  // cf = null;
  // appName = '';
  // resourceGroup = '';

  static async renew(context, appName, resourceGroup=config.resourceGroup) {
    return new this(context, appName, resourceGroup);
  }

  constructor(context, appName, resourceGroup) {
    this.context = context;
    this.appName = appName;
    this.resourceGroup = resourceGroup;

    this._setup().then(() => this.run());
  }

  // Setup the instance (Define websiteClient and cf)
  async _setup() {
    // Login to Azure AD
    const creds = await azureRest.loginWithServicePrincipalSecret(config.clientId, config.secret, config.domain);
    this.websiteClient = new AzWebsiteClient(creds, config.subscriptionId);

    // Create cloudflare client
    const cf = Cloudflare(config.cloudflare);
    if(!await cf.user.read()) {
      throw new Error('Failed to authenticate with cloudflare!');
    }
    this.cf = cf;

    // Get the CF zones
    const cfZoneList = (await cf.zones.browse()).result;
    this.cfZones = {};
    cfZoneList.forEach(z => this.cfZones[z.name] = z);
  }

  // Main function
  async run() {
    // Get the app
    this.app = await this.websiteClient.webApps.get(this.resourceGroup, this.appName);
    if (!this.app) throw new Error(`Failed to get web app "${this.appName}" in resouce group "${this.resourceGroup}"`);
    this.context.log(`Retrieved app "${this.appName}", with hostnames ${this.app.enabledHostNames}`);

    // Get domains that are old enough to renew
    const hostnamesToRenew = await this.getHostnamesToRenew();

    // Check all hostnames match a zone
    hostnamesToRenew.forEach(hostname => {
      const {domain} = psl.parse(hostname);
      if(!this.cfZones[domain]) throw new Error(`Couldn't find a Cloudflare zone for hostname ${hostname} (Domain: ${domain})`);
    });

    // Generate a certificate for given hostnames
    const cert = await this.getCertificate(hostnamesToRenew);
    this.context.log(`Successfully issued cert for ${cert.subject} (${cert.altnames}). Valid until ${cert.expiresAt}`);

    // Convert cert to PFX
    // Upload the certificate
    // Bind the certificate
  }

  // Retrieves a list of hostnames that need renewing from given app.
  async getHostnamesToRenew() {
    let toRenew = [];
    let hostnames = this.app.enabledHostNames.filter(h => !h.endsWith('azurewebsites.net'));
    await Promise.all(hostnames.map(hostname => new Promise((resolve, reject) => {
      let socket = tls.connect(443, hostname, null, () => {
        const issuedAt = new Date(socket.getPeerCertificate().valid_from);
        const age = (new Date() - issuedAt) / (1000 * 60 * 60); // Age in hours
        if(age < (24 * 7)) { // If it's less than a week old
          this.context.log(`IGNORING ${hostname}: ${age} hours old`);
        } else {
          this.context.log(`RENEWING ${hostname}: ${age} hours old`);
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
    })));
  
    return toRenew;
  }

  // Orchestrates issuing cert
  async getCertificate(hostnames) {
    let le = LE.create({
      version: 'v02',
      server: production ?
        'https://acme-v02.api.letsencrypt.org/directory' :
        'https://acme-staging-v02.api.letsencrypt.org/directory',
      challenges: {'dns-01': {set: this.challenge}},
      challengeType: 'dns-01'
    });

    let hasCerts = le.check({domains: hostnames});
    if(hasCerts) throw new Error(`Already have certs? ${hasCerts}`); // TODO figure this case out. What does it even mean

    return le.register({
      domains: hostnames,
      email: config.le.email,
      agreeTos: true,
      rsaKeySize: 2048
    });
  }

  // Orchestrate completing challenge
  async challenge(args, domain, challenge, keyAuthorization, cb) {
    const keyAuthDigest = crypto.createHash('sha256').update(keyAuthorization||'').digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/g, '');
    
    await this.setCloudflareRecords(domain, keyAuthDigest);
    cb();
  }

  // Set the CF TXT records
  async setCloudflareRecords(domain, authContent) {
    // Set the CF attributes
    const challengeDomain = acmePrefix + '.' + domain;
    const zone = this.cfZones[domain];
    const records = await this.getTxtRecords(zone, challengeDomain);
    let record;
    switch (records.length) {
      default:
        this.context.log(`Removing ${records.length - 1} existing verification records, leaving one to edit`);
        await Promise.all(records.slice(1).map(r => this.cf.dnsRecords.del(zone.id, r.id)));
      // noinspection FallThroughInSwitchStatementJS
      case 1:
        this.context.log(`Updating existing TXT record for '${challengeDomain}' with '${authContent}'.`);
        record = await this.cf.dnsRecords.edit(
          zone.id,
          records[0].id,
          Object.assign({}, records[0], { content: authContent, ttl: 120 })
        );
        break;
      case 0:
        this.context.log(`Found no TXT records for '${challengeDomain}'. Creating a new one with '${authContent}'`);
        record = await this.cf.dnsRecords.add(zone.id, {
          type: 'TXT',
          name: challengeDomain,
          content: authContent,
          ttl: 120
        });
      }
    await this.verifyPropagation(challengeDomain, authContent);
    return record.result;
  }

  // Delays until the correct records are being resolved
  async verifyPropagation(domain, challengeContent, attempts = 10) {
    this.context.log(`Awaiting propagation of TXT record for '${domain}'.`);
    for (let i = 0; i <= attempts; i++) {
      try {
        if(await this.checkTxtRecord(domain, challengeContent))
          return this.context.log(`Successfully propagated challenge for '${domain}'.`);
      } catch (error) {
        this.context.warn(`Try ${i + 1}. Awaiting propagation for ${domain}.`);
        await delay(2000);
      }
    }
    throw new Error(`Could not verify challenge for '${domain}'.`);
  }

  // Checks that there is a TXT record at the domain that matches value
  async checkTxtRecord(domain, value) {
    const records = await util.promisify(dns.resolveTxt(domain));
    return records.some(r => r.join() === value);
  }

  // Lists TXT records for a domain via CF
  async getTxtRecords(zone, name) {
    let records = (await this.cf.dnsRecords.browse(zone.id, {type: 'TXT'})).result;
    this.context.log(`Got ${records.length} TXT records for ${name}, ${records.map(r => r.name + ' -- ' + r.value)}`);
    records = records.filter(r => r.name === name);

    return records;
  }
}

function delay(ms) {
  return new Promise(r => {
    setTimeout(() => r(), ms)
  })
}

module.exports = Renewerer;
