// Completely stolen from https://github.com/buschtoens/le-challenge-cloudflare
// (why did it have to be .mjs...?)
const crypto = require('crypto');
const Cloudflare = require('cloudflare');
const consumePages = require('./consume-pages');
const resolveTxt = require('./resolve-txt');

function delay(ms) {
  return new Promise(r => {
    setTimeout(() => r(), ms);
  });
}

/**
 * @typedef {Object} Options
 * @property {string} acmePrefix
 * @property {VerifyPropagationOptions} verifyPropagation
 */

/**
 * @typedef {Object} InitializationOptions
 * @extends Options
 * @property {CloudflareOptions} cloudflare
 * @property {string} acmePrefix
 * @property {VerifyPropagationOptions} verifyPropagation
 */

/**
 * @typedef {Object} CloudflareOptions
 * @property {string} email
 * @property {string} key
 */

/**
 * @typedef {Object} VerifyPropagationOptions
 * @property {number} waitFor The amount of time in ms to wait before each
 *   verification attempt.
 * @property {number} retries The maximum number of retries before failing.
 */

/**
 * This Challenge implementation sets the required DNS records via the
 * Cloudflare API and optionally verifies the propagation via a DNS lookup
 * or using the Google Public DNS API (DNS-Over-HTTPS).
 */
module.exports = class CloudflareChallenge {
  // /**
  //  * The Cloudflare API client.
  //  * @type {Object}
  //  * @private
  //  */
  // cloudflare;
  //
  // /**
  //  * @type {Object}
  //  * @private
  //  */
  // acmePrefix;
  //
  // /**
  //  * @type {VerifyPropagationOptions}
  //  * @private
  //  */
  // verifyPropagation;

  /**
   * Creates a new `CloudflareChallenge` instance. Only exists for compatibility
   * reasons with `greenlock` / `le-acme-core`.
   * @param  {InitializationOptions} options
   * @return {this}
   */
  static create(options) {
    return new this(options);
  }

  /**
   * @param {InitializationOptions} options
   */
  constructor({
                cloudflare = {},
                acmePrefix = '_acme-challenge',
                verifyPropagation = { waitFor: 5000, retries: 20 },
                context
              }) {
    context.log('Creating new CloudflareChallenge instance:', {
      acmePrefix,
      verifyPropagation,
      cloudflare: cloudflare.email
    });

    this.context = context;
    this.cloudflare =
      cloudflare instanceof Cloudflare
        ? cloudflare
        : new Cloudflare(cloudflare);
    this.acmePrefix = acmePrefix;
    this.verifyPropagation = verifyPropagation;
  }

  /**
   * Returns the options for this instance.
   * @method getOptions
   * @return {Options}]
   */
  getOptions() {
    return {
      acmePrefix: this.acmePrefix,
      verifyPropagation: this.verifyPropagation
    };
  }

  /**
   * @method set
   * @param  {Options}  options
   * @param  {string}   domain
   * @param  {string}   challenge
   * @param  {string}   keyAuthorization
   * @param  {Function} done
   */
  async set(
    { acmePrefix, verifyPropagation },
    domain,
    challenge,
    keyAuthorization,
    done
  ) {
    try {
      this.context.log(`Trying to set ACME challenge for '${domain}'.`);

      const authContent = CloudflareChallenge.getAuthContent(keyAuthorization);
      const fqdn = CloudflareChallenge.getFQDN(domain, acmePrefix);

      const zone = await this.getZoneForDomain(domain);
      if (!zone) throw new Error(`Could not find a zone for '${domain}'.`);

      const records = await this.getTxtRecords(zone, fqdn);

      switch (records.length) {
        default:
          this.context.log(
            `Found ${
              records.length
              } existing records. Deleting all but first one.`
          );
          for (const record of records.slice(1))
            await this.cloudflare.dnsRecords.del(zone.id, record.id);
        // eslint-disable-next-line no-fallthrough
        case 1:
          this.context.log(
            `Updating existing TXT record for '${fqdn}' with '${authContent}'.`
          );
          await this.cloudflare.dnsRecords.edit(
            zone.id,
            records[0].id,
            Object.assign({}, records[0], { content: authContent, ttl: 120 })
          );
          break;
        case 0:
          this.context.log(
            `Found no pre-existing TXT record for '${fqdn}'. Attempting to create a new one with '${authContent}'.`
          );
          await this.cloudflare.dnsRecords.add(zone.id, {
            type: 'TXT',
            name: fqdn,
            content: authContent,
            ttl: 120
          });
      }

      if (verifyPropagation)
        await CloudflareChallenge.verifyPropagation(
          { acmePrefix, verifyPropagation, authContent },
          domain,
          challenge,
          this.context
        );

      done(null);
    } catch (error) {
      this.context.log(error);
      done(error);
    }
  }

  // get(defaults, domain, key, done) {}

  async remove({ acmePrefix }, domain, challenge, done) {
    try {
      this.context.log(`Trying to remove ACME challenge for '${domain}'.`);

      const zone = await this.getZoneForDomain(domain);
      if (!zone) throw new Error(`Could not find a zone for '${domain}'.`);

      const fqdn = CloudflareChallenge.getFQDN(domain, acmePrefix);
      const records = await this.getTxtRecords(zone, fqdn);
      if (!records.length)
        throw new Error(`Could not find a TXT record for '${fqdn}'.`);

      for (const record of records)
        await this.cloudflare.dnsRecords.del(zone.id, record.id);

      this.context.log(`Sucessfully removed ACME challenge for '${domain}'.`);
      done(null);
    } catch (error) {
      this.context.log(error);
      done(error);
    }
  }

  // eslint-disable-next-line class-methods-use-this
  async loopback(...args) {
    return CloudflareChallenge.loopback(...args);
  }

  static async loopback(
    { acmePrefix, authContent },
    domain,
    challenge,
    context,
    done
  ) {
    try {
      const fqdn = CloudflareChallenge.getFQDN(domain, acmePrefix);
      context.log(`Testing TXT record existence for '${fqdn}' using native DNS.`);

      const records = await resolveTxt(fqdn);

      if (authContent) {
        context.log(`Verifying presence of ${authContent}`);
        if (!records.includes(authContent))
          throw new Error(`Could not verify '${domain}'.`);
      }

      if (typeof done === 'function') done(null, records);
    } catch (error) {
      if (typeof done === 'function') done(error, null);
      else throw error;
    }
  }

  static async verifyPropagation(
    { verifyPropagation, ...options },
    domain,
    challenge,
    context,
    waitFor = verifyPropagation.waitFor,
    retries = verifyPropagation.retries
  ) {
    context.log(`Awaiting propagation of TXT record for '${domain}'.`);
    for (let i = 0; i <= retries; i++) {
      try {
        await CloudflareChallenge.loopback(options, domain, challenge, context);
        context.log(`Successfully propagated challenge for '${domain}'.`);
        return;
      } catch (error) {
        context.log(`Failed propagation check #${i} / ${retries}. waiting ${waitFor}ms. (${error.message})`);
        await delay(waitFor);
      }
    }
    throw new Error(`Could not verify challenge for '${domain}'.`);
  }

  static getFQDN(domain, acmePrefix) {
    return `${acmePrefix}.${domain}`;
  }

  static getAuthContent(keyAuthorization) {
    if (typeof keyAuthorization !== 'string')
      throw new TypeError('Expected keyAuthorization to be a string.');

    return crypto
      .createHash('sha256')
      .update(keyAuthorization)
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/g, '');
  }

  async getZoneForDomain(domain) {
    // for (const zone of (await this.cloudflare.zones.browse(pagination)).result)
    for await (const zone of consumePages(pagination =>
      this.cloudflare.zones.browse(pagination)
    ))
      if (domain.endsWith(zone.name)) return zone;

    return null;
  }

  async getTxtRecords(zone, name) {
    const records = [];

    // for (const txtRecord of (await this.cloudflare.dnsRecords.browse(zone.id, {
    for await (const txtRecord of consumePages(pagination =>
      this.cloudflare.dnsRecords.browse(zone.id, {
        ...pagination,
        type: 'TXT',
        name
      })
    )) // Ugh, let's just assume it works
      if (txtRecord.name === name) records.push(txtRecord);

    return records;
  }
};
