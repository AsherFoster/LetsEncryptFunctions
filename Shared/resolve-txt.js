const util = require('util');
const dns = require('dns');

const nodeResolveTxt = util.promisify(dns.resolveTxt);

/**
 * Returns an array of all TXT records for the specified domain.
 * @param {string} fqdn - The domain to lookup.
 * @return {string[]} - The TXT records for the specified domain.
 * @throws {Error} throw when the lookup fails.
 * @private
 */
module.exports = async function resolveTxt(fqdn) {
  const records = await nodeResolveTxt(fqdn);
  return records.map(r => r.join(' '));
};
