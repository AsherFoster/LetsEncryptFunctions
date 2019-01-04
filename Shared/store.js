'use strict';
const Storage = require("@azure/storage-blob");
const crypto = require('crypto');

module.exports.create = async function create(options) {
  let defaults = {
    accountKeypairs: {},
    certificateKeypairs: {},
    accountIndices: {},
    certIndices: {},
    certificates: {},
    accounts: {},
    accountCerts: {}
  };
  let memDb = JSON.parse(JSON.stringify(defaults)); // Deep copy the defaults

  const {storage, context} = options;
  const sharedKeyCred = new Storage.SharedKeyCredential(storage.account, storage.key);
  const pipeline = Storage.StorageURL.newPipeline(sharedKeyCred);
  const serviceURL = new Storage.ServiceURL(
    `https://${storage.account}.blob.core.windows.net`,
    pipeline
  );

  const containerURL = Storage.ContainerURL.fromServiceURL(serviceURL, storage.container);
  const blobURL = Storage.BlobURL.fromContainerURL(containerURL, storage.configBlobName || 'greenlock.json');
  try {
    // const downloadBlockBlobResponse = await blobURL.download(Storage.Aborter.none, 0);
    // const blobContent = await consumeStream(downloadBlockBlobResponse.readableStreamBody);
    const props = await blobURL.getProperties(Storage.Aborter.timeout(10000));
    const blobContent = Buffer.alloc(props.contentLength);
    await Storage.downloadBlobToBuffer(Storage.Aborter.timeout(10000), blobContent, blobURL, 0);
    memDb = JSON.parse(blobContent.toString());
    if(context) context.log('Downloaded config from Az Storage!');
  } catch(e) {
    console.error(e);
    // Failed to get the config, create one.
    await setConfig(defaults);
    if(context) context.log('Initializing config in Az!');
  }

  async function setConfig(value) {
    value._lastUpdate = new Date();
    const content = JSON.stringify(value);
    const blockBlobURL = Storage.BlockBlobURL.fromBlobURL(blobURL);
    await blockBlobURL.upload(
      Storage.Aborter.none,
      content,
      content.length
    );
  }

  async function saveConfig() {
    context.log('Saveconfig called!');
    return setConfig(memDb);
  }

  const accounts = {
    __promisified: true,
    // Accounts
    setKeypairAsync: async function (opts, keypair) {
      // opts.email // non-optional
      // opts.keypair // non-optional

      if (!opts.email) {
        throw new Error("MUST use email when setting Keypair");
      }

      if (!keypair.privateKeyJwk) {
        throw new Error("MUST use privateKeyJwk when setting Keypair");
      }
      if (!keypair.privateKeyPem) {
        throw new Error("MUST use privateKeyPem when setting Keypair");
      }
      if (!keypair.publicKeyPem) {
        throw new Error("MUST use publicKeyPem when setting Keypair");
      }

      const accountId = crypto.createHash('sha256').update(keypair.publicKeyPem).digest('hex');

      memDb.accountIndices[accountId] = accountId;
      memDb.accountIndices[opts.email] = accountId;
      memDb.accountKeypairs[accountId] = keypair;
      /*
      {
        id: accountId
        // TODO nix accountId
      , accountId: accountId
      , email: opts.email
      , keypair: keypair
      };
      */
      await saveConfig();
      return memDb.accountKeypairs[accountId];
    },
    // Accounts
    checkKeypairAsync: async function (opts) {
      // opts.email // optional
      // opts.accountId // optional

      const keypair = opts.keypair || {};
      let index;

      if (keypair.publicKeyPem) {
        index = crypto.createHash('sha256').update(keypair.publicKeyPem).digest('hex');
        index = memDb.accountIndices[index];
      }
      else if (keypair.publicKeyJwk) {
        // TODO RSA.exportPublicPem(keypair);
        throw new Error("id from publicKeyJwk not yet implemented");
      }
      else if (opts.email) {
        index = memDb.accountIndices[opts.email];
      }
      else {
        throw new Error("MUST supply email or keypair.publicKeyPem or keypair.publicKeyJwk");
      }

      return memDb.accountKeypairs[index] || null;
    },


    // Accounts
    setAsync: async function (opts, reg) {
      // opts.email
      // reg.keypair
      // reg.receipt // response from acme server

      const keypair = reg.keypair || opts.keypair || {};
      let accountId;
      let index;

      if (keypair.publicKeyPem) {
        index = crypto.createHash('sha256').update(keypair.publicKeyPem).digest('hex');
        index = memDb.accountIndices[index];
      }
      else if (keypair.publicKeyJwk) {
        // TODO RSA.exportPublicPem(keypair);
        throw new Error("id from publicKeyJwk not yet implemented");
      }
      else if (opts.email) {
        index = memDb.accountIndices[opts.email];
      }
      else {
        throw new Error("MUST supply email or keypair.publicKeyPem or keypair.publicKeyJwk");
      }

      accountId = memDb.accountIndices[index];
      if (!accountId) {
        throw new Error("keypair was not previously set with email and keypair.publicKeyPem");
      }

      memDb.accounts[accountId] = {
        id: accountId,
        // TODO nix accountId
        accountId: accountId,
        email: opts.email,
        keypair: keypair,
        agreeTos: opts.agreeTos || reg.agreeTos
        // receipt: reg.receipt || opts.receipt
      };
      Object.keys(reg).forEach(function (key) {
        memDb.accounts[accountId][key] = reg[key];
      });

      await saveConfig();
      return memDb.accounts[accountId];
    },
    // Accounts
    checkAsync: async function (opts) {
      // opts.email // optional
      // opts.accountId // optional
      // opts.domains // optional

      const keypair = opts.keypair || {};
      let index;
      let accountId;
      let account;

      if (opts.accountId) {
        index = memDb.accountIndices[opts.accountId];
      }
      else if (keypair.publicKeyPem) {
        index = crypto.createHash('sha256').update(keypair.publicKeyPem).digest('hex');
        index = memDb.accountIndices[index];
      }
      else if (keypair.publicKeyJwk) {
        // TODO RSA.exportPublicPem(keypair);
        throw new Error("id from publicKeyJwk not yet implemented");
      }
      else if (opts.email) {
        index = memDb.accountIndices[opts.email];
      }
      else if (opts.domains && opts.domains[0]) {
        index = memDb.accountIndices[opts.domains[0]];
      }
      else {
        console.error(opts);
        throw new Error("MUST supply email or keypair.publicKeyPem or keypair.publicKeyJwk");
      }

      accountId = memDb.accountIndices[index];
      if (!accountId) {
        return null;
      }

      account = JSON.parse(JSON.stringify(memDb.accounts[accountId] || null));
      account.keypair = memDb.accountKeypairs[accountId] || null;

      return account;
    }
  };

  const certificates = {
    __promisified: true,
    // Certificates
    setKeypairAsync: async function (opts, keypair) {
      // opts.domains

      if (!opts.domains || !opts.domains.length) {
        throw new Error("MUST use domains when setting Keypair");
      }
      if (!opts.email) {
        throw new Error("MUST use email when setting Keypair");
      }
      // if (!opts.accountId) {
      //   cb(new Error("MUST use accountId when setting Keypair"));
      //   return;
      // }



      if (!keypair.privateKeyJwk) {
        throw new Error("MUST use privateKeyJwk when setting Keypair");
      }
      if (!keypair.privateKeyPem) {
        throw new Error("MUST use privateKeyPem when setting Keypair");
      }
      if (!keypair.publicKeyPem) {
        new Error("MUST use publicKeyPem when setting Keypair");
      }



      const subject = opts.domains[0];

      opts.domains.forEach(function (domain) {
        memDb.certIndices[domain] = subject;
      });

      memDb.certificateKeypairs[subject] = keypair;
      /*
      {
        subject: subject
      , keypair: keypair
      };
      */
      await saveConfig();
      return memDb.certificateKeypairs[subject];
    },
    // Certificates
    checkKeypairAsync: async function (opts) {
      // opts.domains
      if (!opts.domains || !opts.domains.length) {
        throw new Error("MUST use domains when checking Keypair");
      }

      const domain = opts.domains[0];
      const subject = memDb.certIndices[domain];

      return memDb.certificateKeypairs[subject];
    },

    // Certificates
    setAsync: async function ({certs, ...opts}) {
      // opts.domains
      // opts.email // optional
      // opts.accountId // optional

      // certs.privkey
      // certs.cert
      // certs.chain

      let index;
      let accountId;
      let account;
      context.log(certs);
      const subject = certs.subject || opts.domains[0];
      const altnames = certs.altnames || opts.domains;
      let accountCerts;

      if (opts.accountId) {
        index = opts.accountId;
      }
      else if (opts.email) {
        index = opts.email;
      }
      else {
        throw new Error("MUST supply email or accountId");
      }

      accountId = memDb.accountIndices[index];
      account = memDb.accounts[accountId];

      if (!account) {
        throw new Error("account must exist");
      }

      accountId = memDb.accountIndices[index];
      if (!accountId) {
        throw new Error("keypair was not previously set with email and keypair.publicKeyPem");
      }

      memDb.certIndices[subject] = subject;
      altnames.forEach(function (altname) {
        memDb.certIndices[altname] = subject;
      });

      accountCerts = memDb.accountCerts[accountId] || {};
      accountCerts[subject] = subject;
      memDb.accountCerts[accountId] = accountCerts;

      memDb.certificates[subject] = certs;

      // SAVE to the database, index the email address, the accountId, and alias the domains
      await saveConfig();
      return certs;
    },
    // Certificates
    checkAsync: async function (opts) {
      // You will be provided one of these (which should be tried in this order)
      // opts.domains
      // opts.email // optional
      // opts.accountId // optional
      let subject;
      let subjects;
      let accountId;

      if (opts.domains) {
        subject = memDb.certIndices[opts.domains[0]];
        return memDb.certificates[subject];
      }

      if (opts.accountId) {
        accountId = memDb.accountIndices[opts.accountId];
      }
      else if (opts.email) {
        accountId = memDb.accountIndices[opts.email];
      }

      subjects = memDb.accountCerts[accountId] || [];
      return subjects.map(function (subject) {
        subject = memDb.certIndices[subject];
        return memDb.certificates[subject] || null ;
      });
    }
  };

  if(context) context.log('Store initialized!');
  return {
    getOptions: function () {
      Object.keys(defaults).forEach(function (key) {
        if ('undefined' === typeof options[key]) {
          options[key] = defaults[key];
        }
      });

      // merge options with default settings and then return them
      return options;
    },
    accounts, certificates
  };
};
