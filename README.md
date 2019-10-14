# [Deprecated] Lets Encrypt Functions
**This is definitely not maintained, and may not be compatible with newer APIs. Use with caution**

A library I made to renew [Azure Web App](https://azure.microsoft.com/en-us/services/app-service/web/)
certificates using [Let's Encrypt](https://letsencrypt.org/), designed to be run on [Azure Functions](https://azure.microsoft.com/en-us/services/functions/).
Uses cloudflare for challenges

### Usage
It's as simple as:
```js
const renew = require('../Shared/index');

module.exports = async function (context, myTimer) {
  const startTime = new Date().toISOString();

  await renew(context, 'WebAppName');
  
  context.log('JavaScript timer trigger function ran!', startTime);
};
```


### The big problem.
The problem with this is that I can't get it running on Azure.
When it comes to writing functions, I have two options: Functions on Windows or Linux.
With Linux, I can't adjust the node version above v6 or something, so some of the code won't run.
I could work around it, but it'd be a pain.
On Windows, I can't run any of the required shell tools such as OpenSSL for some damn reason.
So yeah. 

### The workaround
Sort of. You can run it locally using the [Azure Functions Core Tools](https://github.com/Azure/azure-functions-core-tools#readme) and then use the REST API to trigger the timer manually.
This gets rid of the whole automatic part though, so it's not very helpful.

### Config
This script needs a decent amount of configuring:
```typescript
interface Config {
  clientId: string; // The Azure AD app that has access to your web app
  secret: string; // The secret of the AD app
  domain: string; // The domain used to authenticate the AD app,
  
  resourceGroup: string; // The resource group the Web App is part of
  subscriptionId: string; // Sub ID everything is in
  
  le: {
    email: string; // Email attached to the cert
  };
  
  cloudflare: {
    email: string; // Email of your cloudflare account
    key: string; // Cloudflare API key
  };
  
  storage: {
    account: string; // Storage account the Greenlock config is stored in
    container: string; // Container the config is stored in
    configBlobName: string; // Name of the blob the config is stored in
    // Supports dev and prod overrides, devConfigBlobName and prodConfigBlobName
    key: string; // Storage account key
  }
  
  dnsServers: string[]; // List of DNS servers to check propagation with
}
```
