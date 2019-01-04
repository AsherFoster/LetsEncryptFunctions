const renew = require('../Shared/index');

module.exports = async function (context, myTimer) {
  const startTime = new Date().toISOString();

  if(myTimer.isPastDue) {
    context.log('JavaScript is running late!');
  }

  await renew(context, 'AFApis');

  context.log('JavaScript timer trigger function ran!', startTime);
};