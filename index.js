module.exports = process.env.PCRYPT_COV
  ? require('./lib-cov/pcrypt')
  : require('./lib/pcrypt');
