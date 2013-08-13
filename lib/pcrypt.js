/*!
 * pcrypt - password key generate/compare
 * Copyright (c) 2012 Jake Luer <jake@alogicalparadox.com>
 * MIT Licensed
 */

/*!
 * Module dependancies
 */

var crypto = require('crypto')
  , facet = require('facet');

var nextTick = 'undefined' !== typeof setImmediate
  ? setImmediate
  : process.nextTick;

module.exports = Pcrypt;

function Pcrypt (config) {
  if (!(this instanceof Pcrypt)) return new Pcrypt(config);
  this.set('length', 128);
  this.set('iterations', 1000);
  this.set('rand chars', 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890');
  this.set('rand length', 10);
  this.set(config);
}

facet(Pcrypt.prototype);

/**
 * .gen (password, callback)
 *
 * Generate a passkey for a given password.
 *
 *     pcrypt.gen('hell0universe!', function (err, key) {
 *       user.passkey = key;
 *     });
 *
 * @param {String} password
 * @param {Function} callback
 * @cb {Error|null}
 * @cb {String} passkey
 * @api public
 */

Pcrypt.prototype.gen = function (pass, cb) {
  var iters = this.get('iterations')
    , len = this.get('length')
    , salt;

  salt = crypto.randomBytes(len)
    .toString('hex')
    .slice(0, len);

  crypto.pbkdf2(pass, salt, iters, len, function (err, hash) {
    if (err) return cb(err);
    var passkey = salt + '::';
    passkey += new Buffer(hash, 'binary').toString('base64') + '::'
    passkey += iters + '::';
    passkey += len;
    cb(null, passkey);
  });
};

/**
 * .compare (password, passkey, callback)
 *
 * Compare a password to a previously generated
 * passkey. Callback will include a boolean indicating
 * whether the password is a match.
 *
 *     pcrypt.compare('hell0universe!', user.passkey, function (err, match) {
 *       if (match) {
 *         // do login stuffs
 *       }
 *     });
 *
 * @param {String} password
 * @param {String} passkey (from `.gen`)
 * @param {Function} callback
 * @cb {Error|null}
 * @cb {Boolean} match
 * @api public
 */

Pcrypt.prototype.compare = function (pass, key, cb) {
  var parts = key.split('::')
    , hash, iters, len, salt;

  salt = parts[0];
  hash = parts[1];
  iters = parseInt(parts[2], 10) || this.get('iterations');
  len = parseInt(parts[3], 10) || this.get('length');

  crypto.pbkdf2(pass, salt, iters, len, function (err, compare) {
    if (err) return cb(err);
    compare = new Buffer(compare, 'binary').toString('base64');
    cb(null, hash === compare);
  });
};

/**
 * .random (callback)
 *
 * Generate a random password and provide the password
 * for notification and the key for storage. Can use
 * `.randChars` and `.randLength` to adjust the behavior
 * of the random password generator.
 *
 * Defaults to alphanumeric with a length of 10 characters.
 *
 * @param {Function} callback
 * @cb {Error|null}
 * @cb {String} password
 * @cb {String} passkey
 * @api public
 */

Pcrypt.prototype.random = function (cb) {
  var randChars = this.get('rand chars')
    , randLength  = this.get('rand length')
    , pass = ''
    , i = 0
    , x;

  for (; i < randLength; i++) {
    x = Math.floor(Math.random() * randChars.length);
    pass += randChars.charAt(x);
  }

  this.gen(pass, function (err, key) {
    if (err) return cb(err);
    cb(null, pass, key);
  });
};
