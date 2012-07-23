/*!
 * Module dependancies
 */

var crypto = require('crypto');

/*!
 * Default config values
 */

var len = 128
  , iterations = 12000;

/**
 * .length
 *
 * Get/set the length of the salt random bytes.
 *
 * @param {Number} length
 * @returns {Number} length
 * @api public
 */

Object.defineProperty(exports, 'length',
  { get: function () { return len; }
  , set: function (n) { len = n; }
});

/**
 * .iterations
 *
 * Get/set the number of `crypto.pbkdf2` iterations.
 *
 * @param {Number} iterations
 * @returns {Number} iterations
 * @api public
 */

Object.defineProperty(exports, 'iterations',
  { get: function () { return iterations; }
  , set: function (n) { iterations = n; }
});

/**
 * .gen (password, callback)
 *
 * Generate a passkey for a given password.
 *
 * @param {String} password
 * @param {Function} callback
 * @cb {Error|null}
 * @cb {String} passkey
 * @api public
 */

exports.gen = function (pass, cb) {
  crypto.randomBytes(len, function (err, salt) {
    if (err) return cb(err);
    salt = salt.toString('base64');
    crypto.pbkdf2(pass, salt, iterations, len, function (err, hash) {
      if (err) return cb(err);
      cb(null, salt + hash);
    });
  });
};

/**
 * .compare (password, passkey, callback)
 *
 * Compare a password to a previously generated
 * passkey. Callback will include a boolean indicating
 * whether the password is a match.
 *
 * @param {String} password
 * @param {String} passkey (from `.gen`)
 * @param {Function} callback
 * @cb {Error|null}
 * @cb {Boolean} match
 * @api public
 */

exports.compare = function (pass, key, cb) {
  var l = key.length
    , salt = key.substring(0, l - len)
    , hash = key.substring(salt.length);
  crypto.pbkdf2(pass, salt, iterations, len, function (err, compare) {
    if (err) return cb(err);
    cb(null, hash === compare);
  });
};