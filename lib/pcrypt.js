/*!
 * pcrypt - password key generate/compare
 * Copyright (c) 2012 Jake Luer <jake@alogicalparadox.com>
 * MIT Licensed
 */

/*!
 * Module dependancies
 */

var crypto = require('crypto');

/*!
 * Default config values
 */

var len = 128
  , iterations = 1000
  , randChars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
  , randLength = 10;

/**
 * .length
 *
 * Get/set the length of the salt random bytes.
 *
 *     pcrypt.length = 256;
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
 *     pcrypt.iterations = 2000;
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
 * .randChars
 *
 * Get/set the random characters used when generating
 * a random password.
 *
 *     pcrypt.randChars = 'acb123';
 *
 * @param {Number} iterations
 * @returns {Number} iterations
 * @api public
 */

Object.defineProperty(exports, 'randChars',
  { get: function () { return randChars; }
  , set: function (s) { randChars = s; }
});

/**
 * .randLength
 *
 * Get/set the length of a randomly generated password.
 *
 *     pcrypt.randLength = 10;
 *
 * @param {Number} iterations
 * @returns {Number} iterations
 * @api public
 */

Object.defineProperty(exports, 'randLength',
  { get: function () { return randLength; }
  , set: function (n) { randLength = n; }
});

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

exports.compare = function (pass, key, cb) {
  var l = key.length
    , salt = key.substring(0, l - len)
    , hash = key.substring(salt.length);
  crypto.pbkdf2(pass, salt, iterations, len, function (err, compare) {
    if (err) return cb(err);
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

exports.random = function (cb) {
  var pass = randomPass();
  exports.gen(pass, function (err, key) {
    if (err) return cb(err);
    cb(null, pass, key);
  });
};

/*!
 * randomPass ()
 *
 * Generate a random string passed on the configuration
 * and return it for further processing.
 *
 * @returns {String} password
 * @api private
 */

function randomPass () {
  var l = randChars.length
    , pass = ''
    , x;

  for (var i = 0; i < randLength; i++) {
    x = Math.floor(Math.random() * l);
    pass += randChars.charAt(x);
  }

  return pass;
}
