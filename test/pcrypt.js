var Pcrypt = require('..')
  , pass = 'hello-universe'
  , notpass = 'hello-world';

describe('Pcrypt', function () {
  describe('.gen(pass, cb)', function () {
    it('can make a passkey', function (done) {
      var pcrypt = Pcrypt();
      pcrypt.gen(pass, function (err, key) {
        should.not.exist(err);
        key.should.be.a('string')
          .with.length.above(250);
        done();
      });
    });
  });

  describe('.compare(pass, str, cb)', function () {
    it('can match on same pass', function (done) {
      var pcrypt = Pcrypt();
      pcrypt.gen(pass, function (err, str) {
        should.not.exist(err);
        pcrypt.compare(pass, str, function (err, match) {
          should.not.exist(err);
          match.should.be.true;
          done();
        });
      });
    });

    it('can not match on different pass', function (done) {
      var pcrypt = Pcrypt();
      pcrypt.gen(pass, function (err, str) {
        should.not.exist(err);
        pcrypt.compare(notpass, str, function (err, match) {
          should.not.exist(err);
          match.should.be.false;
          done();
        });
      });
    });
  });

  describe('.random()', function () {
    it('can generate a random password', function (done) {
      var pcrypt = Pcrypt();
      pcrypt.random(function (err, pass, key) {
        should.not.exist(err);
        should.exist(pass);
        should.exist(key);

        pass.should.have.length(pcrypt.get('rand length'));
        pcrypt.compare(pass, key, function (err, match) {
          should.not.exist(err);
          match.should.be.true;
          done();
        });
      });
    });
  });
});
