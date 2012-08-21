var pcrypt = require('..')
  , pass = 'hello-universe'
  , notpass = 'hello-world';

describe('generate', function () {

  it('can make a passkey', function (done) {
    pcrypt.gen(pass, function (err, key) {
      Should.not.exist(err);
      key.should.be.a('string')
        .with.length(300);
      done();
    });
  });

});

describe('compare', function () {

  it('can matches on same pass', function (done) {
    pcrypt.gen(pass, function (err, str) {
      Should.not.exist(err);
      pcrypt.compare(pass, str, function (err, match) {
        Should.not.exist(err);
        match.should.be.true;
        done();
      });
    });
  });

  it('doesn\'t match on different pass', function (done) {
    pcrypt.gen(pass, function (err, str) {
      Should.not.exist(err);
      pcrypt.compare(notpass, str, function (err, match) {
        Should.not.exist(err);
        match.should.be.false;
        done();
      });
    });
  });

});

describe('length', function () {

  it('can set length', function (done) {
    pcrypt.length = 256;
    pcrypt.should.have.length(256);

    pcrypt.gen(pass, function (err, key) {
      Should.not.exist(err);
      key.should.be.a('string')
        .with.length(600);
      pcrypt.length = 128;
      done();
    });
  });

});

describe('iterations', function () {

  it('can set length', function (done) {
    pcrypt.iterations = 2000;
    pcrypt.iterations.should.equal(2000);

    pcrypt.gen(pass, function (err, key) {
      Should.not.exist(err);
      key.should.be.a('string')
        .with.length(300);
      pcrypt.iterations = 1000;
      done();
    });
  });

});

describe('random password generation', function () {
  var charsDef = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
    , charsNew = 'abc123';

  beforeEach(function () {
    pcrypt.randChars = charsDef;
    pcrypt.randLength = 10;
  });

  it('can be configured', function () {
    pcrypt.should.have.property('randChars', charsDef);
    pcrypt.should.have.property('randLength', 10);

    pcrypt.randChars = charsNew;
    pcrypt.should.have.property('randChars', charsNew);

    pcrypt.randLength = 20;
    pcrypt.should.have.property('randLength', 20);
  });

  it('can generate a random password', function (done) {
    pcrypt.random(function (err, pass, key) {
      Should.not.exist(err);
      Should.exist(pass);
      Should.exist(key);

      pass.should.have.length(pcrypt.randLength);

      pcrypt.compare(pass, key, function (err, match) {
        Should.not.exist(err);
        match.should.be.true;
        done();
      });
    });
  });

});
