var pcrypt = require('..')
  , pass = 'hello-universe';

var options = [
    [ 128, 1000 ]
  , [ 256, 1000 ]
  , [ 512, 1000 ]
  , [ 1024, 1000 ]
  , [ 128, 2000 ]
  , [ 128, 4000 ]
  , [ 128, 8000 ]
  , [ 128, 16000 ]
]

suite('generate', function () {
  set('iterations', 10);
  set('mintime', 1000);

  function generate (len, iters) {
    var crypt = pcrypt();
    crypt.set('length', len);
    crypt.set('iterations', iters);
    return function (done)  {
      crypt.gen(pass, function (err, passkey) {
        if (err) throw err;
        done();
      });
    }
  }

  options.forEach(function (opt) {
    var len = opt[0]
      , iters = opt[1];
    bench('len: ' + len + ', iters: ' + iters, generate(len, iters));
  });
});
