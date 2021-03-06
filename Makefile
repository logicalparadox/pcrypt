TESTS = test/*.js
REPORTER = spec

test:
	@NODE_ENV=test ./node_modules/.bin/mocha \
		--require ./test/helpers/bootstrap \
		--reporter $(REPORTER) \
		$(TESTS)

test-cov: lib-cov
	@PCRYPT_COV=1 $(MAKE) test REPORTER=html-cov > coverage.html

lib-cov: clean
	@jscoverage lib lib-cov

clean:
	@rm -rf lib-cov
	@rm -f coverage.html

bench:
	@NODE_ENV=bench ./node_modules/.bin/matcha

.PHONY: test lib-cov test-cov clean bench
