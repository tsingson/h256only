# h256only

Fork of jwt-go that rips out every algorithm except H256. The API is a lot
simpler, there are a lot fewer opportunities for vulnerable code, and it's
harder to make errors.

While the inputs and outputs may resemble JWT, this is explicitly *not* JWT.
Algorithm choice is a deliberate JWT design decision; here, specifying an "alg"
parameter in the header is illegal.

## Why?

JWT is a bad specification, and a number of libraries have had problems
implementing it in the past:

- Authentication bypass by specifying "None". In general allowing an attacker to
choose the algorithm, and asking authors to support several different algorithms
in security code, is a bad idea. https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/

- Tell the receiver that an HMAC secret key is the RSA public key and bypass
  signature authentication. https://twitter.com/bcrypt/status/583070541336195072

- Incomplete RSA curve validation: http://blogs.adobe.com/security/2017/03/critical-vulnerability-uncovered-in-json-encryption.html

- The official JWT sponsor does not support X.509 certificate validation in
  their Javascript client library: https://www.npmjs.com/package/jsonwebtoken

All of these problems are due to a specification that is too complex and
algorithms that are difficult to implement. It is likely that JWT libraries will
continue to have problems in the future.

Particular to the jwt library, `jwt-go` forces you to check two different places
for a valid token (`err == nil` and `t.Valid`), and the Keyfunc is error prone.
It also registers a number of hashing methods by default, any one of which could
have an error.

If you still need to use a JWT-like thing, you should use exactly one state of
the art authenticator (HMAC with SHA256), and exactly one method of specifying
which key you want to use (a 256-bit random value, stored as a `[32]byte`).

## Changes from the JWT spec

The only known "typ" parameter for this library is `"h256only"`. All other types
will return an error on parse.

The "alg" parameter is illegal, because the only supported algorithm is H256.

## Upgrade path

It's possible at some point that someone will create a feasible attack against
sha256, the cryptography primitive underlying this library. In that case, you
should not continue to use this library; create a new library with a better
cryptographic primitive and use that instead.

## Differences from jwt-go

This library changed 46 files, added 801 lines and deleted 3131 lines, compared
with jwt-go. Considering that lines of code correlate with defects, fewer lines
of code decreases the chance of a vulnerability appearing in this library.

Here is a partial list of changes.

- No attempt is made to validate contents of the Claims object when parsing a
token. The API's for validating timestamps have been removed; the API's were
confusing, the association between JSON and Javascript may lead people to
think the timestamps should be multiplied or divided by 1000 before use, and
it's difficult to correctly parse large ints in JSON. If you need to validate
`exp`, `iat`, or `nbf`, I suggest storing them in the token in an unambiguous
time format like RFC3339, or writing the parsing logic yourself and testing it
thoroughly.

- SigningMethod has been removed (there is only one accepted algorithm)

- Tokens cannot be invalid - we return an error instead

- No RSA, ECDSA, or None algorithms.

- No Parser type

- The "alg" parameter is illegal. The only allowable "typ" is "h256only"

- ValidationErrors are gone, every function returns exactly one error. We exit
immediately from Parse if there is a failure.

- All keys are `*[32]byte` - this allows us to use the type system. There is no need anymore for Keyfunc.

- TimeFunc is gone.

- Parse/ParseWithClaims don't also return the token, if err is not nil

- Code to extract JWT tokens from HTTP requests is gone (there should be exactly
  one way you can set and get in your own code; implement it yourself)
