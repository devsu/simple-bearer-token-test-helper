const jwt = require('jsonwebtoken');
const pem2jwk = require('pem-jwk').pem2jwk;
const ursa = require('ursa');

const ursaKeys = ursa.generatePrivateKey();
const generatedKeys = {
  'public': ursaKeys.toPublicPem('utf8'),
  'private': ursaKeys.toPrivatePem('utf8'),
};

module.exports = class {
  setupToken(expiration) {
    this.keys = generatedKeys;
    this.rsaKeys = ursaKeys;
    this.kid = '1234567';
    this.header = {
      'alg': 'RS256',
      'typ': 'JWT',
      'kid': this.kid,
    };
    this.payload = this.getSamplePayload();
    this.payload.exp = expiration;
    this.tokenString = this.getSignedTokenString(this.payload, this.kid,
      this.keys.private);
    this.signature = this.tokenString.split('.')[2];
    this.bearerTokenString = `Bearer ${this.tokenString}`;
    this.jwk = this.getSampleJWK();
  }

  setupExpiredToken() {
    const expiration = Math.floor(Date.now() / 1000) - (60 * 60);
    return this.setupToken(expiration);
  }

  setupValidToken() {
    const expiration = Math.floor(Date.now() / 1000) + (60 * 60);
    return this.setupToken(expiration);
  }

  getSignedTokenString(payload, kid, privatePem) {
    const options = {
      'header': {
        'kid': kid,
      },
      'algorithm': 'RS256',
    };
    return jwt.sign(payload, privatePem, options);
  }

  getSampleJWK() {
    const jwk = pem2jwk(this.keys.public);
    jwk.kid = this.kid;
    jwk.alg = 'RS256';
    jwk.use = 'sig';
    return jwk;
  }

  getSamplePayload() {
    return {
      'realm_access': {
        'roles': ['admin', 'uma_authorization', 'user'],
      },
      'resource_access': {
        'node-service': {
          'roles': ['view-everything'],
        },
        'account': {
          'roles': ['manage-account', 'manage-account-links', 'view-profile'],
        },
      },
      'name': 'Juan Perez',
      'preferred_username': 'juanperez@example.com',
      'given_name': 'Juan',
      'family_name': 'Perez',
      'email': 'juanperez@example.com',
      'typ': 'Bearer',
    };
  }

  verifyToken(token) {
    expect(token.header).toEqual(this.header);
    expect(token.payload).toEqual(jasmine.objectContaining(this.payload));
    expect(token.signature).toEqual(this.signature);
    expect(token.raw).toEqual(this.tokenString);
  }
};
