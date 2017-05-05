const jwt = require('jsonwebtoken');
const pem2jwk = require('pem-jwk').pem2jwk;
const ursa = require('ursa');

const ursaKeys = ursa.generatePrivateKey();
const generatedKeys = {
  'public': ursaKeys.toPublicPem('utf8'),
  'private': ursaKeys.toPrivatePem('utf8'),
};

module.exports = class {
  setupToken(customOptions) {
    const options = customOptions || {};
    this.keys = generatedKeys;
    this.rsaKeys = ursaKeys;
    this.header = Object.assign({}, this.getSampleHeader(), options.header);
    this.payload = Object.assign({}, this.getSamplePayload(), options.payload);
    this.kid = this.header.kid;
    this.tokenString = this.getSignedTokenString(this.keys.private, options.signOptions);
    this.signature = this.tokenString.split('.')[2];
    this.bearerTokenString = `Bearer ${this.tokenString}`;
    this.jwk = this.getSampleJWK();
  }

  getSampleHeader() {
    return {
      'alg': 'RS256',
      'typ': 'JWT',
      'kid': '1234567',
    };
  }

  setupExpiredToken(customOptions) {
    const expiration = Math.floor(Date.now() / 1000) - (60 * 60);
    const options = Object.assign({}, customOptions);
    options.payload.exp = expiration;
    return this.setupToken(options);
  }

  setupValidToken(customOptions) {
    const expiration = Math.floor(Date.now() / 1000) + (60 * 60);
    const options = Object.assign({}, customOptions);
    options.payload.exp = expiration;
    return this.setupToken(expiration);
  }

  getSignedTokenString(privatePem, customSignOptions) {
    const defaultOptions = {
      'header': this.header,
      'algorithm': 'RS256',
    };
    const signOptions = Object.assign({}, defaultOptions, customSignOptions);
    return jwt.sign(this.payload, privatePem, signOptions);
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
