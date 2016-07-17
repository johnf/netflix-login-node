"use strict";

var expect = require('chai').expect;
var nock = require('nock');

var netflixCrypto = require('../lib/crypto');

var Purdy = require('purdy');

// Setup nock
nock.disableNetConnect();

describe('Netflix Crypto', function() {

  describe('#_importNetflixKey()', function() {
    it('should decode the public key', function() {
      var netflixPublicKey = netflixCrypto._importNetflixKey();
      expect(netflixPublicKey).to.be.an('object');
      expect(netflixPublicKey).to.have.property('n');
    });
  });

  describe('#_generateRSAKeyPair()', function() {
    this.timeout(10000);

    it('should generate an RSA key pair', function() {
      return netflixCrypto._generateRSAKeyPair().then(function(rsaKeyPair) {
        expect(rsaKeyPair).to.be.an('object');
        expect(rsaKeyPair).to.have.property('privateKey');
        expect(rsaKeyPair).to.have.property('publicKey');
        expect(rsaKeyPair).to.have.property('publicKeyPem');
      });
    });
  });
});
