// import { expect } from 'chai';
import nock from 'nock';

// import netflixCrypto from '../src/crypto';

// Setup nock
nock.disableNetConnect();

describe('Netflix Crypto', () => {
  /*
  describe('#_importNetflixKey()', () => {
    it('should decode the public key', () => {
      const netflixPublicKey = netflixCrypto.importNetflixKey();
      expect(netflixPublicKey).to.be.an('object');
      expect(netflixPublicKey).to.have.property('n');
    });
  });

  describe('#_generateRSAKeyPair()', function moo() {
    this.timeout(10000);

    it('should generate an RSA key pair', () => (
      netflixCrypto.generateRSAKeyPair().then((rsaKeyPair) => {
        expect(rsaKeyPair).to.be.an('object');
        expect(rsaKeyPair).to.have.property('privateKey');
        expect(rsaKeyPair).to.have.property('publicKey');
        expect(rsaKeyPair).to.have.property('publicKeyPem');
      })
    ));
  });
  */
});
