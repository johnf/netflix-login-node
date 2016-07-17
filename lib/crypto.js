
var fs = require('fs');
var forge = require('node-forge');
var request = require('request-promise');
var zlib = require('zlib');

var debug = require('debug')('netflix-login:crypto');
var Purdy = require('purdy');

var netflixLogin = require('../index');
var lzw = require('../lzw');

var netflixPublicKey64 = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlibeiUhffUDs6QqZiB+jXH/MNgITf7OOcMzuSv4G3JysWkc0aPbT3vkCVaxdjNtw50zo2Si8I24z3/ggS3wZaF//lJ/jgA70siIL6J8kBt8zy3x+tup4Dc0QZH0k1oxzQxM90  FB5x+UP0hORqQEUYZCGZ9RbZ/WNV70TAmFkjmckutWN9DtR6WUdAQWr0HxsxI9R05nz5qU2530AfQ95h+WGZqnRoG0W6xO1X05scyscNQg0PNCy3nfKBG+E6uIl5JB4dpc9cgSNgkfAIeuPURhpD0jHkJ/+4ytpdsXAGmwYmoJcCSE1TJyYYoExuoaE8gLFeM01xXK5VIN  U7/eWjQIDAQAB';

module.exports = {
  crypto: {},

  _cryptoDataFilename: 'cryptoData.json',

  _baseOptions: {
    method: 'POST',
    uri: 'https://www.netflix.com/api/msl/NFCDCH-LX-/cadmium/manifest',
  },

  fetchCryptoKeys: function(authData, options) {
    debug('fetching crypto keys');

    var self = this;

    self.authData = authData;

    self._baseOptions = Object.assign({}, netflixLogin._baseOptions, self._baseOptions);
    self._baseOptions.jar = self.authData.cookieJar;

    options = options || {};

    this._importNetflixKey();

    // FIXME: Remove the moo bits ince we are complete
    if (options.useCache && fs.existsSync(this._cryptoDataFilename)) {
      return this._loadFromCache();
    }

    this._generateRSAKeyPair().then(function() {
      return self._sendFirstManifest();
    }).then(function(responseJSON) {
      var response = JSON.parse(responseJSON);

      self._verifyFirstManifest(response);
      self._processFirstManifestResponse(response);
      }).then(function() {
    }).then(function() {
      return self._sendSecondManifest();
    }).then(function(responseJSON) {
      responseJSON = responseJSON.replace(/^{/, '').replace(/}$/, '');
      var parts = responseJSON.split(/}{/);
      parts = parts.map(function(part) {
        return '{' + part + '}';
      });

      var header = JSON.parse(parts[0]);
      var payload = JSON.parse(parts[1]);

      self._verifySecondManifest(header);
      self._processSecondManifestResponse(header);
    }).then(function() {
      if (options.useCache) {
        return self._saveToCache();
      }

      return this.crypto;
    }).catch(function(error) {
      console.error(error.stack);
    });
  },

  _saveToCache: function() {
    debug('saving to cache');

    var self = this;

    var rsaPublicKeyPem = forge.pki.publicKeyToPem(this.crypto.rsaKeyPair.publicKey);
    var rsaPrivateKeyPem = forge.pki.privateKeyToPem(this.crypto.rsaKeyPair.privateKey);
    var data = {
      rsaPublicKeyPemStripped: this.crypto.rsaKeyPair.publicKeyPem,
      rsaPublicKeyPem: rsaPublicKeyPem,
      rsaPrivateKeyPem: rsaPrivateKeyPem,
      mastertoken: this.crypto.mastertoken,
      mastertoken64: this.crypto.mastertoken64,
      keydata: this.crypto.keydata,
      keys: this.crypto.keys,
    };
    var dataJSON = JSON.stringify(data);

    return new Promise(function(resolve, reject) {
      fs.writeFile(self._cryptoDataFilename, dataJSON, function(err) {
        if (err) {
          return reject(err);
        }

        resolve(this.crypto);
      });
    });
  },

  _loadFromCache: function() {
    debug('loading from cache');
    var self = this;

    return new Promise(function(resolve, reject) {
      fs.readFile(self._cryptoDataFilename, function(err, dataJSON) {
        if (err) {
          return reject(err);
        }

        var data = JSON.parse(dataJSON);

        var rsaPublicKey = forge.pki.publicKeyFromPem(data.rsaPublicKeyPem);
        var rsaPrivateKey = forge.pki.privateKeyFromPem(data.rsaPrivateKeyPem);
        self.crypto.rsaKeyPair = {
          publicKey: rsaPublicKey,
          privateKey: rsaPrivateKey,
          publicKeyPem: data.rsaPublicKeyPemStripped
        };
        self.crypto.mastertoken = data.mastertoken;
        self.crypto.mastertoken64 = data.mastertoken64;
        self.crypto.keydata = data.keydata;
        self.crypto.keys = data.keys;

        resolve();
      });
    });
  },

  _importNetflixKey: function() {
    debug('importing netflix public key');

    var netflixPublicKeyBin = forge.util.decode64(netflixPublicKey64);
    var netflixPublicKeyASN1 = forge.asn1.fromDer(netflixPublicKeyBin);
    var netflixPublicKey = forge.pki.publicKeyFromAsn1(netflixPublicKeyASN1);

    this.crypto.netflixPublicKey = netflixPublicKey;

    return netflixPublicKey;
  },

  _generateRSAKeyPair: function() {
    debug('generating RSA key pair');

    var self = this;

    var options = {
      bits: 2048,
      e: 65537
    };

    var promise = new Promise(function(resolve, reject) {
      forge.pki.rsa.generateKeyPair(options, function(err, rsaKeyPair) {
        if (err) {
          reject(err);
          return;
        }

        var publicKeyPem = forge.pki.publicKeyToPem(rsaKeyPair.publicKey);
        publicKeyPem = publicKeyPem.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, '').replace(/\r\n/g, '');

        rsaKeyPair.publicKeyPem = publicKeyPem;

        self.crypto.rsaKeyPair = rsaKeyPair;

        resolve(rsaKeyPair);
      });
    });

    return promise;
  },

  _sendFirstManifest: function() {
    debug('sending first manifest');

    // FIXME: We are hardcoding this at the moment, where should this come from?
    var messageId = 6926246924684790;
    var sequenceNumber = 1;

    var headerdata = {
      messageid: messageId,
      renewable: true,
      capabilities: {
        compressionalgos: ['GZIP'],
        languages: []
      },
      keyrequestdata: [
        {
          scheme: 'ASYMMETRIC_WRAPPED',
          keydata: {
            keypairid: 'rsaKeypairId',
            mechanism: 'JWK_RSA',
            publickey: this.crypto.rsaKeyPair.publicKeyPem,
          }
        }
      ]
    };

    var headerdataJSON = JSON.stringify(headerdata);
    var headerdata64 = forge.util.encode64(headerdataJSON);

    var payload = {
      sequencenumber: sequenceNumber,
      messageid: messageId,
      endofmsg: true,
      compressionalgo: 'GZIP',
      data: ''
    };
    var payloadJSON = JSON.stringify(payload);
    var payload64 = forge.util.encode64(payloadJSON);

    var firstBody = {
      entityauthdata: {
        scheme: 'NONE',
        authdata: {
          identity: this.authData.esn,
        }
      },
      headerdata: headerdata64,
      signature: ''
    };
    var firstBodyJSON = JSON.stringify(firstBody);

    var secondBody = {
      payload: payload64,
      signature: ''
    };
    var secondBodyJSON = JSON.stringify(secondBody);


    var bodyJSON = firstBodyJSON + secondBodyJSON;

    var myOptions = {
      body: bodyJSON,
    };

    var options = Object.assign({}, this._baseOptions, myOptions);

    return request(options);
  },

  _verifyManifestCommon: function(response) {
    debug('verify manifest common');

    if (response.errordata) {
      var errorJSON = forge.util.decode64(response.errordata);
      var error = JSON.parse(errorJSON);

      throw new Error('Error: ' + Purdy.stringify(error));
    }

    if (response.errormsg) {
      throw new Error("Error: " + response.errormsg);
    }
  },

  _verifyFirstManifest: function(response) {
    debug('verify first manifest');

    this._verifyManifestCommon(response);

    var messageText = forge.util.decode64(response.headerdata);
    var signature = forge.util.decode64(response.signature);

    var messageDigest = forge.md.sha256.create();
    messageDigest.update(messageText, 'binary');

    var digest = messageDigest.digest().bytes();

    var validSignature = this.crypto.netflixPublicKey.verify(digest, signature, 'RSASSA-PKCS1-V1_5');

    if (!validSignature) {
      throw new Error('Couldn\'t verify Netflix Signature');
    }
  },


  _processFirstManifestResponse: function(response) {
    debug('processing first manifest response');

    var headerdataJSON = forge.util.decode64(response.headerdata);
    var headerdata = JSON.parse(headerdataJSON);

    // TODO: Verify the mastertoken signature

    this.crypto.mastertoken64 = headerdata.keyresponsedata.mastertoken;
    this.crypto.keydata = headerdata.keyresponsedata.keydata;

    var encryptionKey = this._unwrapKey(this.crypto.keydata.encryptionkey);
    var hmacKey = this._unwrapKey(this.crypto.keydata.hmackey);

    this.crypto.keys = {
      browser: {
        encryptionKey: encryptionKey,
        hmacKey: hmacKey
      }
    };

    var mastertokenJSON = forge.util.decode64(headerdata.keyresponsedata.mastertoken.tokendata);
    var mastertoken = JSON.parse(mastertokenJSON);
    this.crypto.mastertoken = mastertoken;
  },

  _unwrapKey: function(data) {
    debug('unwrap key');

    var wrappedKey = forge.util.decode64(data);

    var unwrappedKeyJSON = this.crypto.rsaKeyPair.privateKey.decrypt(wrappedKey, 'RSA-OAEP');
    var unwrappedKey = JSON.parse(unwrappedKeyJSON);

    // JWK Keys are Base64URL encoded
    var key = unwrappedKey.k;
    key = key.replace(/-/g, '+');
    key = key.replace(/_/g, '/');
    switch (key.length % 4) {
      case 0:
        break;
      case 2:
        key += "==";
        break;
      case 3:
        key += "=";
        break;
      default:
        throw new Error('Illegal base64url string!');
    }
    key = forge.util.decode64(key);

    var keyData = {
      key: key,
    };

    switch (unwrappedKey.alg) {
      case 'A128CBC':
        keyData.algorithm = 'AES-CBC';
        break;
      case 'HS256':
        keyData.algorithm = 'SHA256';
        break;
      default:
        throw new Error('Unsupported algorithm:' + unwrappedKey.alg);
    }

    return keyData;
  },

  _sendSecondManifest: function() {
    debug('sending second manifest');

    // FIXME: Set messageid
    var messageId = 6926246924684792;

    var firstCleartext = {
      sender: this.authData.esn,
      messageid: messageId,
      renewable: true,
      capabilities: {
        compressionalgos: ['GZIP'],
        languages: []
      },
      keyrequestdata: [
      {
        scheme: 'ASYMMETRIC_WRAPPED',
        keydata: {
          keypairid: 'rsaKeypairId',
          mechanism: 'JWK_RSA',
          publickey: this.crypto.rsaKeyPair.publicKeyPem,
        }
      }
      ],
      userauthdata: {
        scheme: 'NETFLIXID',
        authdata: {}
      }
    };

    var firstCleartextJSON = JSON.stringify(firstCleartext);
    var firstEncrypted = this._encrypt(firstCleartextJSON, 'browser');

    var keyId = this.authData.esn + '_' + this.crypto.mastertoken.sequencenumber;

    var headerdata = {
      keyid: keyId,
      iv: firstEncrypted.iv64,
      ciphertext: firstEncrypted.ciphertext64,
      sha256: 'AA==' // FIXME Where does this come from?
    };
    var headerdataJSON = JSON.stringify(headerdata);
    var headerdata64 = forge.util.encode64(headerdataJSON);
    var signature64 = this._sign(headerdataJSON, 'browser');

    var firstBody = {
      mastertoken: this.crypto.mastertoken64,
      headerdata: headerdata64,
      signature: signature64,
    };
    var firstBodyJSON = JSON.stringify(firstBody);

    var uiPlayContext = {
      row: -97,
      rank: -97,
      location: 'WATCHNOW',
      request_id: '2f4d7448-a81f-46a3-b90e-77150ea9e3ec'
    };
    var uiPlayContextJSON = JSON.stringify(uiPlayContext);

    var subData = {
      method: 'manifest',
      lookupType: 'STANDARD',
      viewableIds: [80018191],
      profiles: [
        'playready-h264mpl30-dash',
        'playready-h264mpl31-dash',
        'heaac-2-dash',
        'heaac-2-dash-enc',
        'dfxp-ls-sdh',
        'simplesdh',
        'nflx-cmisc',
        'dfxp-ls-sdh-enc',
        'simplesdh-enc',
        'nflx-cmisc-enc',
        'BIF240',
        'BIF320'
      ],
      drmSystem: 'widevine',
      appId: '146694622769522927',
      sessionParams: {
        pinCapableClient: 'false',
        uiplaycontext: uiPlayContextJSON,
      },
      sessionId: '14669462273748950',
      trackId: 0,
      flavor: 'STANDARD',
      secureUrls: true,
      supportPreviewContent: true,
      forceClearStreams: false,
      languages: ['en-US'],
      clientVersion: '4.0004.857.011',
      uiVersion: 'akira'
    };
    var subDataJSON = JSON.stringify(subData);

    var data = [
    {},
    {
      headers: {},
      path: '/cbp/cadmium-4',
      payload: {
        data: subDataJSON
      },
      query: '',
    }
    ];

    var dataJSON = JSON.stringify(data);
    var compressed64 = this._compress(dataJSON);

    // Body B
    var secondCleartext = {
      sequencenumber: 1,
      messageid: messageId,
      compressionalgo: 'GZIP',
      data: compressed64,
    };

    var secondCleartextJSON = JSON.stringify(secondCleartext);
    var secondEncrypted = this._encrypt(secondCleartextJSON, 'browser');

    var firstPayload = {
      keyid: keyId,
      iv: secondEncrypted.iv64,
      ciphertext: secondEncrypted.ciphertext64,
      sha256: 'AA==' // FIXME Where does this come from?
    };
    var firstPayloadJSON = JSON.stringify(firstPayload);
    var firstPayload64 = forge.util.encode64(firstPayloadJSON);
    var secondSignature64 = this._sign(firstPayloadJSON, 'browser');

    var secondBody = {
      payload: firstPayload64,
      signature: secondSignature64,
    };
    var secondBodyJSON = JSON.stringify(secondBody);

    // Body C
    var thirdCleartext = {
      sequencenumber: 2,
      messageid: messageId,
      endofmsg: true,
      compressionalgo: 'GZIP',
      data: '',
    };

    var thirdEncryptedJSON = JSON.stringify(thirdCleartext);
    var thirdEncrypted = this._encrypt(thirdEncryptedJSON, 'browser');

    var secondPayload = {
      keyid: keyId,
      iv: thirdEncrypted.iv64,
      ciphertext: thirdEncrypted.ciphertext64,
      sha256: 'AA==' // FIXME Where does this come from?
    };
    var secondPayloadJSON = JSON.stringify(secondPayload);
    var secondPayload64 = forge.util.encode64(secondPayloadJSON);
    var thirdSignature64 = this._sign(secondPayloadJSON, 'browser');

    var thirdBody = {
      payload: secondPayload64,
      signature: thirdSignature64,
    };
    var thirdBodyJSON = JSON.stringify(thirdBody);

    var bodyJSON = firstBodyJSON + secondBodyJSON + thirdBodyJSON;

    var myOptions = {
      body: bodyJSON,
    };

    var options = Object.assign({}, this._baseOptions, myOptions);

    return request(options);
  },

  _verifySecondManifest: function(response) {
    debug('verify manifest second');

    this._verifyManifestCommon(response);

    var messageText = forge.util.decode64(response.headerdata);
    var signature64 = response.signature;

    var validSignature = this._verify(messageText, signature64, 'browser');

    if (!validSignature) {
      throw new Error('Couldn\'t verify Netflix Signature');
    }
  },

  _processSecondManifestResponse: function(response) {
    debug('processing manifest second');

    var headerdataJSON = forge.util.decode64(response.headerdata);
    var headerdata = JSON.parse(headerdataJSON);

    var keyresponsedataJSON = this._decrypt(headerdata.ciphertext, headerdata.iv, 'browser');
    var keyresponsedata = JSON.parse(keyresponsedataJSON);

    this.crypto.useridtoken64 = keyresponsedata.useridtoken;

    var useridtokenJSON = forge.util.decode64(keyresponsedata.useridtoken.tokendata);
    var useridtoken = JSON.parse(useridtokenJSON);
    this.crypto.useridtoken = useridtoken;
  },

  _encrypt: function(cleartext, device) {
    debug('encrypt');

    var keyData = this.crypto.keys[device];
    var algorithm = keyData.encryptionKey.algorithm;
    var key = keyData.encryptionKey.key;
    var iv = forge.random.getBytesSync(16);

    var buffer = forge.util.createBuffer(cleartext);

    var cipher = forge.cipher.createCipher(algorithm, key);
    cipher.start({iv: iv});
    cipher.update(buffer);
    cipher.finish();

    var encrypted = cipher.output.getBytes();
    var encrypted64 = forge.util.encode64(encrypted);

    var iv64 = forge.util.encode64(iv);

    return {
      ciphertext64: encrypted64,
      iv64: iv64,
    };
  },

  _decrypt: function(ciphertext64, iv64, device) {
    debug('encrypt json');

    var keyData = this.crypto.keys[device];
    var algorithm = keyData.encryptionKey.algorithm;
    var key = keyData.encryptionKey.key;
    var iv = forge.util.decode64(iv64);
    var ciphertext = forge.util.decode64(ciphertext64);

    var decipher = forge.cipher.createDecipher(algorithm, key);
    decipher.start({iv: iv});
    decipher.update(forge.util.createBuffer(ciphertext));
    decipher.finish();

    var decrypted = decipher.output.getBytes();

    return decrypted;
  },

  _sign: function(text2sign, device) {
    debug('sign');

    var keyData = this.crypto.keys[device];
    var algorithm = keyData.hmacKey.algorithm;
    var key = keyData.hmacKey.key;

    var hmac = forge.hmac.create();
    hmac.start(algorithm, key);
    hmac.update(text2sign);

    var digest = hmac.digest();
    var signature = digest.bytes();
    var signature64 = forge.util.encode64(signature);

    return signature64;
  },

  _verify: function(text2verify, signature, device) {
    debug('verify');

    var mySignature = this._sign(text2verify, device);

    return mySignature === signature;
  },

  _compress: function(data) {
    debug('compress');

    var compressed = zlib.gzipSync(data);
    var compressed64 = compressed.toString('base64');

    return compressed64;
  },
};
