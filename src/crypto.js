import fs from 'fs';
import forge from 'node-forge';
import request from 'request-promise';
import zlib from 'zlib';
import Debug from 'debug';
import Purdy from 'purdy';
import util from 'util';

util.inspect.defaultOptions.depth = null;

const debug = Debug('netflix-login:crypto');

const netflixPublicKey64 = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlibeiUhffUDs6QqZiB+jXH/MNgITf7OOcMzuSv4G3JysWkc0aPbT3vkCVaxdjNtw50zo2Si8I24z3/ggS3wZaF//lJ/jgA70siIL6J8kBt8zy3x+tup4Dc0QZH0k1oxzQxM90  FB5x+UP0hORqQEUYZCGZ9RbZ/WNV70TAmFkjmckutWN9DtR6WUdAQWr0HxsxI9R05nz5qU2530AfQ95h+WGZqnRoG0W6xO1X05scyscNQg0PNCy3nfKBG+E6uIl5JB4dpc9cgSNgkfAIeuPURhpD0jHkJ/+4ytpdsXAGmwYmoJcCSE1TJyYYoExuoaE8gLFeM01xXK5VIN  U7/eWjQIDAQAB'; // eslint-disable-line max-len

export const encrypt = (cleartext, keys) => {
  debug('encrypt');

  const algorithm = keys.encryptionKey.algorithm;
  const key = forge.util.decode64(keys.encryptionKey.key64);
  const iv = forge.random.getBytesSync(16);

  const buffer = forge.util.createBuffer(cleartext);

  const cipher = forge.cipher.createCipher(algorithm, key);
  cipher.start({ iv });
  cipher.update(buffer);
  cipher.finish();

  const encrypted = cipher.output.getBytes();
  const encrypted64 = forge.util.encode64(encrypted);

  const iv64 = forge.util.encode64(iv);

  return {
    ciphertext64: encrypted64,
    iv64,
  };
};

export const decrypt = (ciphertext64, iv64, keys) => {
  debug('encrypt json');

  const algorithm = keys.encryptionKey.algorithm;
  const key = forge.util.decode64(keys.encryptionKey.key64);
  const iv = forge.util.decode64(iv64);
  const ciphertext = forge.util.decode64(ciphertext64);

  const decipher = forge.cipher.createDecipher(algorithm, key);
  decipher.start({ iv });
  decipher.update(forge.util.createBuffer(ciphertext));
  decipher.finish();

  const decrypted = decipher.output.getBytes();

  return decrypted;
};

export const sign = (text2sign, keys) => {
  debug('sign');

  const algorithm = keys.hmacKey.algorithm;
  const key = forge.util.decode64(keys.hmacKey.key64);

  const hmac = forge.hmac.create();
  hmac.start(algorithm, key);
  hmac.update(text2sign);

  const digest = hmac.digest();
  const signature = digest.bytes();
  const signature64 = forge.util.encode64(signature);

  return signature64;
};

const verify = (text2verify, signature, keys) => {
  debug('verify');

  const mySignature = sign(text2verify, keys);

  return mySignature === signature;
};

const unwrapKey = (data, cryptoKeys) => {
  debug('unwrap key');

  const wrappedKey = forge.util.decode64(data);

  const unwrappedKeyJSON = cryptoKeys.rsaKeyPair.privateKey.decrypt(wrappedKey, 'RSA-OAEP');
  const unwrappedKey = JSON.parse(unwrappedKeyJSON);

  // JWK Keys are Base64URL encoded
  let key = unwrappedKey.k;
  key = key.replace(/-/g, '+');
  key = key.replace(/_/g, '/');
  switch (key.length % 4) {
    case 0:
      break;
    case 2:
      key += '==';
      break;
    case 3:
      key += '=';
      break;
    default:
      throw new Error('Illegal base64url string!');
  }
  key = forge.util.decode64(key);

  const keyData = {
    key,
  };

  switch (unwrappedKey.alg) {
    case 'A128CBC':
      keyData.algorithm = 'AES-CBC';
      break;
    case 'HS256':
      keyData.algorithm = 'SHA256';
      break;
    default:
      throw new Error(`Unsupported algorithm: ${unwrappedKey.alg}`);
  }

  return keyData;
};

const compress = (data) => {
  debug('compress');

  const compressed = zlib.gzipSync(data);
  const compressed64 = compressed.toString('base64');

  return compressed64;
};

const saveToCache = (filename, cryptoKeys) => {
  debug('saving to cache');

  const rsaPublicKeyPem = forge.pki.publicKeyToPem(cryptoKeys.rsaKeyPair.publicKey);
  const rsaPrivateKeyPem = forge.pki.privateKeyToPem(cryptoKeys.rsaKeyPair.privateKey);

  const data = {
    ...cryptoKeys,
    rsaPublicKeyPemStripped: cryptoKeys.rsaKeyPair.publicKeyPem,
    rsaPublicKeyPem,
    rsaPrivateKeyPem,
  };

  delete data.rsaKeyPair;
  delete data.netflixPublicKey;
  delete data.authData;

  const dataJSON = JSON.stringify(data);

  fs.writeFileSync(filename, dataJSON);
};

const loadFromCache = (filename) => {
  debug('loading from cache');

  const dataJSON = fs.readFileSync(filename);
  const data = JSON.parse(dataJSON);

  const publicKey = forge.pki.publicKeyFromPem(data.rsaPublicKeyPem);
  const privateKey = forge.pki.privateKeyFromPem(data.rsaPrivateKeyPem);
  const publicKeyPem = data.rsaPublicKeyPemStripped;
  delete data.rsaPublicKeyPem;
  delete data.rsaPrivateKeyPem;
  delete data.rsaPublicKeyPemStripped;

  return {
    ...data,
    rsaKeyPair: {
      publicKey,
      privateKey,
      publicKeyPem,
    },
  };
};

const importNetflixKey = () => {
  debug('importing netflix public key');

  const netflixPublicKeyBin = forge.util.decode64(netflixPublicKey64);
  const netflixPublicKeyASN1 = forge.asn1.fromDer(netflixPublicKeyBin);
  const netflixPublicKey = forge.pki.publicKeyFromAsn1(netflixPublicKeyASN1);

  return netflixPublicKey;
};

const forgePromisegenerateKeyPair = options => (
  new Promise((resolve, reject) => {
    forge.pki.rsa.generateKeyPair(options, (err, rsaKeyPair) => {
      if (err) {
        return reject(err);
      }

      return resolve(rsaKeyPair);
    });
  })
);

const generateRSAKeyPair = () => {
  debug('generating RSA key pair');

  const options = {
    bits: 2048,
    e: 65537,
  };

  return forgePromisegenerateKeyPair(options)
    .then((rsaKeyPair) => {
      let publicKeyPem = forge.pki.publicKeyToPem(rsaKeyPair.publicKey);
      publicKeyPem = publicKeyPem.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, '').replace(/\r\n/g, '');

      return {
        ...rsaKeyPair,
        publicKeyPem,
      };
    });
};

const sendFirstManifest = (requestOptions, cryptoKeys) => {
  debug('sending first manifest');

  // FIXME: We are hardcoding this at the moment, where should this come from?
  const messageId = 6926246924684790;
  const sequenceNumber = 1;

  const headerdata = {
    messageid: messageId,
    renewable: true,
    capabilities: {
      compressionalgos: ['GZIP'],
      languages: [],
    },
    keyrequestdata: [
      {
        scheme: 'ASYMMETRIC_WRAPPED',
        keydata: {
          keypairid: 'rsaKeypairId',
          mechanism: 'JWK_RSA',
          publickey: cryptoKeys.rsaKeyPair.publicKeyPem,
        },
      },
    ],
  };

  const headerdataJSON = JSON.stringify(headerdata);
  const headerdata64 = forge.util.encode64(headerdataJSON);

  const payload = {
    sequencenumber: sequenceNumber,
    messageid: messageId,
    endofmsg: true,
    compressionalgo: 'GZIP',
    data: '',
  };
  const payloadJSON = JSON.stringify(payload);
  const payload64 = forge.util.encode64(payloadJSON);

  const firstBody = {
    entityauthdata: {
      scheme: 'NONE',
      authdata: {
        identity: cryptoKeys.authData.esn,
      },
    },
    headerdata: headerdata64,
    signature: '',
  };
  const firstBodyJSON = JSON.stringify(firstBody);

  const secondBody = {
    payload: payload64,
    signature: '',
  };
  const secondBodyJSON = JSON.stringify(secondBody);

  const bodyJSON = firstBodyJSON + secondBodyJSON;

  const options = {
    ...requestOptions,
    body: bodyJSON,
  };

  return request(options);
};

const verifyManifestCommon = (response) => {
  debug('verify manifest common');

  if (response.errordata) {
    const errorJSON = forge.util.decode64(response.errordata);
    const error = JSON.parse(errorJSON);

    throw new Error(`Error: ${Purdy.stringify(error)}`);
  }

  if (response.errormsg) {
    throw new Error(`Error: ${response.errormsg}`);
  }
};

const verifyFirstManifest = (response, cryptoKeys) => {
  debug('verify first manifest');

  verifyManifestCommon(response);

  const messageText = forge.util.decode64(response.headerdata);
  const signature = forge.util.decode64(response.signature);

  const messageDigest = forge.md.sha256.create();
  messageDigest.update(messageText, 'binary');

  const digest = messageDigest.digest().bytes();

  const validSignature = cryptoKeys.netflixPublicKey.verify(digest, signature, 'RSASSA-PKCS1-V1_5');

  if (!validSignature) {
    throw new Error('Couldn\'t verify Netflix Signature');
  }
};


const processFirstManifestResponse = (response, cryptoKeys) => {
  debug('processing first manifest response');

  const headerdataJSON = forge.util.decode64(response.headerdata);
  const headerdata = JSON.parse(headerdataJSON);

  const keydata = headerdata.keyresponsedata.keydata;

  const encryptionKey = unwrapKey(keydata.encryptionkey, cryptoKeys);
  const hmacKey = unwrapKey(keydata.hmackey, cryptoKeys);
  encryptionKey.key64 = forge.util.encode64(encryptionKey.key);
  delete encryptionKey.key;
  hmacKey.key64 = forge.util.encode64(hmacKey.key);
  delete hmacKey.key;

  // TODO: Verify the mastertoken signature
  const mastertokenJSON = forge.util.decode64(headerdata.keyresponsedata.mastertoken.tokendata);
  const mastertoken = JSON.parse(mastertokenJSON);

  return {
    mastertoken64: headerdata.keyresponsedata.mastertoken,
    mastertoken,
    keydata,
    keys: {
      browser: {
        encryptionKey,
        hmacKey,
      },
    },
  };
};

const sendSecondManifest = (requestOptions, cryptoKeys) => {
  debug('sending second manifest');

  // FIXME: Set messageid
  const messageId = 6926246924684792;

  const firstCleartext = {
    sender: cryptoKeys.authData.esn,
    messageid: messageId,
    renewable: true,
    capabilities: {
      compressionalgos: ['GZIP'],
      languages: [],
    },
    keyrequestdata: [
      {
        scheme: 'ASYMMETRIC_WRAPPED',
        keydata: {
          keypairid: 'rsaKeypairId',
          mechanism: 'JWK_RSA',
          publickey: cryptoKeys.rsaKeyPair.publicKeyPem,
        },
      },
    ],
    userauthdata: {
      scheme: 'NETFLIXID',
      authdata: {},
    },
  };

  const firstCleartextJSON = JSON.stringify(firstCleartext);
  const firstEncrypted = encrypt(firstCleartextJSON, cryptoKeys.keys.browser);

  const keyId = `${cryptoKeys.authData.esn}_${cryptoKeys.mastertoken.sequencenumber}`;

  const headerdata = {
    keyid: keyId,
    iv: firstEncrypted.iv64,
    ciphertext: firstEncrypted.ciphertext64,
    sha256: 'AA==', // FIXME Where does this come from?
  };
  const headerdataJSON = JSON.stringify(headerdata);
  const headerdata64 = forge.util.encode64(headerdataJSON);
  const signature64 = sign(headerdataJSON, cryptoKeys.keys.browser);

  const firstBody = {
    mastertoken: cryptoKeys.mastertoken64,
    headerdata: headerdata64,
    signature: signature64,
  };
  const firstBodyJSON = JSON.stringify(firstBody);

  // const uiPlayContext = {
  //   row: -97,
  //   rank: -97,
  //   location: 'WATCHNOW',
  //   request_id: '2f4d7448-a81f-46a3-b90e-77150ea9e3ec',
  // };
  // const uiPlayContextJSON = JSON.stringify(uiPlayContext);

  const subData = {
    method: 'manifest',
    lookupType: 'PREPARE',
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
      'BIF320',
    ],
    drmSystem: 'widevine',
    appId: '146694622769522927',
    sessionParams: {
      pinCapableClient: 'false',
      uiplaycontext: null, // uiPlayContextJSON,
    },
    sessionId: '14880682902052',  // time_t * 10000
    trackId: 0,
    flavor: 'PRE_FETCH',
    secureUrls: true,
    supportPreviewContent: true,
    forceClearStreams: false,
    validatePinProtection: false,
    usePlayReadyHeaderObject: false,
    showAllSubDubTracks: false,
    languages: ['en-AU'],
    clientVersion: '4.0006.237.011',
    uiVersion: 'akira',
  };
  const subDataJSON = JSON.stringify(subData);

  const data = [
    {},
    {
      headers: {},
      path: '/cbp/cadmium-13',
      payload: {
        data: subDataJSON,
      },
      query: '',
    },
  ];

  const dataJSON = JSON.stringify(data);
  const compressed64 = compress(dataJSON);

  // Body B
  const secondCleartext = {
    sequencenumber: 1,
    messageid: messageId,
    compressionalgo: 'GZIP',
    data: compressed64,
  };

  const secondCleartextJSON = JSON.stringify(secondCleartext);
  const secondEncrypted = encrypt(secondCleartextJSON, cryptoKeys.keys.browser);

  const firstPayload = {
    keyid: keyId,
    iv: secondEncrypted.iv64,
    ciphertext: secondEncrypted.ciphertext64,
    sha256: 'AA==', // FIXME Where does this come from?
  };
  const firstPayloadJSON = JSON.stringify(firstPayload);
  const firstPayload64 = forge.util.encode64(firstPayloadJSON);
  const secondSignature64 = sign(firstPayloadJSON, cryptoKeys.keys.browser);

  const secondBody = {
    payload: firstPayload64,
    signature: secondSignature64,
  };
  const secondBodyJSON = JSON.stringify(secondBody);

  // Body C
  const thirdCleartext = {
    sequencenumber: 2,
    messageid: messageId,
    endofmsg: true,
    compressionalgo: 'GZIP',
    data: '',
  };

  const thirdEncryptedJSON = JSON.stringify(thirdCleartext);
  const thirdEncrypted = encrypt(thirdEncryptedJSON, cryptoKeys.keys.browser);

  const secondPayload = {
    keyid: keyId,
    iv: thirdEncrypted.iv64,
    ciphertext: thirdEncrypted.ciphertext64,
    sha256: 'AA==', // FIXME Where does this come from?
  };
  const secondPayloadJSON = JSON.stringify(secondPayload);
  const secondPayload64 = forge.util.encode64(secondPayloadJSON);
  const thirdSignature64 = sign(secondPayloadJSON, cryptoKeys.keys.browser);

  const thirdBody = {
    payload: secondPayload64,
    signature: thirdSignature64,
  };
  const thirdBodyJSON = JSON.stringify(thirdBody);

  const bodyJSON = firstBodyJSON + secondBodyJSON + thirdBodyJSON;

  const options = {
    ...requestOptions,
    body: bodyJSON,
  };

  return request(options);
};

const verifySecondManifest = (response, cryptoKeys) => {
  debug('verify manifest second');

  verifyManifestCommon(response);

  const messageText = forge.util.decode64(response.headerdata);
  const signature64 = response.signature;

  const validSignature = verify(messageText, signature64, cryptoKeys.keys.browser);

  if (!validSignature) {
    throw new Error('Couldn\'t verify Netflix Signature');
  }
};

const processSecondManifestResponse = (response, cryptoKeys) => {
  debug('processing manifest second');

  const headerdataJSON = forge.util.decode64(response.headerdata);
  const headerdata = JSON.parse(headerdataJSON);

  const keyresponsedataJSON = decrypt(headerdata.ciphertext, headerdata.iv, cryptoKeys.keys.browser);
  const keyresponsedata = JSON.parse(keyresponsedataJSON);


  const useridtokenJSON = forge.util.decode64(keyresponsedata.useridtoken.tokendata);
  const useridtoken = JSON.parse(useridtokenJSON);

  return {
    useridtoken64: keyresponsedata.useridtoken,
    useridtoken,
  };
};

export const fetchCryptoKeys = (authData, options = {}) => {
  debug('fetching crypto keys');

  let cryptoKeys = {};
  const cryptoDataFilename = `${options.cachePath}/cryptoData.json`;

  const requestOptions = {
    method: 'POST',
    uri: 'https://www.netflix.com/api/msl/NFCDCH-LX-/cadmium/manifest',
    headers: {
      'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3004.3 Safari/537.36',
    },
    jar: authData.cookieJar,
  };

  debug(authData);

  cryptoKeys.netflixPublicKey = importNetflixKey();
  cryptoKeys.authData = authData;

  if (options.useCache && fs.existsSync(cryptoDataFilename)) {
    const cryptoData = loadFromCache(cryptoDataFilename);
    return {
      ...cryptoKeys,
      ...cryptoData,
    };
  }

  return generateRSAKeyPair()
    .then((rsaKeyPair) => {
      cryptoKeys.rsaKeyPair = rsaKeyPair;
      debug(cryptoKeys);
      return sendFirstManifest(requestOptions, cryptoKeys);
    })
  .then((responseJSON) => {
    const response = JSON.parse(responseJSON);

    verifyFirstManifest(response, cryptoKeys);
    return processFirstManifestResponse(response, cryptoKeys);
  })
  .then((data) => {
    cryptoKeys = {
      ...cryptoKeys,
      ...data,
    };

    return sendSecondManifest(requestOptions, cryptoKeys);
  })
  .then((responseJSON) => {
    const myResponseJSON = responseJSON.replace(/^{/, '').replace(/}$/, '');
    let parts = myResponseJSON.split(/}{/);
    parts = parts.map(part => `{${part}}`);

    const header = JSON.parse(parts[0]);
    // FIXME why do we ignore the payload?
    // const payload = JSON.parse(parts[1]);

    verifySecondManifest(header, cryptoKeys);
    return processSecondManifestResponse(header, cryptoKeys);
  })
  .then((data) => {
    cryptoKeys = {
      ...cryptoKeys,
      ...data,
    };

    if (options.useCache) {
      saveToCache(cryptoDataFilename, cryptoKeys);
    }

    return cryptoKeys;
  })
  .catch((error) => {
    console.error(error.stack);
  });
};
