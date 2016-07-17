"use strict";

var fs = require('fs');
var request = require('request-promise');
var tough = require('tough-cookie');

var Purdy = require('purdy');
var debug = require('debug')('netflix-login');


module.exports = {
  _baseOptions: {
    uri: 'https://www.netflix.com/Login',
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.10586',
    },
    jar: request.jar()
  },

  _authDataFilename: 'authData.json',

  login: function(email, password, options) {
    var self = this;

    options = options || {};

    if (options.useCache && fs.existsSync(self._authDataFilename)) {
      return self._loadFromCache();
    }

    return self._getAuthURL().then(function(authURL) {
      return self._postLogin(authURL, email, password);
    }).then(function(location) {
      return self._getLogin(location);
    }).then(function(authData) {
      if (options.useCache) {
        return self._saveToCache(authData);
      }
      else {
        return authData;
      }
    });
  },

  expired: function() {
    var result = false;

    if (this._cookiesMissing()) {
      return true;
    }

    var cookies = this._cookies();
    console.log(cookies);
    for(let cookie of cookies) {
      if (cookie.key !== 'NetflixId' && cookie.key !== 'SecureNetflixId') {
        continue;
      }
      if (cookie.TTL() === 0) {
        result = true;
      }
    }

    return result;
  },

  _saveToCache: function(authData) {
    debug('saving to cache');

    var self = this;

    var data = {
      cookieJSON: authData.cookieJar._jar.toJSON(),
      esn: authData.esn
    };
    var dataJSON = JSON.stringify(data);

    return new Promise(function(resolve, reject) {
      fs.writeFile(self._authDataFilename, dataJSON, function(err) {
        if (err) {
          return reject(err);
        }

        resolve(authData);
      });
    });
  },

  _loadFromCache: function() {
    debug('loading from cache');
    var self = this;

    return new Promise(function(resolve, reject) {
      fs.readFile(self._authDataFilename, function(err, dataJSON) {
        if (err) {
          return reject(err);
        }

        var data = JSON.parse(dataJSON);

        var cookieJar = new tough.CookieJar.fromJSON(data.cookieJSON);
        var authData = {
          cookieJar: request.jar(cookieJar.store),
          esn: data.esn
        };

        resolve(authData);
      });
    });
  },

  _cookiesMissing: function() {
    var result = 0;

    var cookies = this._cookies();
    for(let cookie of cookies) {
      if (cookie.key === 'NetflixId' || cookie.key === 'SecureNetflixId') {
        result++;
      }
    }

    if (result === 2) {
      return false;
    }
    else {
      return true;
    }
  },

  _cookieJar: function() {
    return this._baseOptions.jar;
  },

  _cookies: function() {
    return this._cookieJar().getCookies(this._baseOptions.uri);
  },

  _reset: function() {
    this._baseOptions.jar = request.jar();
  },

  _getAuthURL: function() {
    return request(this._baseOptions).then(function (body) {
      var authURL = body.match(/name="authURL" value="(.+?)"/)[1];
      debug('authURL: ' + authURL);

      return authURL;
    }) .catch(function (err) {
      throw new Error('netflix-login: Couldn\'t retrieve authURL' + err);
    });
  },

  _postLogin: function(authURL, email, password) {
    var myOptions = {
      method: 'POST',
      simple: false,
      resolveWithFullResponse: true,
      form: {
        authURL: authURL,
        email: email,
        password: password,
        rememberMeCheckbox: 'true',
        flow: 'websiteSignUp',
        mode: 'login',
        action: 'loginAction',
        withFields: 'email,password,rememberMe,nextPage',
        nextPage: ''
      },
    };

    var options = Object.assign({}, this._baseOptions, myOptions);

    return request(options).then(function (response) {
      if (response.statusCode !== 302) {
        throw new Error('netflix-login: Login POST didn\'t redirect. status code: ' + response.statusCode);
      }

      var location = response.headers.location;
      debug('redirected to ' + location);

      return location;
    }).catch(function (err) {
      throw new Error('netflix-login: postLogin failed ' + Purdy.stringify(err));
    });
  },

  _getLogin: function(location) {
    var self = this;

    return request(this._baseOptions).then(function (body) {
      var cookies = self._cookies();
      var authData = {
        cookieJar: self._cookieJar()
      };

      for(let cookie of cookies) {
        if (cookie.key === 'NetflixId') {
          authData.netflixId = cookie.value;
        }
        if (cookie.key === 'SecureNetflixId') {
          authData.secureNetflixId = cookie.value;
        }
      }

      authData.esn = body.match(/"esn":"([^"]+)"/)[1];

      debug('authData: ' + Purdy.stringify(authData));

      return authData;
    }).catch(function (err) {
      throw new Error('netflix-login: getLogin failed ' + err.stack);
    });
  },
};
