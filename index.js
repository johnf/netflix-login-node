"use strict";

var request = require('request-promise');

var Purdy = require('purdy');
var debug = require('debug')('netflix-login');

var baseOptions = {
  uri: 'https://www.netflix.com/Login',
  headers: {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.10586',
  },
  jar: request.jar()
};

module.exports = {
  login: function(email, password) {
    var self = this;

    return self._getAuthURL().then(function(authURL) {
      return self._postLogin(authURL, email, password);
    }).then(function(location) {
      return self._getLogin(location);
    });
  },

  _cookies: function() {
    return this._cookieJar().getCookies(baseOptions.uri);
  },

  _getAuthURL: function() {
    return request(baseOptions).then(function (body) {
      var authURL = body.match(/name="authURL" value="(.+?)"/)[1];
      debug('authURL: ' + authURL);

      return authURL;
    }) .catch(function (err) {
      throw new Error('netflix-login: Couldn\'t retrieve authURL' + err);
    });
  },

  _postLogin: function(authURL, email, password) {
    var options = {
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

    Object.assign(options, baseOptions);

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

    return request(baseOptions).then(function (body) {
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
