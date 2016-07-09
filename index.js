"use strict";

var request = require('request-promise');

var Purdy = require('purdy');
var debug = require('debug')('netflix-login');

module.exports = {
  headers: {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.10586',
  },

  cookieJar: request.jar(),

  login: function(email, password) {
    var self = this;

    return self.getAuthURL().then(function(authURL) {
      return self.postLogin(authURL, email, password);
    }).then(function(location) {
      return self.getLogin(location);
    });
  },

  getAuthURL: function() {
    var options = {
      uri: 'https://www.netflix.com/Login',
      headers: this.headers,
      jar: this.cookieJar,
    };

    return request(options).then(function (body) {
      var authURL = body.match(/name="authURL" value="(.+?)"/)[1];
      debug('authURL: ' + authURL);

      return authURL;
    }) .catch(function (err) {
      throw new Error('netflix-login: Couldn\'t retrieve authURL' + err);
    });
  },

  postLogin: function(authURL, email, password) {
    var options = {
      method: 'POST',
      uri: 'https://www.netflix.com/Login',
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
        nextPage: '',
      },
      headers: this.headers,
      jar: this.cookieJar,
    };

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

  getLogin: function(location) {
    var self = this;

    var options = {
      uri: 'https://www.netflix.com/Login',
      headers: this.headers,
      jar: this.cookieJar,
    };

    return request(options).then(function (body) {
      var cookies = self.cookieJar.getCookies(options.uri);
      var authData = {};

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
      throw new Error('netflix-login: getLogin failed ' + err);
    });
  },
};
