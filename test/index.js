"use strict";

var expect = require('chai').expect;
var nock = require('nock');

var netflixLogin = require('../index');

var Purdy = require('purdy');

// Setup nock
nock.disableNetConnect();
// nock.enableNetConnect();
// nock.recorder.rec();

var username = 'johnf@inodes.org';
var password = 'secret';
var authURL = 'authURL=1468047668683.authURL';
var netflixId = 'netflixCookie';
var secureNetflixId = 'secureNetflixCookie';
var esn = 'ESN';

var nockOptions = {
  allowUnmocked: false
};

// getAuthURL
nock('https://www.netflix.com', nockOptions)
  .get('/Login')
  .reply(302, '', { location: 'https://www.netflix.com/gb/Login' });

nock('https://www.netflix.com', nockOptions)
  .get('/gb/Login')
  .reply(200, 'name="authURL" value="' + authURL + '"');

// postLogin
var body = 'authURL=' + encodeURIComponent(authURL) +
  '&email=' + encodeURIComponent(username) +
  '&password=' + password +
  '&rememberMeCheckbox=true' +
  '&flow=websiteSignUp' +
  '&mode=login' +
  '&action=loginAction' +
  '&withFields=email%2Cpassword%2CrememberMe%2CnextPage' +
  '&nextPage=';
nock('https://www.netflix.com')
  .post('/Login', body)
  .reply(302, '', {
    location: 'https://www.netflix.com/gb/',
    'set-cookie': [
      'NetflixId=' + netflixId + '; Domain=.netflix.com; Path=/; Expires=Sun, 09 Jul 2017 12:44:54 GMT; HttpOnly',
      'SecureNetflixId=' + secureNetflixId + '; Domain=.netflix.com; Path=/; Expires=Fri, 01 Jan 2038 00:00:00 GMT; HttpOnly; Secure',
    ],
  });

// getLogin
nock('https://www.netflix.com', nockOptions)
  .get('/Login')
  .reply(302, '', { location: 'https://www.netflix.com/gb/Login' });

nock('https://www.netflix.com', nockOptions)
  .get('/gb/Login')
  .reply(302, '', { location: 'https://www.netflix.com/browse', });

nock('https://www.netflix.com', nockOptions)
  .get('/browse')
  .reply(200, '"esn":"' + esn + '"');

describe('Netflix Login', function() {

  beforeEach(function resetNetflix() {
    netflixLogin._reset();
  });

  describe('#login()', function() {
    it('should login successfuly', function() {
      return netflixLogin.login('johnf@inodes.org', 'secret').then(function(data) {
        expect(data).to.be.an('object');
        expect(data).to.have.property('netflixId').equal(netflixId);
        expect(data).to.have.property('secureNetflixId').equal(secureNetflixId);
        expect(data).to.have.property('esn').equal(esn);
      });
    });
  });

  describe('#expired()', function() {
    it('should return true if no cookies', function() {
      var expired = netflixLogin.expired();
      expect(expired).to.equal(true);
    });
  });
});
