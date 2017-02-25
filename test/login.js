import { expect } from 'chai';
import nock from 'nock';

import netflixLogin from '../src/login';

// Setup nock
nock.disableNetConnect();
// nock.enableNetConnect();
// nock.recorder.rec();

const username = 'johnf@inodes.org';
const password = 'secret';
const authURL = 'authURL=1468047668683.authURL';
const netflixId = 'netflixCookie';
const secureNetflixId = 'secureNetflixCookie';
const esn = 'ESN';

const nockOptions = {
  allowUnmocked: false,
};

// getAuthURL
nock('https://www.netflix.com', nockOptions)
  .get('/Login')
  .reply(302, '', { location: 'https://www.netflix.com/gb/Login' });

nock('https://www.netflix.com', nockOptions)
  .get('/gb/Login')
  .reply(200, `name="authURL" value="${authURL}"`);

// postLogin
const body = `authURL=${encodeURIComponent(authURL)}
&email=${encodeURIComponent(username)}
&password=${password}
&rememberMeCheckbox=true
&flow=websiteSignUp
&mode=login
&action=loginAction
&withFields=email%2Cpassword%2CrememberMe%2CnextPage
&nextPage=`;

nock('https://www.netflix.com')
  .post('/Login', body)
  .reply(302, '', {
    location: 'https://www.netflix.com/gb/',
    'set-cookie': [
      `NetflixId=${netflixId}; Domain=.netflix.com; Path=/; Expires=Sun, 09 Jul 2017 12:44:54 GMT; HttpOnly`,
      `SecureNetflixId=${secureNetflixId}; Domain=.netflix.com; Path=/; Expires=Fri, 01 Jan 2038 00:00:00 GMT; HttpOnly; Secure`,
    ],
  });

// getLogin
nock('https://www.netflix.com', nockOptions)
  .get('/Login')
  .reply(302, '', { location: 'https://www.netflix.com/gb/Login' });

nock('https://www.netflix.com', nockOptions)
  .get('/gb/Login')
  .reply(302, '', { location: 'https://www.netflix.com/browse' });

nock('https://www.netflix.com', nockOptions)
  .get('/browse')
  .reply(200, `"esn":"${esn}"`);

describe('Netflix Login', () => {
  beforeEach(() => {
    netflixLogin.privateReset();
  });

  describe('#login()', () => {
    it('should login successfuly', () => (
      netflixLogin.login('johnf@inodes.org', 'secret').then((data) => {
        expect(data).to.be.an('object');
        expect(data).to.have.property('netflixId').equal(netflixId);
        expect(data).to.have.property('secureNetflixId').equal(secureNetflixId);
        expect(data).to.have.property('esn').equal(esn);
      })
    ));
  });

  describe('#expired()', () => {
    it('should return true if no cookies', () => {
      const expired = netflixLogin.expired();
      expect(expired).to.equal(true);
    });
  });
});
