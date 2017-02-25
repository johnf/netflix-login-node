import fs from 'fs';
import request from 'request-promise';
import tough from 'tough-cookie';

import Purdy from 'purdy';
import Debug from 'debug';

const debug = Debug('netflix-login');

const baseOptions = {
  uri: 'https://www.netflix.com/Login',
  headers: {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.10586',
  },
  jar: request.jar(),
};

const saveToCache = (authData, filename) => {
  debug('saving to cache');

  const data = {
    // FIXME why are we accessing something private?
    cookieJSON: authData.cookieJar._jar.toJSON(), // eslint-disable-line no-underscore-dangle
    esn: authData.esn,
  };
  const dataJSON = JSON.stringify(data);

  fs.writeFileSync(filename, dataJSON);
};

const loadFromCache = (filename) => {
  debug('loading from cache');

  const dataJSON = fs.readFileSync(filename);
  const data = JSON.parse(dataJSON);

  const cookieJar = new tough.CookieJar.fromJSON(data.cookieJSON); // eslint-disable-line new-cap
  const authData = {
    cookieJar: request.jar(cookieJar.store),
    esn: data.esn,
  };

  return authData;
};

const cookieJar = () => baseOptions.jar;

const cookies = () => cookieJar().getCookies(baseOptions.uri);

const cookiesMissing = () => {
  let result = 0;

  cookies().forEach((cookie) => {
    if (cookie.key === 'NetflixId' || cookie.key === 'SecureNetflixId') {
      result += 1;
    }
  });

  return result !== 2;
};

const getAuthURL = () => (
    request(baseOptions).then((body) => {
      const authURL = body.match(/name="authURL" value="(.+?)"/)[1];
      debug(`authURL: ${authURL}`);

      return authURL;
    })
    .catch((err) => {
      throw new Error(`netflix-login: Couldn't retrieve authURL ${err}`);
    })
);

const postLogin = (authURL, email, password) => {
  const options = {
    ...baseOptions,
    method: 'POST',
    simple: false,
    resolveWithFullResponse: true,
    form: {
      authURL,
      email,
      password,
      rememberMeCheckbox: 'true',
      flow: 'websiteSignUp',
      mode: 'login',
      action: 'loginAction',
      withFields: 'email,password,rememberMe,nextPage',
      nextPage: '',
    },
  };

  return request(options)
    .then((response) => {
      if (response.statusCode !== 302) {
        throw new Error(`netflix-login: Login POST didn't redirect. Bad password? status code: ${response.statusCode}`);
      }

      const location = response.headers.location;
      debug(`redirected to ${location}`);

      return location;
    })
  .catch((err) => {
    throw new Error(`netflix-login: postLogin failed ${Purdy.stringify(err)}`);
  });
};

const getLogin = (/* location */) => (
  request(baseOptions)
    .then((body) => {
      const authData = {
        cookieJar: cookieJar(),
      };

      cookies().forEach((cookie) => {
        if (cookie.key === 'NetflixId') {
          authData.netflixId = cookie.value;
        }
        if (cookie.key === 'SecureNetflixId') {
          authData.secureNetflixId = cookie.value;
        }
      });

      authData.esn = body.match(/"esn":"([^"]+)"/)[1];

      debug(`authData: ${Purdy.stringify(authData)}`);

      return authData;
    })
    .catch((err) => {
      throw new Error(`netflix-login: getLogin failed ${err.stack}`);
    })
);

class NetflixLogin {
  static login(email, password, options = {}) {
    const authDataFilename = `${options.cachePath}/authData.json`;

    if (options.useCache && fs.existsSync(authDataFilename)) {
      return Promise.resolve(loadFromCache(authDataFilename));
    }

    return getAuthURL()
      .then(authURL => postLogin(authURL, email, password))
      .then(location => getLogin(location))
      .then((authData) => {
        if (options.useCache) {
          saveToCache(authData, authDataFilename);
        }

        return authData;
      });
  }

  static expired() {
    let result = false;

    if (cookiesMissing()) {
      return true;
    }

    cookies().forEach((cookie) => {
      if (cookie.key !== 'NetflixId' && cookie.key !== 'SecureNetflixId') {
        return;
      }

      if (cookie.TTL() === 0) {
        result = true;
      }
    });

    return result;
  }

  static privateReset() {
    baseOptions.jar = request.jar();
  }
}

export default NetflixLogin;
