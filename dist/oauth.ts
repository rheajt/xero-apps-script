class OAuth {
  serviceName: string;
  paramLocation: string;
  oauthVersion: string;
  scriptId: string;
  signatureMethod: string;
  propertyStore: GoogleAppsScript.Properties.Properties;
  consumerKey: string;
  consumerSecret: string;
  callbackFunctionName: string;
  requestTokenUrl: string;
  accessTokenUrl: string;
  authorizationUrl: string;

  constructor(serviceName: string) {
    this.serviceName = serviceName;
    this.paramLocation = 'auth-header';
    this.oauthVersion = '1.0a';
    this.scriptId = eval('Script' + 'App').getScriptId();
    this.signatureMethod = 'HMAC-SHA1';
    this.propertyStore = PropertiesService.getUserProperties();
    this.requestTokenUrl = 'https://api.xero.com/oauth/RequestToken';
    this.accessTokenUrl = 'https://api.xero.com/oauth/AccessToken';
    this.authorizationUrl = 'https://api.xero.com/oauth/Authorize';
  }

  setConsumerKey(consumerKey: string): OAuth {
    this.consumerKey = consumerKey;
    return this;
  }

  setConsumerSecret(consumerSecret: string): OAuth {
    this.consumerSecret = consumerSecret;
    return this;
  }

  setCallbackFunction(name: string): OAuth {
    this.callbackFunctionName = name;
    return this;
  }

  /**
   * authorize the service
   */
  authorize() {
    const token = this.getRequestToken();

    this.saveToken(token);

    var oauthParams = {
      oauth_token: token.public,
    };
    return this.buildUrl_(this.authorizationUrl, oauthParams);
  }

  /**
   * get request token
   */
  getRequestToken() {
    const params = {
      method: 'get',
      muteHttpExceptions: true,
    };

    const oauthParams = {
      oauth_callback: this.getCallbackUrl(),
    };

    const response = this.fetchInternal_(
      this.requestTokenUrl,
      params,
      { secret: this.consumerSecret },
      oauthParams,
    );
    console.log(response);
    if (response.getResponseCode() >= 400) {
      throw 'Error starting OAuth flow: ' + response.getContentText();
    }

    let token: Token = this.parseToken_(response.getContentText());
    token.type = 'request';
    return token;
  }

  /**
   * parse tokens
   * @param content
   */
  parseToken_(content: string) {
    console.log(content);
    let token: Token = content
      .split('&')
      .reduce(function(result: { [key: string]: any }, pair: string) {
        let parts = pair.split('=');
        result[decodeURIComponent(parts[0])] = decodeURIComponent(parts[1]);
        return result;
      }, {});

    // Verify that the response contains a token.
    if (!token.oauth_token) {
      throw Error('parsing token: key "oauth_token" not found');
    }

    // Set fields that the signing library expects.
    token.public = token.oauth_token;
    token.secret = token.oauth_token_secret;

    return token;
  }

  /**
   * save token
   */
  saveToken(token: Token) {
    const key = this.getPropertyKey_();
    const value = JSON.stringify(token);
    this.propertyStore.setProperty(key, value);
  }

  /**
   * get the callback url for the request
   */
  getCallbackUrl() {
    const stateToken = ScriptApp.newStateToken()
      .withMethod(this.callbackFunctionName)
      .withArgument('serviceName', this.serviceName)
      .withTimeout(3600)
      .createToken();

    const url = `https://script.google.com/macros/d/${
      this.scriptId
    }/usercallback`;

    return this.buildUrl_(url, {
      state: stateToken,
    });
  }

  /**
   * build a url from a base and given params
   * @param url base
   * @param params parameters to append
   */
  buildUrl_(url: string, params: { [key: string]: any }) {
    const paramString = Object.keys(params)
      .map(key => {
        return `${encodeURIComponent(key)}=${encodeURIComponent(params[key])}`;
      })
      .join('&');

    return url + (url.indexOf('?') >= 0 ? '&' : '?') + paramString;
  }

  /**
   * Fetches a URL using the OAuth1 credentials of the service. Use this method
   * the same way you would use `UrlFetchApp.fetch()`.
   * @param url
   * @param params
   */
  fetch(
    url: string,
    params: { [key: string]: any },
  ): GoogleAppsScript.URL_Fetch.HTTPResponse {
    if (!this.hasAccess()) {
      throw 'Service not authorized.';
    }
    const token = this.getToken_();
    return this.fetchInternal_(url, params, token);
  }

  /**
   * Makes a `UrlFetchApp` request using the optional OAuth1 token and/or
   * additional parameters.
   */
  fetchInternal_(url: string, params, opt_token = null, opt_oauthParams?) {
    console.log({
      public: this.consumerKey,
      secret: this.consumerSecret,
    });
    const signer = new Signer({
      signature_method: this.signatureMethod,
      consumer: {
        public: this.consumerKey,
        secret: this.consumerSecret,
      },
    });

    const request: RequestData = {
      url,
      method: 'get',
    };

    let token = opt_token || null;
    let oauthParams = opt_oauthParams || null;

    if (
      params.payload &&
      (!params.contentType ||
        params.contentType == 'application/x-www-form-urlencoded')
    ) {
      let data = params.payload;

      if (typeof data == 'string') {
        data = signer.deParam(data);
      }
      request.data = data;
    }

    oauthParams = signer.authorize(request, token, oauthParams);
    const signerHeaders = signer.toHeader(oauthParams);
    params.headers = { ...params.headers, ...signerHeaders };
    console.log(JSON.stringify(params.headers));

    if (
      params.payload &&
      (!params.contentType ||
        params.contentType == 'application/x-www-form-urlencoded')
    ) {
      // Disable UrlFetchApp escaping and use the signer's escaping instead.
      // This will ensure that the escaping is consistent between the signature and the request.
      let payload = Object.keys(request.data)
        .map(function(key) {
          return (
            signer.percentEncode(key) + '=' + signer.percentEncode(payload[key])
          );
        })
        .join('&');

      params.payload = payload;
      console.log('payload', params.payload);
      params.escaping = false;
    }

    return UrlFetchApp.fetch(url, params);
  }

  getPropertyKey_() {
    return 'oauth1.0a.' + this.serviceName;
  }

  getToken_() {
    const key = this.getPropertyKey_();
    let token: string;
    if (!token) {
      token = this.propertyStore.getProperty(key);
    }

    if (token) {
      return JSON.parse(token);
    } else {
      return null;
    }
  }

  hasAccess() {
    const token = this.getToken_();
    return token && token.type == 'access';
  }
}
