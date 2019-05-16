class Signer {
  consumer: { [key: string]: any };
  signature_method: string;
  nonce_length: number;
  version: string;
  parameter_seperator: string;
  last_ampersand: boolean;

  constructor(opts: { [key: string]: any }) {
    if (!opts.consumer) {
      throw new Error('consumer option is required');
    }
    this.consumer = opts.consumer;
    this.signature_method = 'HMAC-SHA1';
    this.nonce_length = 32;
    this.version = '1.0a';
    this.parameter_seperator = ',';

    this.last_ampersand =
      typeof opts.last_ampersand === 'undefined' ? true : opts.last_ampersand;
  }

  hash(base_string: string, key: string) {
    const sig = Utilities.computeHmacSignature(
      Utilities.MacAlgorithm.HMAC_SHA_1,
      base_string,
      key,
    );
    return Utilities.base64Encode(sig);
  }

  /**
   * OAuth request authorize
   */
  authorize(request: RequestData, token: Token, opt_oauth_data) {
    let oauth_data: { [key: string]: any } = {
      oauth_consumer_key: this.consumer.public,
      oauth_nonce: this.getNonce(),
      oauth_signature_method: this.signature_method,
      oauth_timestamp: this.getTimeStamp(),
      oauth_version: this.version,
    };

    if (opt_oauth_data) {
      oauth_data = this.mergeObject(oauth_data, opt_oauth_data);
    }

    if (!token) {
      token = {};
    }

    if (token.public) {
      oauth_data.oauth_token = token.public;
    }

    if (!request.data) {
      request.data = {};
    }

    try {
      oauth_data.oauth_signature = this.getSignature(
        request,
        token.secret,
        oauth_data,
      );
    } catch (err) {
      console.log('signer.class-authorize', err);
      throw Error(err);
    }

    return oauth_data;
  }

  /**
   * Create a OAuth Signature
   * @param  request data
   * @param  token_secret public and secret token
   * @param  oauth_data   OAuth data
   */
  getSignature(request, token_secret, oauth_data): string {
    const baseString = this.getBaseString(request, oauth_data);
    const signingKey = this.getSigningKey(token_secret);
    console.log(JSON.stringify({ baseString, signingKey }));
    return this.hash(baseString, signingKey);
  }

  /**
   * Base String = Method + Base Url + ParameterString
   * @param  request data
   * @param  OAuth data
   */
  getBaseString(request, oauth_data) {
    return (
      request.method.toUpperCase() +
      '&' +
      this.percentEncode(this.getBaseUrl(request.url)) +
      '&' +
      this.percentEncode(this.getParameterString(request, oauth_data))
    );
  }

  /**
   * Get data from url
   * -> merge with oauth data
   * -> percent encode key & value
   * -> sort
   *
   * @param  request data
   * @param  OAuth data
   * @return Parameter string data
   */
  getParameterString(request, oauth_data) {
    const base_string_data = this.sortObject(
      this.percentEncodeData(
        this.mergeObject(
          oauth_data,
          this.mergeObject(request.data, this.deParamUrl(request.url)),
        ),
      ),
    );

    let data_str = '';

    //base_string_data to string
    for (let key in base_string_data) {
      data_str += key + '=' + base_string_data[key] + '&';
    }

    //remove the last character
    data_str = data_str.substr(0, data_str.length - 1);
    return data_str;
  }

  /**
   * Create a Signing Key
   * @param  token_secret Secret Token
   * @return Signing Key
   */
  getSigningKey(token_secret = '') {
    // Don't percent encode the signing key (PKCS#8 PEM private key) when using
    // the RSA-SHA1 method. The token secret is never used with the RSA-SHA1
    // method.
    if (this.signature_method === 'RSA-SHA1') {
      return this.consumer.secret;
    }

    if (!this.last_ampersand && !token_secret) {
      return this.percentEncode(this.consumer.secret);
    }

    return (
      this.percentEncode(this.consumer.secret) +
      '&' +
      this.percentEncode(token_secret)
    );
  }

  /**
   * Get base url
   */
  getBaseUrl(url: string) {
    return url.split('?')[0];
  }

  /**
   * Get data from String
   */
  deParam(string: string) {
    const arr = string.replace(/\+/g, ' ').split('&');
    let data = {};

    for (let i = 0; i < arr.length; i++) {
      const item = arr[i].split('=');
      data[item[0]] = decodeURIComponent(item[1]);
    }
    return data;
  }

  /**
   * Get data from url
   */
  deParamUrl(url: string) {
    const tmp = url.split('?');

    if (tmp.length === 1) return {};

    return this.deParam(tmp[1]);
  }

  /**
   * Percent Encode
   */
  percentEncode(str: string): string {
    return encodeURIComponent(str)
      .replace(/\!/g, '%21')
      .replace(/\*/g, '%2A')
      .replace(/\'/g, '%27')
      .replace(/\(/g, '%28')
      .replace(/\)/g, '%29');
  }

  /**
   * Percent Encode Object
   */
  percentEncodeData(data: { [key: string]: any }) {
    const result = {};

    for (let key in data) {
      result[this.percentEncode(key)] = this.percentEncode(data[key]);
    }

    return result;
  }

  /**
   * Get OAuth data as Header
   */
  toHeader(oauth_data) {
    oauth_data = this.sortObject(oauth_data);

    let header_value = 'OAuth ';

    for (var key in oauth_data) {
      if (key !== 'realm' && key.indexOf('oauth_') === -1) continue;
      header_value +=
        this.percentEncode(key) +
        '="' +
        this.percentEncode(oauth_data[key]) +
        '"' +
        this.parameter_seperator;
    }

    return {
      Authorization: header_value.substr(
        0,
        header_value.length - this.parameter_seperator.length,
      ), //cut the last chars
    };
  }

  /**
   * Create a random word characters string with input length
   */
  getNonce() {
    const word_characters =
      'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = '';

    for (var i = 0; i < this.nonce_length; i++) {
      result +=
        word_characters[
          parseInt((Math.random() * this.nonce_length).toString(), 10)
        ];
    }

    return result;
  }

  /**
   * Get Current Unix TimeStamp
   * @return current unix timestamp
   */
  getTimeStamp() {
    return parseInt((new Date().getTime() / 1000).toString(), 10);
  }

  ////////////////////// HELPER FUNCTIONS //////////////////////

  /**
   * Merge object
   * @param  obj1
   * @param  obj2
   * @return
   */
  mergeObject(obj1, obj2) {
    var merged_obj = obj1;
    for (var key in obj2) {
      merged_obj[key] = obj2[key];
    }
    return merged_obj;
  }

  /**
   * Sort object by key
   * @param  data
   * @return sorted object
   */
  sortObject(data) {
    var keys = Object.keys(data);
    var result = {};

    keys.sort();

    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      result[key] = data[key];
    }

    return result;
  }
}
