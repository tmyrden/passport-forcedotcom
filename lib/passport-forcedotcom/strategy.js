/**
 * Module dependencies.
 */
var querystring = require('querystring'),
  util = require('util'),
  OAuth2Strategy = require('passport-oauth').OAuth2Strategy,
  url = require('url');


function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://login.salesforce.com/services/oauth2/authorize';
  options.tokenURL = options.tokenURL || 'https://login.salesforce.com/services/oauth2/token';
  options.scopeSeparator = options.scopeSeparator || ',';

  OAuth2Strategy.call(this, options, verify);
  this.name = 'forcedotcom';

  var self = this; // so we can set `_results` on the strategy instance
  this._oauth2.getOAuthAccessToken = function(code, params, callback) {
    // This form preserves the params sent as arguments, so grant_type and
    // redirect_uri don't need to be re-specified.
    var params = params || {};
    params['client_id'] = this._clientId;
    params['client_secret'] = this._clientSecret;
    params['code'] = code;

    var post_data = querystring.stringify(params);
    var post_headers = {
      'Content-Length': post_data.length,
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/jsonrequest',
      'Cache-Control': 'no-cache,no-store,must-revalidate'
    };

    this._request("POST", this._getAccessTokenUrl(), post_headers, post_data, null, function(error, data, response) {
      if (error) {
        console.log(error);
        callback(error);
      } else {
        self._oauthData = JSON.parse(data);
        var parsedHost = url.parse(self._oauthData.id);
        var parsedInstance = url.parse(self._oauthData.instance_url);
        parsedHost.host = parsedInstance.host;
        parsedHost.hostname = parsedInstance.hostname;
        parsedHost.protocol = parsedInstance.protocol;
        self._oauthData.id = url.format(parsedHost);
        callback(null, self._oauthData["access_token"], self._oauthData["refresh_token"]);
      }
    });
  }

}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


Strategy.prototype.userProfile = function(token, done) {
  var self = this;
  //Set useAuthorizationHeaderforGET to true so that we can make userInfo call to get actual user info.
  this._oauth2.useAuthorizationHeaderforGET(true);
  console.log(this._oauthData.id);
  this._oauth2.get(self._oauthData.id, token, function(err, body, res) {
    if (err) {
      return done(err);
    }
    try {
      console.log('BODY:');
      console.log(body);
      var finalResult = JSON.parse(body);
      finalResult._oauthData = self._oauthData;
      done(null, finalResult);
    } catch (e) {
      done(e);
    }
  });
}



/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
