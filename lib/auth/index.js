import httpntlm from 'httpntlm';
import cookie from 'cookie';
import uuid from 'uuid';
import {MicrosoftOnline} from "./strategies/microsoft-online";
import {Federation} from "./strategies/federation";
import {NTLM} from "./strategies/ntlm";

var authenticateUsingFederation = function (authOptions, cb) {
  fetchEndpoints(function (err, wsdlInfo) {
    if (err) return cb(err);
    var wstrustFlowOptions,
      flow,
      identifier = wsdlInfo.Identifier.replace("http://", "https://"),
      keyTypeUnsupported = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey";

    if (wsdlInfo.KeyType === keyTypeUnsupported)
      wsdlInfo.KeyType = "http://schemas.xmlsoap.org/ws/2005/02/trust/SymmetricKey";

    wstrustFlowOptions = {
      wstrustEndpoint: identifier + "/2005/usernamemixed",
      username: authOptions.username,
      password: authOptions.password,
      appliesTo: organizationServiceEndpoint,
      useClientEntropy: wsdlInfo.RequireClientEntropy,
      keyType: wsdlInfo.KeyType,
      keySize: wsdlInfo.KeySize
    };

    flow = new WSTrustFlow(wstrustFlowOptions);
    flow.getWSSecurityHeader(function (err, header) {
      if (err) {
        return cb(err);
      }

      return cb(null, header);
    });
  });
};

export class Index {
  constructor(settings) {
  }

  do(options, cb) {
    var responseXMLCB = function (err, resXml) {
        if (err) {
          return cb(err);
        }

        var token = xpath.select("//*[local-name()='EncryptedData']", resXml).toString(),
          authToken = uuid.v4(),
          authItem = {token: token};

        cacheTokenByAuth.set(authToken, authItem);
        cacheAuthByUser.set(options.username, authToken);
        return cb(null, {auth: authToken});
      },

      federationCB = function (err, header) {
        if (err) {
          return cb(err);
        }

        var authToken = uuid.v4(),
          authItem = {header: header};

        cacheTokenByAuth.set(authToken, authItem);
        cacheAuthByUser.set(options.username, authToken);
        return cb(null, {auth: authToken});
      };

    // handles optional 'options' argument
    if (!cb && typeof options === "function") {
      cb = options;
      options = {};
    }

    // sets default values
    cb = cb || defaultCb;
    options = options || {};

    // validates arguments values
    if (typeof options !== "object") {
      return cb(new Error("'options' argument is missing or invalid."));
    }

    // Validates username and password
    options.username = options.username || settings.username;
    options.password = options.password || settings.password;

    if (settings.authType === "microsoft_online") {
      authenticateUsingMicrosoftOnline(options, responseXMLCB);
    } else if (settings.authType === "federation") {
      authenticateUsingFederation(options, federationCB);
    } else if (settings.authType === "ntlm") {
      authenticateUsingNTLM(options, cb);
    } else {
      // Default Live Id
      authenticateUsingLiveId(options, responseXMLCB);
    }
  }
}

const strategies = {
  'microsoft-online': MicrosoftOnline,
  'federation': Federation,
  'ntlm': NTLM
};

export function authenticate(settings, callback) {
  const authType = settings['authType'] || 'federation';
  const Strategy = strategies[authType];
  const strategy = new Strategy(settings);
  return strategy.auth(settings, callback);
}