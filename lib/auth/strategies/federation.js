import {xpath} from 'xpath';
import {BaseStrategy} from './base-strategy';
import WSTrustFlow from './ws-security/wsTrustFlow';
import uuid from "uuid";

const organizationPath = "/XRMServices/2011/Organization.svc";

export class Federation extends BaseStrategy {
  auth(options, cb) {
    this.fetchEndpoints((err, wsdlInfo) => {
      if (err) {
        return cb(err);
      }

      const organizationServiceEndpoint = "https://" + this.settings.hostName + organizationPath;
      const identifier = wsdlInfo.Identifier.replace("http://", "https://");
      const keyTypeUnsupported = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey";

      if (wsdlInfo.KeyType === keyTypeUnsupported) {
        wsdlInfo.KeyType = "http://schemas.xmlsoap.org/ws/2005/02/trust/SymmetricKey";
      }

      const wstrustFlowOptions = {
        wstrustEndpoint: identifier + "/2005/usernamemixed",
        username: options.username,
        password: options.password,
        appliesTo: organizationServiceEndpoint,
        useClientEntropy: wsdlInfo.RequireClientEntropy,
        keyType: wsdlInfo.KeyType,
        keySize: wsdlInfo.KeySize
      };

      const flow = new WSTrustFlow(wstrustFlowOptions);
      flow.getWSSecurityHeader((err, header) => {
        if (err) {
          return cb(err);
        }

        const authToken = uuid.v4();
        const authItem = {header: header};

        this.cache.token.set(authToken, authItem);
        this.cache.user.set(options.username, authToken);
        return cb(null, {auth: authToken});
      });
    });
  }
}