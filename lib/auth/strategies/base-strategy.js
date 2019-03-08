import {paramsHaveRequestBody} from 'request/lib/helpers';
import {xpath} from 'xpath';
import {DOMParser} from 'xmldom';
import {Cache}           from 'mem-cache';
import {addSecureOptions, request} from "../../helpers";
import {organizationPath} from "../../constants";

const domParser = new DOMParser();
const faultTextXpath = "//*[local-name()='Fault']/*[local-name()='Reason']/*[local-name()='Text']/text()";
const importLocationXpath = "//*[local-name()='import' and namespace-uri()='http://schemas.xmlsoap.org/wsdl/']/@location";
const authenticationTypeXpath = "//*[local-name()='Authentication' and namespace-uri()='http://schemas.microsoft.com/xrm/2011/Contracts/Services']/text()";
const issuerAddressXpath = "//*[local-name()='SignedSupportingTokens']/*[local-name()='Policy']/*[local-name()='IssuedToken']/*[local-name()='Issuer']/*[local-name()='Address']/text()";
const liveAppliesToXpath = "//*[local-name()='LiveIdAppliesTo']/text()";

export class BaseStrategy {
  constructor(settings, cache) {
    this.settings = settings;
    this.endpoints = null;
    this.cache = cache;
  }

  fetchEndpoints(cb) {
    if (this.endpoints) {
      return cb(null, this.endpoints);
    }

    const schema = this.settings.useHttp ? 'http://' : 'https://';
    const options = {
      uri: `${schema}${this.settings.hostName}:${this.settings.port}${organizationPath}?wsdl`
    };

    addSecureOptions(options);

    request(options, (err, res, body) => {
      if (err) {
        return cb(err);
      }

      const resXml = domParser.parseFromString(body);
      const fault = xpath.select(faultTextXpath, resXml);

      if (fault.length > 0) {
        return cb(new Error(fault.toString()), null);
      }

      const location = xpath.select(importLocationXpath, resXml)
        .map(function (attr) {
          return attr.value;
        })[0];

      if (location.length > 0) {
        const opts = {url: location};

        addSecureOptions(opts);

        request(opts, function (err, res, body) {
          if (err) {
            return cb(err);
          }

          const resXmlImport = domParser.parseFromString(body);
          const faultImport = xpath.select(faultTextXpath, resXmlImport);

          if (faultImport.length > 0) {
            return cb(new Error(faultImport.toString()), null);
          }

          const authenticationType = xpath.select(authenticationTypeXpath, resXmlImport).toString();
          const issuerAddress = xpath.select(issuerAddressXpath, resXmlImport).toString();
          const liveAppliesTo = xpath.select(liveAppliesToXpath, resXmlImport).toString();
          const identifier = xpath.select("//*[local-name()='Identifier']/text()", resXmlImport).toString();
          const keyType = xpath.select("//*[local-name()='KeyType']/text()", resXmlImport).toString();
          const keySize = xpath.select("//*[local-name()='KeySize']/text()", resXmlImport).toString();
          const requireClientEntropy = (body.indexOf("RequireClientEntropy") > -1);

          this.endpoints = {
            AuthenticationType: authenticationType,
            IssuerAddress: issuerAddress,
            DeviceAddUrl: "https://login.live.com/ppsecure/DeviceAddCredential.srf",
            LiveIdAppliesTo: liveAppliesTo,
            Identifier: identifier,
            KeyType: keyType,
            KeySize: keySize,
            RequireClientEntropy: requireClientEntropy
          };
          return cb(null, this.endpoints);
        });
      }
    });
  };
}