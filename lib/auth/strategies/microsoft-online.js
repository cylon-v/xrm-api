import {xpath} from 'xpath';
import {addSecureOptions, request} from '../helpers';
import {DOMParser} from 'xmldom';
import {BaseStrategy} from "./base-strategy";

const domParser = new DOMParser();

const microsoftOnlineSaml = `
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>
        <a:ReplyTo>
            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
        <a:To s:mustUnderstand="1">{toMustUnderstand}</a:To>
        <o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <o:UsernameToken>
                <o:Username>{username}</o:Username>
                <o:Password>{password}</o:Password>
            </o:UsernameToken>
        </o:Security>
    </s:Header>
    <s:Body>
        <t:RequestSecurityToken xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust">
            <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
            <a:EndpointReference>
                <a:Address>{endpoint}</a:Address>
            </a:EndpointReference>
            </wsp:AppliesTo>
            <t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType>
            <t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType>
            <t:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</t:TokenType>
        </t:RequestSecurityToken>
    </s:Body>
</s:Envelope>`;

export class MicrosoftOnline extends BaseStrategy {
  auth(opts, cb){
    const loginEndpoint = "urn:crmapac:dynamics.com";
    const {username, password} = opts;
    const host = "login.microsoftonline.com";
    const path = "/extSTS.srf";

    //build full name condition for XPath expression
    const name = (name) => "/*[name(.)='" + name + "']";

    const samlRequest = microsoftOnlineSaml
        .replace("{username}", username)
        .replace("{password}", password)
        .replace("{toMustUnderstand}", "https://" + host + path)
        .replace("{endpoint}", loginEndpoint),

      options = {
        method: "POST",
        uri: "https://" + host + path,
        body: samlRequest,
        headers: { "Content-Length": Buffer.byteLength(samlRequest) }
      };

    this.addSecureOptions(options);

    this.request(options, (err, res, body) => {
      if (err) return cb(err);

      const resXml = domParser.parseFromString(body);

      // search for a fault
      const exp = [
        'S:Envelope', 'S:Body', 'S:Fault', 'S:Detail',
        'psf:error', 'psf:internalerror', 'psf:text'
      ].map(name).join('') + '/text()';

      const fault = xpath.select(exp, resXml);

      if (fault.length > 0) return cb(new Error(fault.toString()));

      return cb(null, resXml);
    });
  }
}