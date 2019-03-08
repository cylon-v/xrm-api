/*jslint nomen: true, stupid: true */

// module dependencies
var xpath           = require("xpath");
var Cache           = require("mem-cache");
var domParser       = new (require("xmldom").DOMParser)();
var parseString     = require("xml2js").parseString;
var WSTrustFlow     = require("./auth/strategies/ws-security/wsTrustFlow.js");
var constants       = require("constants");
var Agentkeepalive  = require("agentkeepalive");
var request         = require("request");
var ntlm            = require("httpntlm/ntlm.js");

// this class implements all features
var Util = function (settings) {
    "use strict";

    // Arguments validation
    if (!settings || typeof settings !== "object") {
        throw new Error("'settings' argument must be an object instance.");
    }
    
    if (!settings.hostName) {
        // If no direct hostname was supplied, check information about domain, and, probably, domainUrlSuffix
        if (!settings.domain || typeof settings.domain !== "string"){
            throw new Error("'settings.domain' property is a required string.");
        }
        if (settings.domainUrlSuffix && typeof settings.domainUrlSuffix !== "string"){
            throw new Error("'settings.domainUrlSuffix' must be string.");
        }
    }
    
	// Set default value if organization name is missing
	if (!settings.organizationName) {
		settings.organizationName = "";
	}
    
    if (settings.timeout && typeof settings.timeout !== "number") {
        throw new Error("'settings.timeout' property must be a number.");
    }

    if (settings.username && typeof settings.username !== "string") {
        throw new Error("'settings.username' property must be a string.");
    }

    if (settings.password && typeof settings.password !== "string") {
        throw new Error("'settings.password' property must be a string.");
    }

    if (settings.port && typeof settings.port !== "number") { 
        throw new Error("'settings.port' property must be a number.");
    }

    if (settings.organizationName && typeof settings.organizationName !== "string") {
        throw new Error("'settings.organizationName' property must be a string.");
    }

    var authenticationTypes = ["live_id", "microsoft_online", "federation", "ntlm"];

    // Set default value if authentication type is wrong or invalid
    if (!settings.authType || typeof settings.authType !== "string" || authenticationTypes.indexOf(settings.authType) === -1) { 
        settings.authType = "live_id";
    }
	
    // Sets default arguments values
    settings.timeout = settings.timeout || 15 * 60 * 1000;  // default sessions timeout of 15 minutes in ms
    settings.returnJson = true;
    settings.port = settings.port || (settings.useHttp ? 80 : 443);

    settings.hostName = settings.hostName || (function() {
        if (settings.domainUrlSuffix) {
            return settings.domain + settings.domainUrlSuffix;
        }
        // Default Url Suffix will point to CRM online instance
        return settings.domain + ".api.crm.dynamics.com";
    })();
    settings.userAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.111 Safari/537.36";

    settings.cacheTokenByAuth = new Cache(settings.timeout);
    settings.cacheAuthByUser = new Cache(settings.timeout);
    settings.tokensForDeviceCache = new Cache(settings.timeout);

    var defaultUrlSuffix = ".api.crm.dynamics.com",

        organizationPath                = "/XRMServices/2011/Organization.svc",
        organizationServiceEndpoint     = "https://" + settings.hostName + organizationPath,
        SOAPActionBase                  = "http://schemas.microsoft.com/xrm/2011/Contracts/Services/IOrganizationService/",
        renameKey,

      executeSoapPost,
        deepObjCopy,
        defaultCb,
        authenticateUsingMicrosoftOnline,
        authenticateUsingLiveId,
        authenticateUsingFederation,
        authenticateUsingNTLM,
        addSecureOptions,
        parseResponse,
        authenticate,
        executePost,

        //load templates once

        authRequestDeviceTokenMessage = `
<?xml version="1.0" encoding="utf-8" ?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>
        <a:MessageID>urn:uuid:{messageuuid}</a:MessageID>
        <a:ReplyTo>
            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
        <a:To s:mustUnderstand="1">{issuer}</a:To>
        <o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <u:Timestamp u:Id="_0">
                <u:Created>{timeCreated}</u:Created>
                <u:Expires>{timeExpires}</u:Expires>
            </u:Timestamp>
            <o:UsernameToken u:Id="devicesoftware">
                <o:Username>{deviceUsername}</o:Username>
                <o:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">{devicePassword}</o:Password>
            </o:UsernameToken>
        </o:Security>
    </s:Header>
    <s:Body>
        <t:RequestSecurityToken xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust">
            <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
                <a:EndpointReference>
                    <a:Address>{liveIdAppliesTo}</a:Address>
                </a:EndpointReference>
            </wsp:AppliesTo>
            <t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType>
        </t:RequestSecurityToken>
    </s:Body>
</s:Envelope>`,

        authRequestSTSTokenMessage = `
<?xml version="1.0" encoding="utf-8" ?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <s:Header>
    <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>
    <a:MessageID>urn:uuid:{messageuuid}</a:MessageID>
    <a:ReplyTo>
      <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
    </a:ReplyTo>
    <a:To s:mustUnderstand="1">{issuer}</a:To>
    <o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <u:Timestamp u:Id="_0">
        <u:Created>{created}</u:Created>
        <u:Expires>{expires}</u:Expires>
      </u:Timestamp>
      <o:UsernameToken u:Id="user">
        <o:Username>{username}</o:Username>
        <o:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">{password}</o:Password>
      </o:UsernameToken>
      <wsse:BinarySecurityToken ValueType="urn:liveid:device" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
        <EncryptedData Id="BinaryDAToken0" Type="http://www.w3.org/2001/04/xmlenc#Element" xmlns="http://www.w3.org/2001/04/xmlenc#">
          <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#tripledes-cbc"></EncryptionMethod>
          <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:KeyName>http://Passport.NET/STS</ds:KeyName>
          </ds:KeyInfo>
          <CipherData>
            <CipherValue>{cipher}</CipherValue>
          </CipherData>
        </EncryptedData>
      </wsse:BinarySecurityToken>
    </o:Security>
  </s:Header>
  <s:Body>
    <t:RequestSecurityToken xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust">
      <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
        <a:EndpointReference>
          <a:Address>urn:crmna:dynamics.com</a:Address>
        </a:EndpointReference>
      </wsp:AppliesTo>
      <wsp:PolicyReference URI="MBI_FED_SSL" xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"/>
      <t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType>
    </t:RequestSecurityToken>
  </s:Body>
</s:Envelope>`,

        faultTextXpath                  = "//*[local-name()='Fault']/*[local-name()='Reason']/*[local-name()='Text']/text()",
        importLocationXpath             = "//*[local-name()='import' and namespace-uri()='http://schemas.xmlsoap.org/wsdl/']/@location",
        authenticationTypeXpath         = "//*[local-name()='Authentication' and namespace-uri()='http://schemas.microsoft.com/xrm/2011/Contracts/Services']/text()",
        issuerAddressXpath              = "//*[local-name()='SignedSupportingTokens']/*[local-name()='Policy']/*[local-name()='IssuedToken']/*[local-name()='Issuer']/*[local-name()='Address']/text()",
        liveAppliesToXpath              = "//*[local-name()='LiveIdAppliesTo']/text()";


};

module.exports = Util;