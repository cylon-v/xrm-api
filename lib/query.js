import {authenticate} from "./auth";
import traverse from 'traverse';
import {addSecureOptions, request} from './helpers';
import {organizationPath} from './constants';
import AgentKeepAlive  from 'agentkeepalive';


export class Query {
  constructor(settings) {
    this.settings = settings;
  }

  deepObjCopy(dupeObj, pfxs) {
    var retObj = {},
      objInd,
      rk;

    if (typeof dupeObj === "object") {
      if (dupeObj.length) {
        retObj = [];
      }

      for (objInd in dupeObj) {
        if (dupeObj.hasOwnProperty(objInd)) {
          rk = renameKey(objInd, pfxs);
          if (typeof dupeObj[objInd] === "object") {
            retObj[rk] = deepObjCopy(dupeObj[objInd], pfxs);
          } else if (typeof dupeObj[objInd] === "string") {
            retObj[rk] = dupeObj[objInd];
          } else if (typeof dupeObj[objInd] === "number") {
            retObj[rk] = dupeObj[objInd];
          } else if (typeof dupeObj[objInd] === "boolean") {
            if (dupeObj[rk]) {
              retObj[objInd] = true;
            } else {
              retObj[objInd] = false;
            }
          }
        }
      }
    }
    return retObj;
  }

  executeSoapPost(options, action, template, body, cb) {
    const timeCreated = new Date();
    const timeExpires = new Date(timeCreated.getTime() + 5 * 60000);

    const xmlrequestbody = template.replace("{requetbody}", body);

    const soapEnvelopeMessage = `
      <s:Envelope xmlns:s="{envelopeNS}" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
          {header}
          {body}
      </s:Envelope>
    `;

    if (this.settings.authType === "ntlm") {
      const soapPostMessage = soapEnvelopeMessage
        .replace("{envelopeNS}", "http://schemas.xmlsoap.org/soap/envelope/")
        .replace("{header}", "")
        .replace("{body}", xmlrequestbody);

      const url = (this.settings.useHttp ? "http://" : "https://") + this.settings.hostName + ":" + this.settings.port + "/" + this.settings.organizationName + organizationPath + "/web";

      httpHeaders.cookie = "ReqClientId=" + options.ReqClientId;
      httpHeaders.SOAPAction = SOAPActionBase + action;
      httpHeaders["Content-Length"] = Buffer.byteLength(soapPostMessage);
      httpHeaders["Content-Type"] = "text/xml; charset=utf-8";
      httpHeaders.Accept = "application/xml, text/xml, */*";
      httpHeaders["User-Agent"] = this.settings.userAgent;

      const ntlmOptions = {
        username: options.username || this.settings.username,
        password: options.password || this.settings.password,
        workstation: options.workstation || this.settings.workstation || "",
        domain: options.ntlmDomain || this.settings.ntlmDomain || ""
      };

      const type1msg = ntlm.createType1Message(ntlmOptions);
      const agent = this.settings.useHttp ? new AgentKeepAlive() : new AgentKeepAlive.HttpsAgent();

      let reqOptions = {
        method: options.method || "GET",
        url: url,
        headers: {
          Authorization: type1msg,
        },
        agent: agent,
        timeout: this.settings.requestTimeout
      };

      addSecureOptions(reqOptions);

      request(reqOptions, (err, res) => {
        if (err) {
          return cb(err);
        }
        if (!res.headers["www-authenticate"]) {
          return cb(new Error("www-authenticate not found on response of second request"));
        }

        const type2msg = ntlm.parseType2Message(res.headers["www-authenticate"]);
        const type3msg = ntlm.createType3Message(type2msg, ntlmOptions);

        httpHeaders.Authorization = type3msg;

        reqOptions = {
          method: "POST",
          url: url,
          body: soapPostMessage,
          agent: agent,
          timeout: this.settings.requestTimeout,
          headers: httpHeaders
        };

        addSecureOptions(reqOptions);

        request(reqOptions, (err, res, body) => {
          if (err) {
            return cb(err);
          }

          this.parseResponse(body, cb);
        });
      });

    } else {
      let soapHeader = `
                <s:Header>
                    <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/xrm/2011/Contracts/Services/IOrganizationService/` + action + `</a:Action>
                    <a:MessageID>urn:uuid:` + uuid.v4() + `</a:MessageID>
                    <a:ReplyTo>
                    <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
                    </a:ReplyTo>
                    <a:To s:mustUnderstand="1">` + organizationServiceEndpoint + `</a:To>
                    {security}
                </s:Header>`;

      if (options.encryptedData) {
        const security = `<wsse:Security s:mustUnderstand="1" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
                    <u:Timestamp u:Id="_0">\
                    <u:Created>` + timeCreated.toISOString() + `</u:Created>
                    <u:Expires>` + timeExpires.toISOString() + `</u:Expires>
                    </u:Timestamp>` + options.encryptedData + `</wsse:Security>`;

        soapHeader = soapHeader.replace("{security}", security);
      } else if (options.header) {
        soapHeader = soapHeader.replace("{security}", options.header);
      } else {
        return cb(new Error("Neither token or header found."));
      }

      const url = (this.settings.useHttp ? "http://" : "https://") + this.settings.hostName + ":" + this.settings.port + organizationPath;
      const soapPostMessage = soapEnvelopeMessage
        .replace("{envelopeNS}", "http://www.w3.org/2003/05/soap-envelope")
        .replace("{header}", soapHeader)
        .replace("{body}", xmlrequestbody);

      httpHeaders["Content-Type"] = "application/soap+xml; charset=UTF-8";
      httpHeaders["Content-Length"] = Buffer.byteLength(soapPostMessage);

      let requestOptions = {
        method: "POST",
        uri: url,
        body: soapPostMessage,
        headers: httpHeaders
      };

      addSecureOptions(requestOptions);

      request(requestOptions, (err, res, body) => {
        if (err) {
          return cb(err);
        }

        this.parseResponse(body, cb);
      });
    }
  };


  executePost(options, action, template, body, cb) {
    let authItem;
    // handles optional 'options' argument
    if (!cb && typeof options === "function") {
      cb = options;
      options = {};
    }

    // sets default values
    cb = cb || ((err) => {
      throw err
    });
    options = options || {};
    if (!options || typeof options !== "object") {
      return cb(new Error("'options' argument is missing or invalid."));
    }

    if (options.encryptedData || options.header) {
      this.executeSoapPost(options, action, template, body, cb);
    } else if (options.auth) {
      authItem = this.cacheTokenByAuth.get(options.auth);
      options.encryptedData = authItem.token; //For LiveId an MSOnline
      options.header = authItem.header; //For Federation
      options.ReqClientId = authItem.ReqClientId; //For NTLM

      this.executeSoapPost(options, action, template, body, cb);
    } else {
      authenticate(options, (err, data) => {
        if (err) {
          return cb(err);
        }

        authItem = this.settings.cacheTokenByAuth.get(data.auth);
        options.encryptedData = authItem.token; //For LiveId an MSOnline
        options.header = authItem.header; //For Federation

        this.executeSoapPost(options, action, template, body, cb);
      });
    }
  }

  executePostPromised(options, action, template, body) {
    return new Promise((fulfill, reject) => {
      this.executePost(options, action, template, body, (err, data) => {
        if (err) {
          reject(err);
        }
        fulfill(data);
      });
    });
  }

  renameKey = function (objInd, prefixes) {
    var rk = objInd;
    prefixes.forEach(function (p) {
      if (objInd.indexOf(p) === 0) {
        rk = objInd.replace(p, "");
      }
    });

    return rk;
  };

  parseResponse(body, cb) {
    let data = body;
    const resXml = domParser.parseFromString(body);
    const fault = xpath.select(faultTextXpath, resXml);

    if (fault.length > 0) {
      return cb(new Error(fault.toString()));
    }

    if (this.settings.returnJson)
      parseString(body, {explicitArray: false}, function (err, jsondata) {
        if (err) {
          return cb(err);
        }

        const prefixes = [];
        //removes namespaces
        const data_no_ns = traverse(jsondata).map(function () {
          if (this.key !== undefined) {
            var pos = this.key.indexOf("xmlns:"),
              k = this.key.substring(6, this.key.length) + ":";

            if (pos > -1 || this.key.indexOf("xmlns") > -1) {
              if (prefixes.lastIndexOf(k) === -1) {
                prefixes.push(k);
              }

              this.remove();
            }
          }
        });
        //removes 'xx:' prefixes
        data = this.deepObjCopy(data_no_ns, prefixes);
        cb(null, data);
      });

    else cb(null, data);
  };
}