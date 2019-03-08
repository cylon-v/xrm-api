import {xpath} from 'xpath';
import {addSecureOptions, request} from '../helpers';
import {DOMParser} from 'xmldom';
import {BaseStrategy} from "./base-strategy";
import httpntlm from "httpntlm";
import cookie from "cookie";
import uuid from "uuid";

const domParser = new DOMParser();


export class NTLM extends BaseStrategy {
  auth(opts, cb){
    var authOptions = {
      url: (settings.useHttp ? "http://" : "https://") + settings.hostName + ":" + settings.port,
      username: options.username || settings.username,
      password: options.password || settings.password,
      workstation: options.workstation || settings.workstation || "",
      domain: options.ntlmDomain || settings.ntlmDomain || "",

      headers: {
        "User-Agent": settings.userAgent
      }
    };

    httpntlm.get(authOptions, function (err, res) {
      if (err) {
        return cb(err);
      }

      if (res.cookies.length === 0) {
        return cb(new Error("Invalid Username or Password"));
      }

      var cookies = cookie.parse(res.headers["set-cookie"].join(";")),
        authToken = uuid.v4(),
        session = {
          username: options.username,
          password: options.password,
          ReqClientId: cookies.ReqClientId
        };

      settings.cacheTokenByAuth.set(authToken, session);
      settings.cacheAuthByUser.set(options.username, authToken);
      return cb(null, {auth: authToken, username: options.username});
    });
  }
}