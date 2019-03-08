import {MicrosoftOnline} from "./strategies/microsoft-online";
import {Federation} from "./strategies/federation";
import {NTLM} from "./strategies/ntlm";

const strategies = {
  'microsoft-online': MicrosoftOnline,
  'federation': Federation,
  'ntlm': NTLM
};

export function authenticate(settings, authCache, callback) {
  const authType = settings['authType'] || 'federation';
  const Strategy = strategies[authType];
  const strategy = new Strategy(settings, authCache);
  return strategy.auth(settings, callback);
}