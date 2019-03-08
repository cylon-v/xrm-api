import constants from 'constants';
import {Request, initParams} from 'request';
import {paramsHaveRequestBody} from 'request/lib/helpers';

export function addSecureOptions(reqOptions) {
  reqOptions.secureOptions = constants.SSL_OP_NO_TLSv1_2;
  reqOptions.ciphers = "ECDHE-RSA-AES256-SHA:AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM";
  reqOptions.honorCipherOrder = true;
  return reqOptions;
}

export function request(uri, options, callback) {
  if (typeof uri === 'undefined') {
    throw new Error('undefined is not a valid uri or options object.')
  }

  const params = initParams(uri, options, callback);

  if (params.method === 'HEAD' && paramsHaveRequestBody(params)) {
    throw new Error('HTTP HEAD requests MUST NOT include a request body.')
  }

  return new Request(params);
}
