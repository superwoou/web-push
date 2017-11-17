'use strict';

const urlBase64 = require('urlsafe-base64');
const url = require('url');
const http2 = require('http2');
const {
  HTTP2_HEADER_METHOD,
  HTTP2_HEADER_PATH,
  HTTP2_HEADER_STATUS,
  HTTP2_HEADER_CONTENT_TYPE,
} = http2.constants;

const WebPushError = require('./web-push-error.js');
const vapidHelper = require('./vapid-helper.js');
const encryptionHelper = require('./encryption-helper.js');

// Default TTL is four weeks.
const DEFAULT_TTL = 2419200;

let gcmAPIKey = '';
let vapidDetails;

const clientSessions = {};

function WebPushLib() {
}

/**
 * When sending messages to a GCM endpoint you need to set the GCM API key
 * by either calling setGMAPIKey() or passing in the API key as an option
 * to sendNotification().
 * @param  {string} apiKey The API key to send with the GCM request.
 */
WebPushLib.prototype.setGCMAPIKey = function(apiKey) {
  if (apiKey === null) {
    gcmAPIKey = null;
    return;
  }

  if (typeof apiKey === 'undefined' || typeof apiKey !== 'string' ||
    apiKey.length === 0) {
    throw new Error('The GCM API Key should be a non-empty string or null.');
  }

  gcmAPIKey = apiKey;
};

/**
 * When making requests where you want to define VAPID details, call this
 * method before sendNotification() or pass in the details and options to
 * sendNotification.
 * @param  {string} subject    This must be either a URL or a 'mailto:'
 * address. For example: 'https://my-site.com/contact' or
 * 'mailto: contact@my-site.com'
 * @param  {Buffer} publicKey  The public VAPID key.
 * @param  {Buffer} privateKey The private VAPID key.
 */
WebPushLib.prototype.setVapidDetails =
  function(subject, publicKey, privateKey) {
    if (arguments.length === 1 && arguments[0] === null) {
      vapidDetails = null;
      return;
    }

    vapidHelper.validateSubject(subject);
    vapidHelper.validatePublicKey(publicKey);
    vapidHelper.validatePrivateKey(privateKey);

    vapidDetails = {
      subject: subject,
      publicKey: publicKey,
      privateKey: privateKey
    };
  };

  /**
   * To get the details of a request to trigger a push message, without sending
   * a push notification call this method.
   *
   * This method will throw an error if there is an issue with the input.
   * @param  {PushSubscription} subscription The PushSubscription you wish to
   * send the notification to.
   * @param  {string} [payload]              The payload you wish to send to the
   * the user.
   * @param  {Object} [options]              Options for the GCM API key and
   * vapid keys can be passed in if they are unique for each notification you
   * wish to send.
   * @return {Object}                       This method returns an Object which
   * contains 'endpoint', 'method', 'headers' and 'payload'.
   */
WebPushLib.prototype.generateRequestDetails =
  function(subscription, payload, options) {
    if (!subscription || !subscription.endpoint) {
      throw new Error('You must pass in a subscription with at least ' +
        'an endpoint.');
    }

    if (typeof subscription.endpoint !== 'string' ||
      subscription.endpoint.length === 0) {
      throw new Error('The subscription endpoint must be a string with ' +
        'a valid URL.');
    }

    if (payload) {
      // Validate the subscription keys
      if (!subscription.keys || !subscription.keys.p256dh ||
        !subscription.keys.auth) {
        throw new Error('To send a message with a payload, the ' +
          'subscription must have \'auth\' and \'p256dh\' keys.');
      }
    }

    let currentGCMAPIKey = gcmAPIKey;
    let currentVapidDetails = vapidDetails;
    let timeToLive = DEFAULT_TTL;
    let extraHeaders = {};

    if (options) {
      const validOptionKeys = [
        'headers',
        'gcmAPIKey',
        'vapidDetails',
        'TTL'
      ];
      const optionKeys = Object.keys(options);
      for (let i = 0; i < optionKeys.length; i += 1) {
        const optionKey = optionKeys[i];
        if (validOptionKeys.indexOf(optionKey) === -1) {
          throw new Error('\'' + optionKey + '\' is an invalid option. ' +
            'The valid options are [\'' + validOptionKeys.join('\', \'') +
            '\'].');
        }
      }

      if (options.headers) {
        extraHeaders = options.headers;
        let duplicates = Object.keys(extraHeaders)
            .filter(function (header) {
              return typeof options[header] !== 'undefined';
            });

        if (duplicates.length > 0) {
          throw new Error('Duplicated headers defined [' +
            duplicates.join(',') + ']. Please either define the header in the' +
            'top level options OR in the \'headers\' key.');
        }
      }

      if (options.gcmAPIKey) {
        currentGCMAPIKey = options.gcmAPIKey;
      }

      if (options.vapidDetails) {
        currentVapidDetails = options.vapidDetails;
      }

      if (options.TTL) {
        timeToLive = options.TTL;
      }
    }

    if (typeof timeToLive === 'undefined') {
      timeToLive = DEFAULT_TTL;
    }

    const requestDetails = {
      method: 'POST',
      headers: {
        TTL: timeToLive
      }
    };
    Object.keys(extraHeaders).forEach(function (header) {
      requestDetails.headers[header] = extraHeaders[header];
    });
    let requestPayload = null;

    if (payload) {
      if (!subscription.keys ||
        typeof subscription !== 'object' ||
        !subscription.keys.p256dh ||
        !subscription.keys.auth) {
        throw new Error(new Error('Unable to send a message with ' +
          'payload to this subscription since it doesn\'t have the ' +
          'required encryption keys'));
      }

      const encrypted = encryptionHelper.encrypt(
        subscription.keys.p256dh, subscription.keys.auth, payload);

      requestDetails.headers['Content-Length'] = encrypted.cipherText.length;
      requestDetails.headers['Content-Type'] = 'application/octet-stream';
      requestDetails.headers['Content-Encoding'] = 'aesgcm';
      requestDetails.headers.Encryption = 'salt=' + encrypted.salt;
      requestDetails.headers['Crypto-Key'] = 'dh=' + urlBase64.encode(encrypted.localPublicKey);

      requestPayload = encrypted.cipherText;
    } else {
      requestDetails.headers['Content-Length'] = 0;
    }

    const isGCM = subscription.endpoint.indexOf(
      'https://android.googleapis.com/gcm/send') === 0;
    // VAPID isn't supported by GCM hence the if, else if.
    if (isGCM) {
      if (!currentGCMAPIKey) {
        console.warn('Attempt to send push notification to GCM endpoint, ' +
          'but no GCM key is defined. Please use setGCMApiKey() or add ' +
          '\'gcmAPIKey\' as an option.');
      } else {
        requestDetails.headers.Authorization = 'key=' + currentGCMAPIKey;
      }
    } else if (currentVapidDetails) {
      const parsedUrl = url.parse(subscription.endpoint);
      const audience = parsedUrl.protocol + '//' +
        parsedUrl.host;

      const vapidHeaders = vapidHelper.getVapidHeaders(
        audience,
        currentVapidDetails.subject,
        currentVapidDetails.publicKey,
        currentVapidDetails.privateKey
      );

      requestDetails.headers.Authorization = vapidHeaders.Authorization;
      if (requestDetails.headers['Crypto-Key']) {
        requestDetails.headers['Crypto-Key'] += ';' +
          vapidHeaders['Crypto-Key'];
      } else {
        requestDetails.headers['Crypto-Key'] = vapidHeaders['Crypto-Key'];
      }
    }

    requestDetails.body = requestPayload;
    requestDetails.endpoint = subscription.endpoint;

    return requestDetails;
  };

/**
 * To send a push notification call this method with a subscription, optional
 * payload and any options.
 * @param  {PushSubscription} subscription The PushSubscription you wish to
 * send the notification to.
 * @param  {string} [payload]              The payload you wish to send to the
 * the user.
 * @param  {Object} [options]              Options for the GCM API key and
 * vapid keys can be passed in if they are unique for each notification you
 * wish to send.
 * @return {Promise}                       This method returns a Promise which
 * resolves if the sending of the notification was successful, otherwise it
 * rejects.
 */
WebPushLib.prototype.sendNotification =
  function(subscription, payload, options) {
    const me = this;

    let requestDetails;
    try {
      requestDetails = this.generateRequestDetails(
        subscription, payload, options);
    } catch (err) {
      return Promise.reject(err);
    }

    return new Promise((resolve, reject) => {
      const httpsOptions = {};
      const urlParts = url.parse(requestDetails.endpoint);
      const host = urlParts.protocol + "//" + urlParts.host;

      if(!clientSessions[host]) {
        clientSessions[host] = http2.connect(host);
      }

      const headers = {
        ':method': requestDetails.method,
        ':path': urlParts.path
      };

      for(let i in requestDetails.headers)
        headers[i.toLowerCase()] = requestDetails.headers[i];

      const pushRequest = clientSessions[host].request(headers);
      pushRequest.on('response', (resp_headers) => {
        let responseText = '';
        pushRequest.on('data', (chunk) => {
          responseText += chunk;
        });
        pushRequest.on('end', () => {
          if(resp_headers[HTTP2_HEADER_STATUS] !== 201) {
            reject(new WebPushError('Received unexpected response code',
              resp_headers[HTTP2_HEADER_STATUS], resp_headers, responseText, requestDetails.endpoint));
          } else {
            resolve({
              statusCode: resp_headers[HTTP2_HEADER_STATUS],
              body: responseText,
              headers: resp_headers
            })
          }
          resolve();
        });
      });
      pushRequest.on('error', (err) => {
        reject(err);
      })
      if (requestDetails.body) {
        pushRequest.write(requestDetails.body);
      }
      pushRequest.end();
    });
  };

WebPushLib.prototype.closeHttp2Connection =
  function() {
    for(let i in clientSessions)
      clientSessions[i].destroy();
  }

module.exports = WebPushLib;
