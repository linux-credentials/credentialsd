/**
 * Content script running in MAIN world (page context).
 * Overrides navigator.credentials.create/get and communicates
 * with the ISOLATED world bridge script via window.postMessage.
 */

let requestCounter = 0;
const pendingRequests = {};

// Base64url helpers (Chromium doesn't have Uint8Array.toBase64/fromBase64)
function arrayBufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64urlToArrayBuffer(str) {
  if (!str) return null;
  const padded = str.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// Listen for responses from the bridge script
window.addEventListener('message', (event) => {
  if (event.source !== window) return;
  if (event.data?.type !== 'credentialsd-response') return;

  const { requestId, data, error } = event.data;
  const request = pendingRequests[requestId];
  if (!request) return;
  delete pendingRequests[requestId];

  if (error) {
    request.reject(new DOMException(error.message || 'WebAuthn operation failed', error.name || 'NotAllowedError'));
  } else {
    request.resolve(data);
  }
});

function startRequest() {
  const requestId = requestCounter++;
  let resolve, reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  pendingRequests[requestId] = { resolve, reject };
  return { requestId, promise };
}

function serializePublicKeyOptions(options) {
  const clone = JSON.parse(JSON.stringify(options, (key, value) => {
    if (value instanceof ArrayBuffer) {
      return { __b64url__: arrayBufferToBase64url(value) };
    }
    if (ArrayBuffer.isView(value)) {
      return { __b64url__: arrayBufferToBase64url(value.buffer) };
    }
    return value;
  }));
  return clone;
}

function reconstructCredentialResponse(credential) {
  const obj = {};
  obj.id = credential.id;
  obj.rawId = base64urlToArrayBuffer(credential.rawId);
  obj.authenticatorAttachment = credential.authenticatorAttachment;
  const response = {};

  // Registration response
  if (credential.response.attestationObject) {
    response.clientDataJSON = base64urlToArrayBuffer(credential.response.clientDataJSON);
    response.attestationObject = base64urlToArrayBuffer(credential.response.attestationObject);
    response.transports = credential.response.transports ? [...credential.response.transports] : [];
    const authenticatorData = base64urlToArrayBuffer(credential.response.authenticatorData);
    response.authenticatorData = authenticatorData;
    response.getAuthenticatorData = function() { return this.authenticatorData; };
    response.getPublicKeyAlgorithm = function() { return credential.response.publicKeyAlgorithm; };
    if (credential.response.publicKey) {
      response.publicKey = base64urlToArrayBuffer(credential.response.publicKey);
    }
    response.getPublicKey = function() { return this.publicKey || null; };
    response.getTransports = function() { return this.transports; };

    if (typeof AuthenticatorAttestationResponse !== 'undefined') {
      Object.setPrototypeOf(response, AuthenticatorAttestationResponse.prototype);
    }
  }
  // Assertion response
  else if (credential.response.signature) {
    response.clientDataJSON = base64urlToArrayBuffer(credential.response.clientDataJSON);
    response.authenticatorData = base64urlToArrayBuffer(credential.response.authenticatorData);
    response.signature = base64urlToArrayBuffer(credential.response.signature);
    response.userHandle = credential.response.userHandle
      ? base64urlToArrayBuffer(credential.response.userHandle)
      : null;

    if (typeof AuthenticatorAssertionResponse !== 'undefined') {
      Object.setPrototypeOf(response, AuthenticatorAssertionResponse.prototype);
    }
  } else {
    throw new Error('Unknown credential response type received');
  }

  // Client extension results
  const extensions = {};
  if (credential.clientExtensionResults) {
    if (credential.clientExtensionResults.hmacGetSecret) {
      extensions.hmacGetSecret = {};
      extensions.hmacGetSecret.output1 = base64urlToArrayBuffer(credential.clientExtensionResults.hmacGetSecret.output1);
      if (credential.clientExtensionResults.hmacGetSecret.output2) {
        extensions.hmacGetSecret.output2 = base64urlToArrayBuffer(credential.clientExtensionResults.hmacGetSecret.output2);
      }
    }
    if (credential.clientExtensionResults.prf) {
      extensions.prf = {};
      if (credential.clientExtensionResults.prf.results) {
        extensions.prf.results = {};
        extensions.prf.results.first = base64urlToArrayBuffer(credential.clientExtensionResults.prf.results.first);
        if (credential.clientExtensionResults.prf.results.second) {
          extensions.prf.results.second = base64urlToArrayBuffer(credential.clientExtensionResults.prf.results.second);
        }
      }
      if (credential.clientExtensionResults.prf.enabled !== undefined) {
        extensions.prf.enabled = credential.clientExtensionResults.prf.enabled;
      }
    }
    if (credential.clientExtensionResults.largeBlob) {
      extensions.largeBlob = {};
      if (credential.clientExtensionResults.largeBlob.blob) {
        extensions.largeBlob.blob = base64urlToArrayBuffer(credential.clientExtensionResults.largeBlob.blob);
      }
    }
    if (credential.clientExtensionResults.credProps) {
      extensions.credProps = credential.clientExtensionResults.credProps;
    }
  }

  obj.response = response;
  obj.clientExtensionResults = extensions;
  obj.getClientExtensionResults = function() { return this.clientExtensionResults; };
  obj.type = 'public-key';

  obj.toJSON = function() {
    const json = {};
    json.id = this.id;
    json.rawId = this.id;
    json.response = {};
    if (credential.response.attestationObject) {
      json.response.clientDataJSON = credential.response.clientDataJSON;
      json.response.authenticatorData = credential.response.authenticatorData;
      json.response.transports = this.response.transports;
      json.response.publicKey = credential.response.publicKey;
      json.response.publicKeyAlgorithm = credential.response.publicKeyAlgorithm;
      json.response.attestationObject = credential.response.attestationObject;
    } else if (credential.response.signature) {
      json.response.clientDataJSON = credential.response.clientDataJSON;
      json.response.authenticatorData = credential.response.authenticatorData;
      json.response.signature = credential.response.signature;
      json.response.userHandle = credential.response.userHandle;
    }
    json.authenticatorAttachment = this.authenticatorAttachment;
    json.clientExtensionResults = this.clientExtensionResults;
    json.type = this.type;
    return json;
  };

  if (typeof PublicKeyCredential !== 'undefined') {
    Object.setPrototypeOf(obj, PublicKeyCredential.prototype);
  }

  return obj;
}

// Override navigator.credentials
if (navigator.credentials) {
  const originalCreate = navigator.credentials.create?.bind(navigator.credentials);
  const originalGet = navigator.credentials.get?.bind(navigator.credentials);

  navigator.credentials.create = function(options) {
    if (!options || !options.publicKey) {
      if (originalCreate) return originalCreate(options);
      return Promise.reject(new DOMException('Not supported', 'NotSupportedError'));
    }

    console.log('[credentialsd] intercepting navigator.credentials.create');
    const { signal, ...rest } = options;
    const { requestId, promise } = startRequest();
    const serialized = serializePublicKeyOptions(rest);

    window.postMessage({
      type: 'credentialsd-request',
      requestId,
      cmd: 'create',
      options: serialized,
    }, '*');

    return promise.then(reconstructCredentialResponse);
  };

  navigator.credentials.get = function(options) {
    if (!options || !options.publicKey) {
      if (originalGet) return originalGet(options);
      return Promise.reject(new DOMException('Not supported', 'NotSupportedError'));
    }

    console.log('[credentialsd] intercepting navigator.credentials.get');
    const { signal, ...rest } = options;
    const { requestId, promise } = startRequest();
    const serialized = serializePublicKeyOptions(rest);

    window.postMessage({
      type: 'credentialsd-request',
      requestId,
      cmd: 'get',
      options: serialized,
    }, '*');

    return promise.then(reconstructCredentialResponse);
  };
}

if (typeof PublicKeyCredential !== 'undefined') {
  PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async function() {
    return true;
  };

  const origGetClientCapabilities = PublicKeyCredential.getClientCapabilities;
  PublicKeyCredential.getClientCapabilities = function() {
    console.log('[credentialsd] intercepting PublicKeyCredential.getClientCapabilities');
    const { requestId, promise } = startRequest();

    window.postMessage({
      type: 'credentialsd-request',
      requestId,
      cmd: 'getClientCapabilities',
    }, '*');

    return promise;
  };
}

console.log('[credentialsd] WebAuthn credential override active (Edge/Chromium)');
