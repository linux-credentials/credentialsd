/**
 * Background service worker for Edge/Chromium.
 * Bridges content script messages to the native messaging host.
 */

let contentPort;
let nativePort;

function arrayBufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64urlToBytes(str) {
  if (!str) return null;
  const padded = str.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function connected(port) {
  console.log('[credentialsd] received connection from content script');
  contentPort = port;

  // Connect to native messaging host
  nativePort = chrome.runtime.connectNative('xyz.iinuwa.credentialsd_helper');
  if (chrome.runtime.lastError) {
    console.error('[credentialsd] native connect error:', chrome.runtime.lastError.message);
    return;
  }
  console.log('[credentialsd] connected to native app');

  contentPort.onMessage.addListener(rcvFromContent);
  nativePort.onMessage.addListener(rcvFromNative);

  nativePort.onDisconnect.addListener(() => {
    if (chrome.runtime.lastError) {
      console.error('[credentialsd] native port disconnected:', chrome.runtime.lastError.message);
    }
  });
}

function rcvFromContent(msg) {
  const { requestId, cmd, options } = msg;
  const origin = contentPort.sender.origin;
  const topOrigin = new URL(contentPort.sender.tab.url).origin;

  if (options) {
    const serializedOptions = serializeRequest(options);
    console.debug('[credentialsd] forwarding', cmd, 'to native app');
    nativePort.postMessage({ requestId, cmd, options: serializedOptions, origin, topOrigin });
  } else {
    console.debug('[credentialsd] forwarding', cmd, '(no options) to native app');
    nativePort.postMessage({ requestId, cmd, origin, topOrigin });
  }
}

function rcvFromNative(msg) {
  console.log('[credentialsd] received from native, forwarding to content');
  contentPort.postMessage(msg);
}

function serializeBytes(buffer) {
  if (buffer && buffer.__b64url__) {
    // Already base64url-encoded by the MAIN world script
    return buffer.__b64url__;
  }
  if (buffer instanceof ArrayBuffer || ArrayBuffer.isView(buffer)) {
    return arrayBufferToBase64url(buffer);
  }
  if (typeof buffer === 'string') {
    return buffer;
  }
  return buffer;
}

function serializeRequest(options) {
  const clone = JSON.parse(JSON.stringify(options));

  // The MAIN world script serialized ArrayBuffers as { __b64url__: "..." }
  // Unwrap these for the native host
  function unwrapB64url(obj) {
    if (obj === null || obj === undefined) return obj;
    if (typeof obj !== 'object') return obj;
    if (obj.__b64url__) return obj.__b64url__;
    if (Array.isArray(obj)) return obj.map(unwrapB64url);
    const result = {};
    for (const key of Object.keys(obj)) {
      result[key] = unwrapB64url(obj[key]);
    }
    return result;
  }

  return unwrapB64url(clone);
}

// Listen for connections from content script
console.log('[credentialsd] background service worker starting (Edge/Chromium)');
chrome.runtime.onConnect.addListener(connected);
