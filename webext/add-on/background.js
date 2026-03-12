/**
 * Background script that bridges content script messages
 * to the native messaging host.
 *
 * Works in both Firefox (background script) and Chromium (service worker).
 * ArrayBuffer serialization is handled by the MAIN world content script,
 * so this script simply forwards messages between content and native.
 */

const browserAPI = globalThis.browser || globalThis.chrome;

let contentPort;
let nativePort;

function connected(port) {
  console.log('[credentialsd] received connection from content script');
  contentPort = port;

  // Connect to native messaging host
  nativePort = browserAPI.runtime.connectNative('xyz.iinuwa.credentialsd_helper');

  // Check for connection errors (browser-specific patterns)
  const connectError = nativePort.error || browserAPI.runtime.lastError;
  if (connectError) {
    console.error('[credentialsd] native connect error:', connectError.message || connectError);
    return;
  }

  console.log('[credentialsd] connected to native app');

  contentPort.onMessage.addListener(rcvFromContent);
  nativePort.onMessage.addListener(rcvFromNative);

  nativePort.onDisconnect.addListener(() => {
    const error = browserAPI.runtime.lastError;
    if (error) {
      console.error('[credentialsd] native port disconnected:', error.message);
    }
  });
}

function rcvFromContent(msg) {
  const { requestId, cmd, options } = msg;
  const origin = contentPort.sender.origin;
  const topOrigin = new URL(contentPort.sender.tab.url).origin;

  if (options) {
    console.debug('[credentialsd] forwarding', cmd, 'to native app');
    nativePort.postMessage({ requestId, cmd, options, origin, topOrigin });
  } else {
    console.debug('[credentialsd] forwarding', cmd, '(no options) to native app');
    nativePort.postMessage({ requestId, cmd, origin, topOrigin });
  }
}

function rcvFromNative(msg) {
  console.log('[credentialsd] received from native, forwarding to content');
  contentPort.postMessage(msg);
}

// Listen for connections from content script
console.log('[credentialsd] background script starting');
browserAPI.runtime.onConnect.addListener(connected);
