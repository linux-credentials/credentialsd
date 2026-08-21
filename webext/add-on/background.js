/**
 * Background script that bridges content script messages
 * to the native messaging host.
 *
 * Works in both Firefox (background script) and Chromium (service worker).
 * ArrayBuffer serialization is handled by the MAIN world content script,
 * so this script simply forwards messages between content and native.
 */

const browserAPI = globalThis.browser || globalThis.chrome;

function connected(port) {
  const portId = port.sender.tab.id;
  console.log('[credentialsd] received connection from content script', portId);
  port.onMessage.addListener((msg) => rcvFromContent(msg, port));
}

async function rcvFromContent(msg, port) {
  const { requestId, cmd, options = null } = msg;
  console.debug('[credentialsd] forwarding', cmd, 'to native app');

  const origin = port.sender.origin;
  const topOrigin = new URL(port.sender.tab.url).origin;
  const request = { requestId, cmd, options, origin, topOrigin };

  try {
    const response = await browserAPI.runtime.sendNativeMessage('xyz.iinuwa.credentialsd_helper', request);
    console.log('[credentialsd] received from native, forwarding to content');
    port.postMessage(response);
  } catch (error) {
    console.error('[credentialsd] Error sending message to native app', error.message);
  }
}

// Listen for connections from content script
console.log('[credentialsd] background script starting');
browserAPI.runtime.onConnect.addListener(connected);
