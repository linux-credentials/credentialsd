/**
 * Content script running in ISOLATED world.
 * Bridges window.postMessage from the MAIN world content script
 * to the background script via runtime.connect.
 *
 * Works in both Firefox and Chromium browsers.
 */

const browserAPI = globalThis.browser || globalThis.chrome;
const port = browserAPI.runtime.connect({ name: 'credentialsd-helper' });

// Forward responses from background back to page context
port.onMessage.addListener((msg) => {
  const { requestId, data, error } = msg;
  window.postMessage({
    type: 'credentialsd-response',
    requestId,
    data,
    error,
  }, '*');
});

port.onDisconnect.addListener(() => {
  console.warn('[credentialsd] background port disconnected');
});

// Listen for requests from the MAIN world content script
window.addEventListener('message', (event) => {
  if (event.source !== window) return;
  if (event.data?.type !== 'credentialsd-request') return;

  const { requestId, cmd, options } = event.data;
  port.postMessage({ requestId, cmd, options });
});

console.log('[credentialsd] content bridge active');
