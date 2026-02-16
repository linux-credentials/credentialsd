/**
 * Content script running in ISOLATED world.
 * Bridges window.postMessage from the MAIN world content script
 * to the background service worker via chrome.runtime.connect.
 */

const port = chrome.runtime.connect({ name: 'credentialsd-helper' });

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

console.log('[credentialsd] content bridge active (Edge/Chromium)');
