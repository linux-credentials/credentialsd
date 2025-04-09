/*
On startup, connect to the "credential_shim" app.
*/
let contentPort;
let nativePort;

function connected(port) {
  console.log("received connection from content script");

  // initialize content port
  contentPort = port;
  console.log(contentPort);

  // Initialize native port
  nativePort = browser.runtime.connectNative("credential_manager_shim");
  console.log(`connected to native app`)
  console.log(nativePort)

  // Set up content port listener
  contentPort.onMessage.addListener(rcvFromContent)

 // Set up native port listener
 console.log("setting up native port response listener")
 nativePort.onMessage.addListener(rcvFromNative);

}

function rcvFromContent(msg) {
  const { requestId, cmd, options } = msg;
  const origin = contentPort.sender.origin
  const topOrigin = new URL(contentPort.sender.tab.url).origin
  // const isCrossOrigin = origin === topOrigin
  // const isTopLevel = contentPort.sender.frameId === 0;


  const serializedOptions = serializeRequest(options)

  console.debug(options.publicKey.challenge)
  console.debug("background script received options, passing onto native app")
  nativePort.postMessage({ requestId, cmd, options: serializedOptions, origin, topOrigin })
}

function rcvFromNative(msg) {
  console.log("Received (native -> background): " + msg);
  console.log("forwarding to content script");
  const { requestId, data, error } = msg;
  contentPort.postMessage(msg);
}

function serializeBytes(buffer) {
  const options = {alphabet: "base64url", omitPadding: true};
  return new Uint8Array(buffer).toBase64(options)
}

function deserializeBytes(base64str) {
  const options = {alphabet: "base64url"}
  return Uint8Array.fromBase64(base64str, options)
}

function serializeRequest(options) {
  // Serialize ArrayBuffers
  const clone = structuredClone(options)
  clone.publicKey.challenge = serializeBytes(options.publicKey.challenge)
  clone.publicKey.user.id = serializeBytes(options.publicKey.user.id)
  if (clone.publicKey.excludedCredentials) {
    for (const cred in clone.publicKey.excludedCredentials) {
      cred.id = serializeBytes(cred.id)
    }
  }
  if (clone.publicKey.allowCredentials) {
    for (const cred of clone.allowCredentials) {
      cred.id = serializeBytes(cred.id);
    }
  }
  return clone
}


// Listen for connections from content script
console.log("Starting up credential_manager_shim background script")
browser.runtime.onConnect.addListener(connected);