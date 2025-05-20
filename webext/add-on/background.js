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
  if (nativePort.error) {
    console.error(nativePort.error)
    throw nativePort.error
  }
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

  if (options) {
    const serializedOptions = serializeRequest(options)

    console.debug(options.publicKey.challenge)
    console.debug("background script received options, passing onto native app")
    nativePort.postMessage({ requestId, cmd, options: serializedOptions, origin, topOrigin })
  } else {
    console.debug("background script received message without arguments, passing onto native app")
    nativePort.postMessage({ requestId, cmd, origin, topOrigin })
  }
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
  clone.publicKey.challenge = serializeBytes(clone.publicKey.challenge)
  if (clone.publicKey.user) {
    clone.publicKey.user.id = serializeBytes(clone.publicKey.user.id)
  }
  if (clone.publicKey.excludedCredentials) {
    for (const cred in clone.publicKey.excludedCredentials) {
      cred.id = serializeBytes(cred.id)
    }
  }
  if (clone.publicKey.allowCredentials) {
    for (const cred of clone.publicKey.allowCredentials) {
      cred.id = serializeBytes(cred.id);
    }
  }
  if (clone.publicKey.extensions && clone.publicKey.extensions.prf) {
    if (clone.publicKey.extensions.prf.eval) {
      clone.publicKey.extensions.prf.eval.first = serializeBytes(clone.publicKey.extensions.prf.eval.first);
      if (clone.publicKey.extensions.prf.eval.second) {
        clone.publicKey.extensions.prf.eval.second = serializeBytes(clone.publicKey.extensions.prf.eval.second);
      }
    }
    if (clone.publicKey.extensions.prf.evalByCredential) {
      const evalByCredential = clone.publicKey.extensions.prf.evalByCredential;

      // Iterate over all credentialIDs, serialize the first/second bytebuffer and replace the original evalByCredential map
      const result = {};
      for (const credId in evalByCredentialData) {
        const prfValue = evalByCredentialData[credId];

        if (prfValue && prfValue.first) {
          const newPrfValue = {
              first: serializeBytes(prfValue.first)
          };

          if (prfValue.second) {
              newPrfValue.second = serializeBytes(prfValue.second);
          }
          result[credId] = newPrfValue;
        };
      }
      clone.publicKey.extensions.prf.evalByCredential = result;
    }

    if (clone.publicKey.extensions && clone.publicKey.extensions.credBlob) {
      clone.publicKey.extensions.credBlob = serializeBytes(clone.publicKey.extensions.credBlob);
    }
  }
  return clone
}


// Listen for connections from content script
console.log("Starting up credential_manager_shim background script")
browser.runtime.onConnect.addListener(connected);
