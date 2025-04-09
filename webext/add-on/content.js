let requestCounter = 0;
const pendingRequests = {}
var webauthnPort = browser.runtime.connect({ name: "credential_manager_shim" });
console.log("loading content")

webauthnPort.onMessage.addListener(({ requestId, data, error }) => {
    console.log('received message from background script:')
    console.log(data);
    endRequest(requestId, data, error);
});

console.log("overriding navigator.credentials in content script");
exportFunction(createCredential, navigator.credentials, { defineAs: "create"})
exportFunction(getCredential, navigator.credentials, { defineAs: "get"})


function startRequest() {
    const requestId = requestCounter++;
    const {promise, resolve, reject } = window.Promise.withResolvers();
    pendingRequests[requestId] = { resolve, reject }
    return { requestId, promise }
}

function endRequest(requestId, data, error) {
    const request = pendingRequests[requestId]
    if (data) {
        request.resolve(data)
    } else {
        request.reject(error)
    }
}

function createCredential(request) {
    console.log("forwarding create call from content script to background script")
    console.log(webauthnPort)
    console.log(request)

    // the signal object can't be sent to background script, so omit it
    const { signal, ...options} = request

    const { requestId, promise } = startRequest();
    webauthnPort.postMessage({ requestId, cmd: 'create', options, })
    return promise.then((credential) => {
        const options = { alphabet: "base64url", }
        credential.rawId = Uint8Array.fromBase64(credential.rawId, options)
        const clientDataJSON = credential.response.clientDataJSON
        credential.response.clientDataJSON = Uint8Array.fromBase64(clientDataJSON, options)
        const attestationObject = credential.response.attestationObject
        credential.response.attestationObject = Uint8Array.fromBase64(attestationObject, options)
        credential.response.getTransports = function() {
            return credential.response.transports
        }
        credential.getClientExtensionResults = function() {
            return {}
        }
        credential.toJSON = function() {
            return {
                id: credential.id,
                rawId: credential.id,
                response: {
                    clientDataJSON,
                    authenticatorData: credential.response.authenticatorData,
                    transports: credential.response.transports,
                    publicKey: credential.response.publicKey,
                    publicKeyAlgorithm: credential.response.publicKeyAlgorithm,
                    attestationObject,
                },
                clientExtensionResults: {
                    toJSON: function() { return {} }
                },
                type: "public-key",
            }
        }
        return cloneInto(credential, window, { cloneFunctions: true})
    });
    // window.Promise.reject(new DOMException('navigator.credentials.create not implemented', 'NotAllowedError'));
}

function getCredential(request) {
    console.log("forwarding get call from content script to background script")
    // the signal object can't be sent to background script, so omit it
    const { signal, ...options} = request

    const { requestId, promise } = startRequest();
    webauthnPort.postMessage({ requestId, cmd: 'get', options: serializeRequest(options) })
    return promise
    //window.Promise.reject(new DOMException('navigator.credentials.get not implemented', 'NotAllowedError'));
};