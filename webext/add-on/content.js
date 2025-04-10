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
    if (error) {
        request.reject(error)
    } else {
        request.resolve(data)
    }
}
async function cloneCredentialResponse(credential) {
    try {
        const options = { alphabet: "base64url" }
        const obj = {}
        obj.id = credential.id;
        obj.rawId = cloneInto(Uint8Array.fromBase64(credential.rawId, options), obj)
        // TODO: get authenticator attachment
        obj.authenticatorAttachment = undefined
        const response = {}
        // credential registration response
        if (credential.response.attestationObject) {
            const clientDataJSON = credential.response.clientDataJSON
            response.clientDataJSON = Uint8Array.fromBase64(clientDataJSON, options)
            const attestationObject = credential.response.attestationObject
            response.attestationObject = Uint8Array.fromBase64(attestationObject, options)
            response.transports = [...credential.response.transports]
            const authenticatorData = Uint8Array.fromBase64(credential.response.authenticatorData, options)
            response.authenticatorData = cloneInto(authenticatorData, response)
            response.getAuthenticatorData = function() {
                return this.authenticatorData
            }
            response.getPublicKeyAlgorithm = function() {
                const publicKeyAlgorithm = credential.response.publicKeyAlgorithm
                return publicKeyAlgorithm
            }
            const publicKey = Uint8Array.fromBase64(credential.response.publicKey, options)
            response.publicKey = cloneInto(publicKey, response)
            response.getPublicKey = function() {
                return this.publicKey
            }
            response.getTransports = function() {
                return this.transports
            }

        }
        // credential attestation response
        else if (credential.response.signature) {
            const clientDataJSON = credential.response.clientDataJSON
            response.clientDataJSON = Uint8Array.fromBase64(clientDataJSON, options)
            const authenticatorData = Uint8Array.fromBase64(credential.response.authenticatorData, options)
            response.authenticatorData = cloneInto(authenticatorData, response)
            const signature = Uint8Array.fromBase64(credential.response.signature)
            response.signature = cloneInto(signature, response)
            const userHandle = Uint8Array.fromBase64(credential.response.userHandle)
            response.userHandle = cloneInto(userHandle, response)
        }
        else {
            throw cloneInto(new Error("Unknown credential response type received"), window)
        }
        obj.response = cloneInto(response, obj, { cloneFunctions: true })
        obj.clientExtensionResults = new window.Object();
        obj.getClientExtensionResults = function() {
            // TODO
            return this.clientExtensionResults
        }
        obj.type = "public-key"
        obj.toJSON = function() {
            json = new window.Object();
            json.id = this.id
            json.rawId = this.id

            json.response = new window.Object()
            // credential registration response
            if (credential.response.attestationObject) {
                json.response.clientDataJSON = credential.response.clientDataJSON
                json.response.authenticatorData = credential.response.authenticatorData
                json.response.transports = this.transports
                json.response.publicKey = credential.response.publicKey
                json.response.publicKeyAlgorithm = credential.response.publicKeyAlgorithm
                json.response.attestationObject = credential.response.attestationObject
            }
            // credential attestation response
            else if (credential.response.signature) {
                json.response.clientDataJSON = credential.response.clientDataJSON
                json.response.authenticatorData = credential.response.authenticatorData
                json.response.signature = credential.response.signature
                json.response.userHandle = credential.response.userHandle
            }
            else {
                throw cloneInto(new Error("Unknown credential type received"), window)
            }

            json.authenticatorAttachment = this.authenticatorAttachment
            json.clientExtensionResults = this.clientExtensionResults
            json.type = this.type
            return json
        }
        return cloneInto(obj, window, { cloneFunctions: true })
    }
    catch (error) {
        console.error(error)
        throw cloneInto(error, window)
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
    return promise.then(cloneCredentialResponse)
}

function getCredential(request) {
    console.log("forwarding get call from content script to background script")
    // the signal object can't be sent to background script, so omit it
    const { /** @type {AbortSignal} */signal, ...options} = request

    const { requestId, promise } = startRequest();
    webauthnPort.postMessage({ requestId, cmd: 'get', options, })
    return promise.then(cloneCredentialResponse)
};