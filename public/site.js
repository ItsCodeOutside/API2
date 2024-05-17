var messages;
var randomString;


function setup(){
    messages = document.getElementById('messages');
    randomString = generateRandomString() + generateRandomString() + generateRandomString();
    appendMessage(`randomString = "${randomString}"`);
    if (CheckBrowserSupportsWebAuthn())
    {
        appendMessage('Ready...');
        //register();
    }
    else
    {
        appendMessage('WebAuthn not supported');
    }
}

function appendMessage(message){
    const messageElement = document.createElement('div');
    messageElement.innerText = message;
    messages.appendChild(messageElement);
}


function CheckBrowserSupportsWebAuthn(){
    if (window.PublicKeyCredential) {
        return true;
    }
    
    return false;    
}

// ------------------------------
function uint8ArrayToString(input){
    return String.fromCharCode.apply(null, input);
  }
  function generateRandomArray(length) {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return array;
  }

// function to create a random string
function generateRandomString() {
    let array = new Uint32Array(1);
    crypto.getRandomValues(array);
    return array[0].toString(36);
}

// ------------------------------
function register(){
    appendMessage('Fetching options...');
    fetch('/register-config').then(function (response) {
        response.json().then(data => {
            appendMessage(`data.Challenge = "${data.challenge}"`);
            appendMessage("Done");            
            data.challenge = Uint8Array.from(data.challenge, c => c.charCodeAt(0));
            data.user.id = Uint8Array.from(data.user.id, c => c.charCodeAt(0));
            appendMessage(`data.Challenge = "${data.challenge}"`);
            appendMessage('Registering...');
            navigator.credentials.create({publicKey: data})
            .then(function (newCredentialInfo) {
                appendMessage('Registered');
                submitToServer(newCredentialInfo);
            })
            .catch(function (error) {
                appendMessage('Registration failed');
                console.log(error);
            });
        });
    }).catch(function (error) {
        appendMessage('Failed to fetch options');
        console.log(error);
    });
}

function base64ToArrayBuffer(base64) {
    console.log("Base64: " + base64);
    let binary_string = atob(base64);
    let len = binary_string.length;
    let bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++){
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}

function arrayBufferToBase64(buffer) {
    let binary = '';
    let bytes = new Uint8Array(buffer);
    let len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

function submitToServer(credential){
    appendMessage('Submitting to server...');
    var decoder = new TextDecoder('utf8');
    let credentialForServer = {
        ...credential,
        rawId: arrayBufferToBase64(credential.rawId),
        response: {
            clientDataJSON: decoder.decode(credential.response.clientDataJSON),
            attestationObject: arrayBufferToBase64(credential.response.attestationObject)
        }
    }
    // Log the attestationObject for comparison with server
    //console.log(credential.response.attestationObject);
    //console.log(credentialForServer.response.attestationObject);

    fetch('/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(credentialForServer)
    }).then(function (response) {
        appendMessage('Submitted to server');
    }).catch(function (error) {
        appendMessage('Failed to submit to server');
        console.log(error);
    });

}

function authenticate(){
    appendMessage('Fetching options...');
    fetch('/authenticate-config').then(function (response) {
        response.json().then(data => {
            console.log(data);
            const authOptions = {
                ...data,
                challenge: Uint8Array.from(data.challenge, c => c.charCodeAt(0)),
                allowCredentials: data.allowCredentials.map(cred => ({
                    ...cred,
                    id: base64ToArrayBuffer(cred.id),
                })),
            }
            appendMessage(`data.Challenge = "${authOptions.challenge}"`);
            appendMessage(`data.Challenge = "${authOptions.challenge}"`);
            appendMessage('Authenticating...');
            navigator.credentials.get({publicKey: authOptions})
            .then(function (newCredentialInfo) {
                appendMessage('Authenticated');
                submitAuthenticateToServer(newCredentialInfo);
            })
            .catch(function (error) {
                appendMessage('Authentication failed');
                console.log(error);
            });
        });
    }).catch(function (error) {
        appendMessage('Failed to fetch options');
        console.log(error);
    });
}

function submitAuthenticateToServer(credential){
    appendMessage('Submitting to server...');
    var decoder = new TextDecoder('utf8');
    let credentialForServer = {
        ...credential,
        rawId: arrayBufferToBase64(credential.rawId),
        response: {
            clientDataJSON: decoder.decode(credential.response.clientDataJSON),
            authenticatorData: arrayBufferToBase64(credential.response.authenticatorData),
            signature: arrayBufferToBase64(credential.response.signature),
            userHandle: arrayBufferToBase64(credential.response.userHandle)
        }
    }
    // Log the attestationObject for comparison with server
    //console.log(credential.response.attestationObject);
    //console.log(credentialForServer.response.attestationObject);

    fetch('/authenticate', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(credentialForServer)
    }).then(function (response) {
        appendMessage('Submitted to server');
    }).catch(function (error) {
        appendMessage('Failed to submit to server');
        console.log(error);
    });
}