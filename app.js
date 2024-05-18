const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const http = require('http').Server(app);
const base64url = require('base64url');
const crypto = require('crypto');
const cose = require('cose-js');
const jwkToPem = require('jwk-to-pem');
const CBOR = require('cbor');
const { ok } = require('assert');
var randomString;
var registered_credentialId;
var registered_publicKeyBytes;

// WARNING: The port is changed when you run the project from here so this must be updated each time
// It needs to be the "Forwarded address" port. Altneratively, you can set a LocalForward in your 
// ~/.ssh/config but that won't show on the "PORTS" tab in the terminal
const relyingPartyOrigin = 'http://localhost:57000';
const relyingPartyName = 'localhost testing webauthn';
const relyingPartyId = 'localhost';

app.use(express.static(__dirname + '/public'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));



// Routes
app.get('/', function (req, res) {
    res.send('Hello World');
});

app.get('/register-config', function (req, res) {
    console.log('register-config');
    const publicKeyCredentialCreationOptions = {
        challenge: generateRandomString(),            
        rp: {
            name: relyingPartyName,
            id: relyingPartyId,
        },
        user: {
            id: "UZSL85T9AFC",
            name: "name of test",
            displayName: "display name of testmoo",
        },
        pubKeyCredParams: [{alg: -7, type: "public-key"}],
        authenticatorSelection: {
            authenticatorAttachment: "cross-platform",
        },
        timeout: 60000,
        attestation: "direct"
    };
    //console.log(`publicKeyCredentialCreationOptions.challenge = "${publicKeyCredentialCreationOptions.challenge}"`);
    randomString = publicKeyCredentialCreationOptions.challenge;
    res.send(publicKeyCredentialCreationOptions);
});

app.post('/register', function (req, res) {
    //console.log(req.body);
    const clientDataJSON = JSON.parse(req.body.response.clientDataJSON);

    // Verify the challenge ID is the same random string we made earlier
    const challengeB64 = base64url.toBase64(clientDataJSON.challenge);
    const challengeString = Buffer.from(challengeB64, 'base64').toString('utf8');
    //console.log(`Base64Url = ${clientDataJSON.challenge}, challenge = ${challengeString}`);
    if (challengeString !== randomString) {
        res.status(400).send('Invalid challenge');
        return;
    }
    if (clientDataJSON.origin !== relyingPartyOrigin) {
        res.status(400).send('Invalid origin');
        return;
    }
    if (clientDataJSON.type !== 'webauthn.create') {
        res.status(400).send('Invalid type');
        return;
    }

    // Verify the attestation object
    // output the attestation object to the console so we can compare with what was logged on the browser
    const authData = CBOR.decode(base64ToArrayBuffer(req.body.response.attestationObject)).authData;

    // get the length of the credential ID
    const dataView = new DataView(new ArrayBuffer(2));
    const idLenBytes = authData.slice(53, 55);
    idLenBytes.forEach((value, index) => dataView.setUint8(index, value));
    const credentialIdLength = dataView.getUint16();
    
    // get the credential ID
    const credentialId = authData.slice(55, 55 + credentialIdLength);
    registered_credentialId = credentialId;
    //console.log("credentialId = " + credentialId);
    // get the public key object
    const publicKeyBytes = authData.slice(55 + credentialIdLength);
    registered_publicKeyBytes = publicKeyBytes;
    
    // the publicKeyBytes are encoded again as CBOR
    const publicKeyObject = CBOR.decode(publicKeyBytes);
    console.log('----');
    console.log(publicKeyObject)
    console.log('----');

    res.send('ok');
});

app.get('/authenticate-config', function (req, res) {
    randomString = generateRandomString();
    const publicKeyCredentialRequestOptions = {
        challenge: randomString,
        allowCredentials: [{
            type: 'public-key',
            // ID would be based on username. It needs to be stored server side from registration
            id: arrayBufferToBase64(registered_credentialId),
        }],
        timeout: 60000,
    };
    console.log(publicKeyCredentialRequestOptions);
    res.send(publicKeyCredentialRequestOptions);
});


app.post('/authenticate', (req, res) => {
    const clientDataJSON = JSON.parse(req.body.response.clientDataJSON);

    // Verify the challenge ID is the same random string we made earlier
    const challengeB64 = base64url.toBase64(clientDataJSON.challenge);
    const challengeString = Buffer.from(challengeB64, 'base64').toString('utf8');
    if (challengeString !== randomString) {
        res.status(400).send('Invalid challenge');
        return;
    }

    const rawId = base64ToArrayBuffer(req.body.rawId);
    const userHandle = base64ToArrayBuffer(req.body.response.userHandle);
    const signature = Buffer.from(base64ToArrayBuffer(req.body.response.signature));
    const authenticatorData = base64ToArrayBuffer(req.body.response.authenticatorData);
    console.log(signature);
    console.log(typeof signature);
    console.log(signature instanceof Buffer);
    
    // Create a hash of the clientDataJSON
    const clientDataHash = crypto.createHash('SHA256').update(Buffer.from(req.body.response.clientDataJSON, 'base64')).digest();
    
    const authenticatorDataBuffer = Buffer.from(authenticatorData);
    const clientDataHashBuffer = Buffer.from(clientDataHash);
    // Concatenate authenticatorData and clientDataHash
    const signedData = Buffer.concat([authenticatorDataBuffer, clientDataHashBuffer]);

    // Create a verify object
    const verify = crypto.createVerify('SHA256');

    // Input the data that was signed
    verify.update(signedData);

    //console.log(registered_publicKeyBytes);

    // get the public key from the registered public key bytes
    const coseKey = CBOR.decode(registered_publicKeyBytes);
    // Convert the COSE key to a JWK
    const jwk = {
        kty: 'EC',
        crv: 'P-256',
        x: coseKey.get(-2).toString('base64'), // -2 is the key for 'x' in COSE
        y: coseKey.get(-3).toString('base64'), // -3 is the key for 'y' in COSE
    };

console.log("jwk: ", jwk);

    // Check the signature
    const publicKey = jwkToPem(jwk); // This should be in the correct format
    const signatureIsValid = verify.verify(publicKey, signature);

    if (!signatureIsValid) {
        res.status(400).send('Invalid signature');
        return;
    } 

    res.send('ok');
});

// Start server
var server = http.listen(3000, function () {
    console.log('server is running on port', server.address().port);
});



// Helper functions
function generateRandomString() {
    let array = new Uint32Array(4);
    crypto.getRandomValues(array);
    return array[0].toString(36)
    + array[1].toString(36)
    + array[2].toString(36)
    + array[3].toString(36);
}

function base64ToArrayBuffer(base64) {
    let binary_string = Buffer.from(base64, 'base64').toString('binary');
    let len = binary_string.length;
    let bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++)        {
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
    return btoa(binary);
}