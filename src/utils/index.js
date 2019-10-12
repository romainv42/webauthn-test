/**
 * based on https://raw.githubusercontent.com/fido-alliance/webauthn-demo/master/utils.js
 */

const crypto = require('crypto')
const base64url = require('base64url').default
const cbor = require('cbor')
const { Certificate } = require('@fidm/x509')
const iso_3166_1 = require('iso-3166-1')

/** U2F Presence constant */
const U2F_USER_PRESENTED = 0x01

/** @type {AuthenticatorTransport[]} */
const transports = ['usb', 'nfc', 'ble']
/** @type {'public-key'} */
const publicKeyType = 'public-key'

/** @typedef {import('./dbconnector').Authenticator} Authenticator */

/**
 * Takes signature, data and PEM public key and tries to verify signature
 * @param {Buffer} signature
 * @param {Buffer} data
 * @param {String} publicKey - PEM encoded public key
 */
function verifySignature(signature, data, publicKey) {
    return crypto.createVerify('SHA256').update(data).verify(publicKey, signature)
}

/**
 * Generates makeCredentials request
 * @param {String} username       - username
 * @param {String} displayName    - user's personal display name
 * @param {Buffer} id             - user's id
 * @return {PublicKeyCredentialCreationOptions} - server encoded make credentials request
 */
function generateServerMakeCredRequest(username, displayName, id) {
    return {
        challenge: crypto.randomBytes(32),

        rp: {
            name: "WebAuthn Demo"
        },
        user: {
            id,
            name: username,
            displayName: displayName
        },
        attestation: 'direct',
        pubKeyCredParams: [
            {type: "public-key", alg: -7}, // "ES256" IANA COSE Algorithms registry
            {type: "public-key", alg: -257} // "RSA256" IANA COSE Algorithms registry
        ]
    }
}

/**
 * Generates getAssertion request
 * @param  {Authenticator[]} authenticators - list of registered authenticators
 * @return {PublicKeyCredentialRequestOptions} - server encoded get assertion request
 */
function generateServerGetAssertion(authenticators) {
    const allowCredentials = authenticators.map(authr => ({
        type: publicKeyType,
        id: base64url.toBuffer(authr.credID),
        transports
    }))
    return {
        challenge: crypto.randomBytes(32),
        allowCredentials
    }
}


/**
 * Returns SHA-256 digest of the given data.
 * @param  {string} data - base64url-encoded data to hash
 * @return - the hash
 */
const hash = data => crypto.createHash('SHA256').update(base64url.toBuffer(data)).digest()

/**
 * Takes COSE encoded public key and converts it to RAW PKCS ECDHA key
 * @param  {Buffer} COSEPublicKey - COSE encoded public key
 * @return - RAW PKCS encoded public key
 */
function COSEECDHAtoPKCS(COSEPublicKey) {
    /* 
       +------+-------+-------+---------+----------------------------------+
       | name | key   | label | type    | description                      |
       |      | type  |       |         |                                  |
       +------+-------+-------+---------+----------------------------------+
       | crv  | 2     | -1    | int /   | EC Curve identifier - Taken from |
       |      |       |       | tstr    | the COSE Curves registry         |
       |      |       |       |         |                                  |
       | x    | 2     | -2    | bstr    | X Coordinate                     |
       |      |       |       |         |                                  |
       | y    | 2     | -3    | bstr /  | Y Coordinate                     |
       |      |       |       | bool    |                                  |
       |      |       |       |         |                                  |
       | d    | 2     | -4    | bstr    | Private key                      |
       +------+-------+-------+---------+----------------------------------+
    */

    const coseStruct = cbor.decodeAllSync(COSEPublicKey)[0]
    const tag = Buffer.from([0x04])
    const x = coseStruct.get(-2)
    const y = coseStruct.get(-3)

    return Buffer.concat([tag, x, y])
}

/* metadata prefix for a raw P-256 EC key:
SEQUENCE {
    SEQUENCE {
        OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
        OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
    }
} */
const PKPrefix = Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex")

/**
 * Convert binary certificate or public key to an OpenSSL-compatible PEM text format.
 * @param  {Buffer} pkBuffer - Cert or PubKey buffer
 * @return PEM
 */
function ASN1toPEM(pkBuffer) {
    if (!Buffer.isBuffer(pkBuffer)) throw new TypeError("ASN1toPEM: pkBuffer must be Buffer.")

    let type
    if (pkBuffer.length == 65 && pkBuffer[0] == 0x04) {
        pkBuffer = Buffer.concat([PKPrefix, pkBuffer])
        type = 'PUBLIC KEY'
    } else {
        type = 'CERTIFICATE'
    }

    return [
        `-----BEGIN ${type}-----`,
        ...pkBuffer.toString('base64').match(/.{1,64}/g),
        `-----END ${type}-----\n`
    ].join('\n')
}

/**
 * Parses authenticatorData buffer.
 * @param {Buffer} buffer - authenticatorData buffer
 * @return parsed authenticatorData struct
 */
function parseMakeCredAuthData(buffer) {
    let i = 37
    const aaguid = buffer.slice(i, i+=16)
    const credIDLen = buffer.slice(i, i+=2).readUInt16BE(0)
    const credID = buffer.slice(i, i+=credIDLen)
    const COSEPublicKey = buffer.slice(i)

    return { ...parseGetAssertAuthData(buffer), aaguid, credID, COSEPublicKey }
}

function verifyAuthenticatorAttestationResponse(webAuthnResponse) {
    const attestationBuffer = base64url.toBuffer(webAuthnResponse.attestationObject)
    const ctapMakeCredResp = cbor.decodeAllSync(attestationBuffer)[0]

    /** @type {{verified: boolean, authrInfo?: Authenticator}} */
    const response = { verified: false }
    if (ctapMakeCredResp.fmt === 'fido-u2f') {
        const authrDataStruct = parseMakeCredAuthData(ctapMakeCredResp.authData)

        if (!(authrDataStruct.flags & U2F_USER_PRESENTED))
            throw new Error('User was NOT presented during authentication!')

        const clientDataHash = hash(webAuthnResponse.clientDataJSON)
        const reservedByte = Buffer.alloc(1)
        const publicKey = COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey)
        const signatureBase = Buffer.concat([reservedByte, authrDataStruct.rpIdHash, clientDataHash, authrDataStruct.credID, publicKey])

        const PEMCertificate = ASN1toPEM(ctapMakeCredResp.attStmt.x5c[0])
        const signature = ctapMakeCredResp.attStmt.sig

        response.verified = verifySignature(signature, signatureBase, PEMCertificate)

        if (response.verified) {
            response.authrInfo = {
                fmt: 'fido-u2f',
                publicKey: base64url.encode(publicKey),
                counter: authrDataStruct.counter,
                credID: base64url.encode(authrDataStruct.credID)
            }
        }
    } else if (ctapMakeCredResp.fmt === 'packed' && ctapMakeCredResp.attStmt.hasOwnProperty('x5c')) {
        const authrDataStruct = parseMakeCredAuthData(ctapMakeCredResp.authData)

        if (!(authrDataStruct.flags & U2F_USER_PRESENTED))
            throw new Error('User was NOT presented during authentication!')

        const clientDataHash = hash(webAuthnResponse.clientDataJSON)
        const publicKey = COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey)
        const signatureBase = Buffer.concat([ctapMakeCredResp.authData, clientDataHash])

        const PEMCertificate = ASN1toPEM(ctapMakeCredResp.attStmt.x5c[0])
        const signature = ctapMakeCredResp.attStmt.sig

        const pem = Certificate.fromPEM(Buffer.from(PEMCertificate))

        // Getting requirements from https://www.w3.org/TR/webauthn/#packed-attestation
        const aaguid_ext = pem.getExtension('1.3.6.1.4.1.45724.1.1.4')

        response.verified = // Verify that sig is a valid signature over the concatenation of authenticatorData
            // and clientDataHash using the attestation public key in attestnCert with the algorithm specified in alg.
            verifySignature(signature, signatureBase, PEMCertificate) &&
            // version must be 3 (which is indicated by an ASN.1 INTEGER with value 2)
            pem.version == 3 &&
            // ISO 3166 valid country
            typeof iso_3166_1.whereAlpha2(pem.subject.countryName) !== 'undefined' &&
            // Legal name of the Authenticator vendor (UTF8String)
            pem.subject.organizationName &&
            // Literal string “Authenticator Attestation” (UTF8String)
            pem.subject.organizationalUnitName === 'Authenticator Attestation' &&
            // A UTF8String of the vendor’s choosing
            pem.subject.commonName &&
            // The Basic Constraints extension MUST have the CA component set to false
            // @ts-ignore
            !pem.extensions.isCA &&
            // If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid)
            // verify that the value of this extension matches the aaguid in authenticatorData.
            // The extension MUST NOT be marked as critical.
            (aaguid_ext == null ||
              authrDataStruct.hasOwnProperty('aaguid')
              && !aaguid_ext.critical
              && crypto.timingSafeEqual(aaguid_ext.value.slice(2), authrDataStruct.aaguid)
            )

        if (response.verified) {
            response.authrInfo = {
                fmt: 'fido-u2f',
                publicKey: base64url.encode(publicKey),
                counter: authrDataStruct.counter,
                credID: base64url.encode(authrDataStruct.credID)
            }
        }
    } else {
        throw new Error('Unsupported attestation format! ' + ctapMakeCredResp.fmt)
    }

    return response
}


/**
 * Takes an array of registered authenticators and find one specified by credID
 * @param  {String} credID - base64url encoded credential
 * @param  {Authenticator[]} authenticators - list of authenticators
 * @return - found authenticator
 */
function findAuthr(credID, authenticators) {
    for (const authr of authenticators) if (authr.credID === credID) return authr
    throw new Error(`Unknown authenticator with credID ${credID}!`)
}

/**
 * Parses AuthenticatorData from GetAssertion response
 * @param  {Buffer} buffer - Auth data buffer
 * @return parsed authenticatorData struct
 */
function parseGetAssertAuthData(buffer) {
    let i = 0
    const rpIdHash = buffer.slice(i, i+=32)
    const flagsBuf = buffer.slice(i, i+=1)
    const flags = flagsBuf[0]
    const counterBuf = buffer.slice(i, i+=4)
    const counter = counterBuf.readUInt32BE(0)

    return { rpIdHash, flagsBuf, flags, counter, counterBuf }
}

/**
 * @param {string} authrId
 * @param {Authenticator[]} authenticators */
function verifyAuthenticatorAssertionResponse(webAuthnResponse, authrId, authenticators) {
    const authr = findAuthr(authrId, authenticators)

    if (authr.fmt === 'fido-u2f') {
        const authrDataStruct = parseGetAssertAuthData(base64url.toBuffer(webAuthnResponse.authenticatorData))

        if (!(authrDataStruct.flags & U2F_USER_PRESENTED))
            throw new Error('User was NOT presented during authentication!')

        const clientDataHash = hash(webAuthnResponse.clientDataJSON)
        const signatureBase = Buffer.concat([authrDataStruct.rpIdHash, authrDataStruct.flagsBuf, authrDataStruct.counterBuf, clientDataHash])

        const publicKey = ASN1toPEM(base64url.toBuffer(authr.publicKey))
        const signature = base64url.toBuffer(webAuthnResponse.signature)

        if (verifySignature(signature, signatureBase, publicKey)) {
            if (authrDataStruct.counter <= authr.counter) throw new Error('Authr counter did not increase!')
            authr.counter = authrDataStruct.counter
            return true
        }
    }

    return false
}

module.exports = {
    generateServerMakeCredRequest,
    generateServerGetAssertion,
    verifyAuthenticatorAttestationResponse,
    verifyAuthenticatorAssertionResponse
}
