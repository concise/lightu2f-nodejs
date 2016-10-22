const assert = require('assert');

const u2fcrypto = require('./u2fcrypto');

const DER_decode_one_something = u2fcrypto.DER_decode_one_something;
const asciiPrintableDecode = u2fcrypto.asciiPrintableDecode;
const asciiPrintableEncode = u2fcrypto.asciiPrintableEncode;
const isValidPublicKey = u2fcrypto.isValidPublicKey;
const jsonDecode = u2fcrypto.jsonDecode;
const jsonEncode = u2fcrypto.jsonEncode;
const sha256 = u2fcrypto.sha256;
const verify = u2fcrypto.verify;
const websafeBase64Decode = u2fcrypto.websafeBase64Decode;
const websafeBase64Encode = u2fcrypto.websafeBase64Encode;
const x509Decode = u2fcrypto.x509Decode;

const genRegChall = function (appId, nonce, keyHandles) {
    return jsonEncode({
        "type": "u2f_register_request",
        "registerRequests": [{
            "appId": appId,
            "challenge": nonce,
            "version": "U2F_V2"
        }],
        "signRequests": keyHandles.map(function (kh) {
            return {
                "appId": appId,
                "challenge": "",
                "keyHandle": kh,
                "version": "U2F_V2"
            };
        })
    });
};

const procRegResp = function (appId, nonce, response) {
    response = jsonDecode(response);

    assert(typeof response === 'object');
    assert(typeof response.clientData === 'string');
    assert(typeof response.registrationData === 'string');

    const client_data_b64 = response.clientData;
    const registration_response_b64 = response.registrationData;

    const client_data_raw = websafeBase64Decode(client_data_b64);
    const client_data_str = asciiPrintableDecode(client_data_raw);
    const client_data_dct = jsonDecode(client_data_str);
    assert(typeof client_data_dct === 'object');
    assert(typeof client_data_dct.typ === 'string');
    assert(typeof client_data_dct.challenge === 'string');
    assert(typeof client_data_dct.origin === 'string');
    assert(client_data_dct.typ === 'navigator.id.finishEnrollment');
    assert(client_data_dct.challenge === nonce);
    const facetid = client_data_dct.origin;
    const cidinfo = client_data_dct.cid_pubkey || null;

    const registration_response_raw = websafeBase64Decode(registration_response_b64);
    assert(registration_response_raw.length >= 67);
    assert(registration_response_raw[0] === 0x05);

    const publickey = registration_response_raw.slice(1, 66);
    assert(isValidPublicKey(publickey));

    const LL = registration_response_raw[66];
    assert(registration_response_raw.length >= 67 + LL);

    const keyhandle = registration_response_raw.slice(67, 67 + LL);
    const [T, L, V, X] = DER_decode_one_something(registration_response_raw.slice(67 + LL));
    const certificate = Buffer.concat([T, L, V]);
    const signature_to_verify = X;
    const attest_pubkey_Q = x509Decode(certificate);
    const data_to_sign = Buffer.concat([
        Buffer.from([0x00]),
        sha256(asciiPrintableEncode(appId)),
        sha256(client_data_raw),
        keyhandle,
        publickey
    ]);
    assert(verify(attest_pubkey_Q, data_to_sign, signature_to_verify));
    return {
        "facetid": facetid,
        "keyHandle": websafeBase64Encode(keyhandle),
        "publicKey": websafeBase64Encode(publickey),
        "certificate": websafeBase64Encode(certificate),
        "cid": cidinfo
    };
};

const genAuthChall = function (appId, nonce, tuples) {
    return jsonEncode({
        "type": "u2f_sign_request",
        "signRequests": tuples.map(function (tuple) {
            const [kh, pk, cnt] = tuple;
            const challengeInfo = websafeBase64Encode(Buffer.concat([
                websafeBase64Decode(nonce),
                websafeBase64Decode(pk),
                cnt === null ? Buffer.alloc(5) : Buffer.from([ 0x01, cnt >> 24, cnt >> 16, cnt >> 8, cnt ])
            ]));
            return {
                "appId": appId,
                "challenge": challengeInfo,
                "keyHandle": kh,
                "version": "U2F_V2"
            };
        })
    });
};

const procAuthResp = function (appId, nonce, response) {
    response = jsonDecode(response);

    assert(typeof response === 'object');
    assert(typeof response.keyHandle === 'string');
    assert(typeof response.clientData === 'string');
    assert(typeof response.signatureData === 'string');

    const keyhandle_b64 = response.keyHandle;
    const client_data_b64 = response.clientData;
    const authentication_response_b64 = response.signatureData;
    const claimed_keyhandle = websafeBase64Decode(keyhandle_b64);

    const client_data_raw = websafeBase64Decode(client_data_b64);
    const client_data_str = asciiPrintableDecode(client_data_raw);
    const client_data_dct = jsonDecode(client_data_str);
    assert(typeof client_data_dct === 'object');
    assert(typeof client_data_dct.typ === 'string');
    assert(typeof client_data_dct.challenge === 'string');
    assert(typeof client_data_dct.origin === 'string');
    assert(client_data_dct.typ === 'navigator.id.getAssertion');
    const facetid = client_data_dct.origin;
    const client_data_challenge = websafeBase64Decode(client_data_dct.challenge);
    const L = websafeBase64Decode(nonce).length;
    assert(client_data_challenge.length === L + 65 + 1 + 4);
    assert(Buffer.compare(websafeBase64Decode(nonce), client_data_challenge.slice(0, L)) === 0);
    const claimed_publickey = client_data_challenge.slice(L, L + 65);
    let claimed_old_counter;
    if (client_data_challenge[L+65] === 1) {
        claimed_old_counter = client_data_challenge.readUInt32BE(L + 65 + 1);
    } else if (client_data_challenge[L+65] === 0) {
        claimed_old_counter = null;
    } else {
        assert(false);
    }
    const cidinfo = client_data_dct.cid_pubkey || null;

    const authentication_response_raw = websafeBase64Decode(authentication_response_b64);
    assert(authentication_response_raw.length >= 5);
    assert(authentication_response_raw[0] === 1);
    const claimed_new_counter_raw = authentication_response_raw.slice(1, 5);
    const claimed_new_counter = claimed_new_counter_raw.readUInt32BE(0);
    const signature_to_verify = authentication_response_raw.slice(5);

    const data_to_sign = Buffer.concat([
        sha256(asciiPrintableEncode(appId)),
        Buffer.from([0x01]),
        claimed_new_counter_raw,
        sha256(client_data_raw)
    ]);

    assert(verify(claimed_publickey, data_to_sign, signature_to_verify));
    return {
        "facetid": facetid,
        "keyHandle": websafeBase64Encode(claimed_keyhandle),
        "publicKey": websafeBase64Encode(claimed_publickey),
        "oldCounter": claimed_old_counter,
        "newCounter": claimed_new_counter,
        "cid": cidinfo
    };
};

const lightu2f = Object.create(null);
lightu2f.genRegChall = genRegChall;
lightu2f.procRegResp = procRegResp;
lightu2f.genAuthChall = genAuthChall;
lightu2f.procAuthResp = procAuthResp;
module.exports = lightu2f;
