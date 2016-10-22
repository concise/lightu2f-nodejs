const assert = require('assert');
const crypto = require('crypto');

assert(crypto.getCurves().indexOf('prime256v1') >= 0, 'prime256v1 unsupported');

const generatePrivateKey = function (entropy) {
    return rfc6979sha256p256csprng(entropy).next().value;
};

const isValidPrivateKey = function (privateKey) {
    if (!Buffer.isBuffer(privateKey)) {
        throw new Error('privateKey MUST be a Buffer');
    }
    if (privateKey.length !== 32) {
        return false;
    }
    const ctx = crypto.createECDH('prime256v1');
    try {
        ctx.setPrivateKey(privateKey);
    } catch (_) {
        return false;
    }
    return true;
};

const isValidPublicKey = function (publicKey) {
    if (!Buffer.isBuffer(publicKey)) {
        throw new Error('publicKey MUST be a Buffer');
    }
    if (!((publicKey.length === 65 && publicKey[0] === 0x04) ||
          (publicKey.length === 33 && publicKey[0] === 0x02) ||
          (publicKey.length === 33 && publicKey[0] === 0x03))) {
        return false;
    }
    const one = Buffer.alloc(32, 0x00);  one[31] = 1;
    const ctx = crypto.createECDH('prime256v1');
    ctx.setPrivateKey(one);
    try {
        ctx.computeSecret(publicKey);
    } catch (_) {
        return false;
    }
    return true;
};

const pemEncode = function (buf, tag) {
    const lines = buf.toString('base64').match(/.{1,64}/g);
    lines.unshift('-----BEGIN ' + tag + '-----');
    lines.push('-----END ' + tag + '-----');
    lines.push('');
    return lines.join('\n');
};

const publicKeyToPemFormat = function (publicKey) {
    if (!(Buffer.isBuffer(publicKey) && publicKey.length === 65)) {
        throw new Error('publicKey MUST be a Buffer of length 65');
    }
    const part1 = Buffer.from(
        '3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');
    const publicKeyInfo = Buffer.concat([part1, publicKey]);
    return pemEncode(publicKeyInfo, 'PUBLIC KEY');
};

const privateKeyToPublicKey = function (privateKey) {
    if (!Buffer.isBuffer(privateKey)) {
        throw new Error('privateKey MUST be a Buffer');
    }
    if (!isValidPrivateKey(privateKey)) {
        throw new Error('invalid privateKey');
    }
    return crypto
        .createECDH('prime256v1')
        .setPrivateKey(privateKey)
        .getPublicKey();
};

const privateKeyToPemFormat = function (privateKey) {
    const publicKey = privateKeyToPublicKey(privateKey);
    const part1 = Buffer.from('30770201010420', 'hex');
    const part2 = Buffer.from('a00a06082a8648ce3d030107a144034200', 'hex');
    const keyPair = Buffer.concat([part1, privateKey, part2, publicKey]);
    return pemEncode(keyPair, 'EC PRIVATE KEY');
};

const sign = function (privateKey, msg) {
    if (!Buffer.isBuffer(msg)) {
        throw new Error('msg MUST be a Buffer');
    }
    const privateKeyInPemFormat = privateKeyToPemFormat(privateKey);
    return crypto
        .createSign('sha256')
        .update(msg)
        .sign(privateKeyInPemFormat);
};

const verify = function (publicKey, msg, signature) {
    if (!Buffer.isBuffer(msg)) {
        throw new Error('msg MUST be a Buffer');
    }
    if (!Buffer.isBuffer(signature)) {
        throw new Error('signature MUST be a Buffer');
    }
    const publicKeyInPemFormat = publicKeyToPemFormat(publicKey);
    return crypto
        .createVerify('sha256')
        .update(msg)
        .verify(publicKeyInPemFormat, signature);
};

const mypbkdf2 = function (salt, password) {
    if (!(Buffer.isBuffer(salt) && salt.length >= 32)) {
        throw new Error('salt MUST be a Buffer of length >= 32');
    }
    try { asciiPrintableDecode(password); } catch (_) {
        throw new Error('password MUST be an ASCII Buffer');
    }
    try {
        return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
    } catch (_) {
        throw new Error('an exception is thrown during crypto.pbkdf2Sync()');
    }
};

const rfc6979sha256p256csprng = function* (entropy) {
    if (!Buffer.isBuffer(entropy)) {
        throw new Error('entropy MUST be a Buffer');
    }
    const _0x01_ = Buffer.alloc(1, 0x01);
    const _0x00_ = Buffer.alloc(1, 0x00);
    let V = Buffer.alloc(32, 0x01);
    let K = Buffer.alloc(32, 0x00);
    K = hmacsha256(K, Buffer.concat([V, _0x00_, entropy]));
    V = hmacsha256(K, V);
    K = hmacsha256(K, Buffer.concat([V, _0x01_, entropy]));
    V = hmacsha256(K, V);
    for (;;) {
        const T = hmacsha256(K, V);
        if (isValidPrivateKey(T)) {
            yield T;
        }
        K = hmacsha256(K, Buffer.concat([V, _0x00_]));
        V = hmacsha256(K, V)
    }
};

const sha256 = function (msg) {
    if (!Buffer.isBuffer(msg)) {
        throw new Error('msg MUST be a Buffer');
    }
    return crypto.createHash('sha256').update(msg).digest();
};

const hmacsha256 = function (key, msg) {
    if (!Buffer.isBuffer(key)) {
        throw new Error('key MUST be a Buffer');
    }
    if (!Buffer.isBuffer(msg)) {
        throw new Error('msg MUST be a Buffer');
    }
    return crypto.createHmac('sha256', key).update(msg).digest();
};

const hexEncode = function (buf) {
    /* Buffer -> String */
    if (!Buffer.isBuffer(buf)) {
        throw new Error('buf MUST be a Buffer');
    }
    return buf.toString('hex');
};

const hexDecode = function (str) {
    /* String -> Buffer */
    if (typeof str !== 'string') {
        throw new Error('input MUST be a String');
    }
    if (!/^([0-9a-f]{2})*$/.test(str)) {
        throw new Error('input MUST be a valid hex encoded result');
    }
    return Buffer.from(str, 'hex');
};

const websafeBase64Encode = function (buf) {
    /* Buffer -> String */
    if (!Buffer.isBuffer(buf)) {
        throw new Error('buf MUST be a Buffer');
    }
    return buf.toString('base64')
              .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};

const websafeBase64Decode = function (str) {
    /* String -> Buffer */
    if (typeof str !== 'string') {
        throw new Error('input MUST be a String');
    }
    if (!
/^([A-Za-z0-9_-]{4})*([A-Za-z0-9_-][AQgw]|[A-Za-z0-9_-]{2}[AEIMQUYcgkosw048])?$/
    .test(str)) {
        throw new Error('input MUST be a valid websafe-base64 encoded result');
    }
    return Buffer.from(str, 'base64');
};

const asciiPrintableEncode = function (str) {
    /* String -> Buffer */
    if (typeof str !== 'string') {
        throw new Error('input MUST be a String');
    }
    for (let i = 0; i < str.length; ++i) {
        const c = str.charCodeAt(i);
        if (c < 32 || c > 126) {
            throw new Error('input MUST be a valid ASCII printable string');
        }
    }
    return Buffer.from(str);
};

const asciiPrintableDecode = function (buf) {
    /* Buffer -> String */
    if (!Buffer.isBuffer(buf)) {
        throw new Error('buf MUST be a Buffer');
    }
    for (let c of buf) {
        if (c < 32 || c > 126) {
            throw new Error('input MUST be a valid ASCII encoded string');
        }
    }
    return buf.toString();
};

const jsonEncode = function (val) {
    /* ? -> String */
    let result;
    try {
        result = JSON.stringify(val);
    } catch (_) {
        throw new Error('input is not JSON serializable');
    }
    if (typeof result !== 'string') {
        throw new Error('input is not JSON serializable');
    }
    return result;
};

const jsonDecode = function (str) {
    /* String -> ? */
    if (typeof str !== 'string') {
        throw new Error('input MUST be a String');
    }
    try {
        return JSON.parse(str);
    } catch (_) {
        throw new Error('input is not a valid JSON string');
    }
};

const x509Encode = function (publicKey) {
    if (!isValidPublicKey(publicKey)) {
        throw new Error('publicKey is invalid');
    }
    if (publicKey.length !== 65) {
        throw new Error('publicKey MUST be in uncompressed format');
    }
    const part1 = Buffer.from(
        '3081d73081bda003020102020100300a06082a8648ce3d040302301c311a3018' +
        '06035504030c114e6f205375636820417574686f72697479301e170d31363031' +
        '30313030303030305a170d3336303130313030303030305a300e310c300a0603' +
        '5504030c037632663059301306072a8648ce3d020106082a8648ce3d03010703' +
        '4200', 'hex');
    const part2 = Buffer.from(
        '300a06082a8648ce3d0403020309003006020103020101', 'hex');
    return Buffer.concat([part1, publicKey, part2]);
};

const x509Decode = function (certificate) {
    // TODO refactor to have better exception handling
    if (!Buffer.isBuffer(certificate)) {
        throw new Error('certificate MUST be a Buffer');
    }
    let _, tbscert, pkinfo, alg, pkbits, P256PUBKEY, Q;
    [tbscert, _, _] = DER_decode_one_SEQUENCE(certificate);
    [_, _, _, _, _, _, pkinfo, ..._] = DER_decode_one_SEQUENCE(tbscert);
    [alg, pkbits] = DER_decode_one_SEQUENCE(pkinfo);
    P256PUBKEY = Buffer.from(
        '301306072a8648ce3d020106082a8648ce3d030107', 'hex');
    if (!(
        Buffer.compare(alg, P256PUBKEY) === 0 &&
        Buffer.compare(pkbits.slice(0, 3), Buffer.from('034200', 'hex')) === 0
    )) {
        throw new Error('invalid certificate');
    }
    let publicKey = pkbits.slice(3);
    if (!isValidPublicKey(publicKey)) {
        throw new Error('invalid certificate');
    }
    return publicKey;
};

const DER_decode_one_SEQUENCE = function (octets) {
    let [T, L, V, tail] = DER_decode_one_something(octets);
    if (Buffer.compare(T, Buffer.from('30', 'hex')) !== 0 || tail.length > 0) {
        throw new Error('invalid SEQUENCE');
    }
    let elms = [];
    tail = V;
    while (tail.length > 0) {
        [T, L, V, tail] = DER_decode_one_something(tail);
        elms.push(Buffer.concat([T, L, V]));
    }
    return elms;
};

const DER_decode_one_something = function (octets) {
    const [T, tail1] = DER_extract_identifier_octets(octets);
    const [L, tail2] = DER_extract_length_octets(tail1);
    const V_length = DER_decode_length_octets(L);
    const [V, tail3] = [tail2.slice(0, V_length), tail2.slice(V_length)];
    return [T, L, V, tail3];
};

const DER_extract_identifier_octets = function (stream) {
    // TODO consider the situation where identifier octets contain more octets
    return [stream.slice(0, 1), stream.slice(1)];
};

const DER_extract_length_octets = function (stream) {
    try {
        assert(stream.length >= 1);
        if (stream[0] >> 7 === 0) {
            return [stream.slice(0, 1), stream.slice(1)];
        } else {
            const l = stream[0] & 0b01111111;
            assert(1 <= l && l <= 126);
            assert(stream.length >= l + 1);
            assert((l === 1 && stream[1] >= 128) || (l > 1 && stream[1] != 0));
            return [stream.slice(0, l + 1), stream.slice(l + 1)];
        }
    } catch (_) {
        throw new Error('invalid DER length octets');
    }
};

const DER_decode_length_octets = function (length_octets) {
    if (length_octets[0] < 128) {
        return length_octets[0];
    }

    length_octets = length_octets.slice(1);

    if (length_octets.length > 3) {
        throw new Error('invalid DER length octets');  // TODO
    }

    let ret = 0;
    for (let i = 0; i < length_octets.length; ++i) {
        ret = (ret << 8) | length_octets[i];
    }
    return ret;
};

module.exports.generatePrivateKey      = generatePrivateKey;
module.exports.isValidPrivateKey       = isValidPrivateKey;
module.exports.isValidPublicKey        = isValidPublicKey;
module.exports.pemEncode               = pemEncode;
module.exports.publicKeyToPemFormat    = publicKeyToPemFormat;
module.exports.privateKeyToPublicKey   = privateKeyToPublicKey;
module.exports.privateKeyToPemFormat   = privateKeyToPemFormat;
module.exports.sign                    = sign;
module.exports.verify                  = verify;
module.exports.mypbkdf2                = mypbkdf2;
module.exports.rfc6979sha256p256csprng = rfc6979sha256p256csprng;
module.exports.sha256                  = sha256;
module.exports.hmacsha256              = hmacsha256;
module.exports.hexEncode               = hexEncode;
module.exports.hexDecode               = hexDecode;
module.exports.websafeBase64Encode     = websafeBase64Encode;
module.exports.websafeBase64Decode     = websafeBase64Decode;
module.exports.asciiPrintableEncode    = asciiPrintableEncode;
module.exports.asciiPrintableDecode    = asciiPrintableDecode;
module.exports.jsonEncode              = jsonEncode;
module.exports.jsonDecode              = jsonDecode;
module.exports.x509Encode              = x509Encode;
module.exports.x509Decode              = x509Decode;
module.exports.DER_decode_one_something = DER_decode_one_something;
