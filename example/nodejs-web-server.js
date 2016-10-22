#!/usr/bin/env node

const crypto = require('crypto');
const fs = require('fs');
const https = require('https');

const lightu2f = require('../lightu2f');
const u2fcrypto = require('../u2fcrypto');

const TLS_CERTIFICATE =
    [ '-----BEGIN CERTIFICATE-----'
    , 'MIIBUDCB9qADAgECAgEAMAoGCCqGSM49BAMCMBkxFzAVBgNVBAMMDmludGVybWVk'
    , 'aWF0ZWNhMB4XDTE2MTAyMTIwMDUwOFoXDTE2MTIyMDIwMDUwOFowFDESMBAGA1UE'
    , 'AwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPu2tD3nAcv4B'
    , 'HD41iSYNOHZP3FW05t4BsidqjUVwkpeZ19449U0jcqjFDw7dVjQ8k96DvF7Innr6'
    , 'PUqKM9SLeqM0MDIwMAYDVR0RBCkwJ4IJbG9jYWxob3N0ggtleGFtcGxlLmNvbYIN'
    , 'Ki5leGFtcGxlLmNvbTAKBggqhkjOPQQDAgNJADBGAiEAjbUfGjPDXg799LP6AEv3'
    , 'P2TVLGmVGjtUsP6mm0taUBMCIQC29FvSzS1jMi8s/mtU1/8EJOj8Jj60qX6vHQjA'
    , 'sdm0OA=='
    , '-----END CERTIFICATE-----'
    ].join('\n');

const TLS_PRIVATE_KEY =
    [ '-----BEGIN EC PARAMETERS-----'
    , 'BggqhkjOPQMBBw=='
    , '-----END EC PARAMETERS-----'
    , '-----BEGIN EC PRIVATE KEY-----'
    , 'MHcCAQEEIJmwh+eH+dGBYV+oj+r/I+KozcmMGuOZ3xcHxblL7fM2oAoGCCqGSM49'
    , 'AwEHoUQDQgAEPu2tD3nAcv4BHD41iSYNOHZP3FW05t4BsidqjUVwkpeZ19449U0j'
    , 'cqjFDw7dVjQ8k96DvF7Innr6PUqKM9SLeg=='
    , '-----END EC PRIVATE KEY-----'
    ].join('\n');

const HTTPS_OPTIONS = { key: TLS_PRIVATE_KEY, cert: TLS_CERTIFICATE };

https.createServer(HTTPS_OPTIONS, (req, res) => {
    const method = req.method;
    const url = req.url;
    const headers = req.headers;
    let body = Buffer.alloc(0);

    req.on('data', (chunk) => {
        body = Buffer.concat([body, chunk]);
    });

    req.on('end', () => {
        responseToAnHttpRequest(method, url, headers, body, res);
    });
}).listen(4433, () => {
    console.log('https://localhost:4433/');
});

const responseToAnHttpRequest = (method, url, headers, body, res) => {
    if (method === 'GET' && url === '/') {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.write(fs.readFileSync(__dirname + '/index.html'));
        res.end();
    } else if (method === 'GET' && url === '/client-app.js') {
        res.setHeader('Content-Type', 'text/javascript; charset=utf-8');
        res.write(fs.readFileSync(__dirname + '/client-app.js'));
        res.end();
    } else if (method === 'GET' && url === '/redux.js') {
        res.setHeader('Content-Type', 'text/javascript; charset=utf-8');
        res.write(fs.readFileSync(__dirname + '/redux.js'));
        res.end();
    } else if (method === 'POST' && url === '/genNonce') {
        res.setHeader('Content-Type', 'application/json');
        res.end(Buffer.from(
            rpc_server_genNonce()
        ));
    } else if (method === 'POST' && url === '/genRegChall') {
        const request_json_str = body.toString();
        res.setHeader('Content-Type', 'application/json');
        res.end(Buffer.from(
            rpc_server_genRegChall(request_json_str)
        ));
    } else if (method === 'POST' && url === '/procRegResp') {
        const request_json_str = body.toString();
        res.setHeader('Content-Type', 'application/json');
        res.end(Buffer.from(
            JSON.stringify(
            rpc_server_procRegResp(request_json_str)
            )
        ));
    } else if (method === 'POST' && url === '/genAuthChall') {
        const request_json_str = body.toString();
        res.setHeader('Content-Type', 'application/json');
        res.end(Buffer.from(
            rpc_server_genAuthChall(request_json_str)
        ));
    } else if (method === 'POST' && url === '/procAuthResp') {
        const request_json_str = body.toString();
        res.setHeader('Content-Type', 'application/json');
        res.end(Buffer.from(
            JSON.stringify(
            rpc_server_procAuthResp(request_json_str)
            )
        ));
    } else {
        res.statusCode = 404;
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.write(Buffer.from('404\n'));
        res.end();
    }
};




//////////////////////////////////////////////////////////////////////////////

const jsonDecode = u2fcrypto.jsonDecode;
const jsonEncode = u2fcrypto.jsonEncode;
const genRegChall  = lightu2f.genRegChall;
const procRegResp  = lightu2f.procRegResp;
const genAuthChall = lightu2f.genAuthChall;
const procAuthResp = lightu2f.procAuthResp;

const rpc_server_genNonce = () => {
    return u2fcrypto.websafeBase64Encode(crypto.randomBytes(32));
};

const rpc_server_genRegChall = (request) => {
    const {appId, nonce, keyHandles} = jsonDecode(request);
    return genRegChall(appId, nonce, keyHandles);
};

const rpc_server_procRegResp = (request) => {
    const {appId, nonce, response} = jsonDecode(request);
    return procRegResp(appId, nonce, response);
};

const rpc_server_genAuthChall = (request) => {
    const {appId, nonce, tuples} = jsonDecode(request);
    return genAuthChall(appId, nonce, tuples);
};

const rpc_server_procAuthResp = (request) => {
    const {appId, nonce, response} = jsonDecode(request);
    return procAuthResp(appId, nonce, response);
};

//////////////////////////////////////////////////////////////////////////////
