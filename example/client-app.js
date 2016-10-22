const {createStore, combineReducers, bindActionCreators, applyMiddleware, compose} = Redux;

//////////////////////////////////////////////////////////////////////////////

const APPID = 'https://localhost:4433';

//////////////////////////////////////////////////////////////////////////////

const example_state = {
    keys: [
        {
            kh: 'IKLSRNMlSdlePuMOpKkcSlk6f3cwQb-FSuDZh9qQXvvs4Ix0VsSn3XSiZbJCWoT9ZMuRtOtQIG44XNz7pojuRg',
            pk: 'BFf5_KoAGt1CajmbdXNrNPap1WoZQPBls9j0hSOTjehm8i2wmi9oaFz0HNRgWqfvUeX3Oe724k0X8TZIL9b-lI0',
            cnt: 19
        },
        {
            kh: 'xVD9M3GoPrUdtRMZEKgWwV6549bl_HGaXNMQGOajZJwc8IdJlHsnMq55j6wpCTHZ4_KvwXsLXsgJ3NKg0oFjrw',
            pk: 'BIAedJqrDgBL-8G1VLkFoiemAE9LzgHdn0K6s1-IU7ekXzWi49dz2VuONd3m-KO-pdJuhsByJWAtSNMczBEA76M',
            cnt: null
        }
    ],
    msg: '',
    current: 'HOME' // HOME | ADD | AUTH
};

const store = createStore((state = {keys:[],msg:'',current:'HOME'}, action) => {

    if (state.current === 'HOME') {
        if (action.type === 'ADD') {
            launch_u2f_add_new_key_process(state.keys);
            return Object.assign({}, state, {current: 'ADD', msg: ''});
        }
        if (action.type === 'AUTH') {
            launch_u2f_auth_process(state.keys);
            return Object.assign({}, state, {current: 'AUTH', msg: ''});
        }
        if (action.type === 'DELETE') {
            return Object.assign({}, state, {keys: [
                ...state.keys.slice(0, action.idx),
                ...state.keys.slice(action.idx+1)
            ], msg: ''});
        }
    }

    if (state.current === 'ADD') {
        if (action.type === 'CANCEL_ADD') {
            return Object.assign({}, state, {
                current: 'HOME',
                msg: action.msg || ''
            });
        }
        if (action.type === 'FINISH_ADD') {
            return Object.assign({}, state, {
                current: 'HOME',
                keys: [...state.keys, action.newkey],
                msg: 'Adding a new key succeeded'
            });
        }
    }

    if (state.current === 'AUTH') {
        if (action.type === 'CANCEL_AUTH') {
            return Object.assign({}, state, {
                current: 'HOME',
                msg: 'Authentication FAILED! (reason: timeout, key invalid, or no key available)'
            });
        }
        if (action.type === 'FINISH_AUTH') {
            return Object.assign({}, state, {
                current: 'HOME',
                msg: 'Authentication succeeded'
            });
        }
    }

    return state;

});

store.subscribe(()=>{
    const s = store.getState();
    console.log(  'now the app state is', JSON.stringify(s)  );

    const root = document.getElementById('root');
    const home = document.getElementById('home');
    const add = document.getElementById('add');
    const auth = document.getElementById('auth');
    const msg = document.getElementById('msg');
    const list = document.getElementById('list');
    const howMany = document.getElementById('how-many');

    home.style.display = add.style.display = auth.style.display = 'none';
    if (s.current === 'HOME') home.style.display = 'block';
    if (s.current === 'ADD')  add.style.display = 'block';
    if (s.current === 'AUTH') auth.style.display = 'block';

    msg.innerText = s.msg || '';

    howMany.innerText = (l => (
        (l === 0) ? '0 U2F keys' : ((l === 1) ? '1 U2F key' : l+' U2f keys')
    ))(s.keys.length);

        list.innerHTML = s.keys.map((key, idx) => '<li><code>unique id: '+key.kh+'<br>public key: '+key.pk+'</code><br><button onclick="store.dispatch({type:\'DELETE\',idx:'+idx+'})">Delete</button></li>').join('');

    // TODO rendering three pages
    // TODO button events dispatch actions (ADD AUTH DELETE)
});

const launch_u2f_add_new_key_process = (keys) => {
    genNonce(nonce => {
        genRegChall(APPID, nonce, keys.map(key => key.kh), regChall => {
            send_message_to_fido_u2f_client_in_browser(regChall, u2fclient_resp => {
                if (JSON.parse(u2fclient_resp).errorCode) {
                    store.dispatch({ type: 'CANCEL_ADD', msg: 'You did not provide a new key in 10 seconds' });
                } else {
                    procRegResp(APPID, nonce, u2fclient_resp, result=>{
                        result = JSON.parse(result);
                        const newkey = {
                            kh: result.keyHandle,
                            pk: result.publicKey,
                            cnt: null
                        };
                        store.dispatch({ type: 'FINISH_ADD', newkey: newkey });
                    });
                }
            });
        });
    });
};

const launch_u2f_auth_process = (keys) => {
    genNonce(nonce => {
        genAuthChall(APPID, nonce, keys.map(key => [key.kh, key.pk, key.cnt]), authChall => {
            send_message_to_fido_u2f_client_in_browser(authChall, u2fclient_resp => {
                if (JSON.parse(u2fclient_resp).errorCode) {
                    store.dispatch({ type: 'CANCEL_AUTH' });
                } else {
                    procAuthResp(APPID, nonce, u2fclient_resp, result=>{
                        result = JSON.parse(result);
                        if (result.facetid === APPID
                            && keys.filter(k=>(k.kh===result.keyHandle && k.pk===result.publicKey)).length === 1
                            ) {
                            store.dispatch({ type: 'FINISH_AUTH' });
                        } else {
                            store.dispatch({ type: 'CANCEL_AUTH' });
                        }
                    });
                }
            });
        });
    });
};

//////////////////////////////////////////////////////////////////////////////

// 五個 lightu2f.js 的非同步函數呼叫
// 輸出都是 JSON 字串

const genNonce = (callback) => {
    fetch('/genNonce', {method: 'POST'}).then(res => res.text()).then(callback);
};

const genRegChall = (appId, nonce, keyHandles, callback) => {
    const request_json_str = JSON.stringify({appId, nonce, keyHandles});
    fetch('/genRegChall', {method: 'POST', body: request_json_str}).then(res => res.text()).then(callback);
};

const procRegResp = (appId, nonce, response, callback) => {
    const request_json_str = JSON.stringify({appId, nonce, response});
    fetch('/procRegResp', {method: 'POST', body: request_json_str}).then(res => res.text()).then(callback);
};

const genAuthChall = (appId, nonce, tuples, callback) => {
    const request_json_str = JSON.stringify({appId, nonce, tuples});
    fetch('/genAuthChall', {method: 'POST', body: request_json_str}).then(res => res.text()).then(callback);
};

const procAuthResp = (appId, nonce, response, callback) => {
    const request_json_str = JSON.stringify({appId, nonce, response});
    fetch('/procAuthResp', {method: 'POST', body: request_json_str}).then(res => res.text()).then(callback);
};

//////////////////////////////////////////////////////////////////////////////

// 非同步程序
// 輸入: JSON 字串
// 輸出: JSON 字串

const send_message_to_fido_u2f_client_in_browser = (msg, callback) => {
    const ID = 'kmendfapggjehodndflmmgagdbamhnfd';
    const p = chrome.runtime.connect(ID);
    p.onMessage.addListener((response) => {
        callback(JSON.stringify(response.responseData));
        p.disconnect();
    });

    const d = JSON.parse(msg)
    d.timeoutSeconds = 10;
    p.postMessage(d);
};

//////////////////////////////////////////////////////////////////////////////
