crossorigin="anonymous";

function clear_settings(){
    window.hebtor = {
        active_hosts:[],
        not_active_hosts: [],
        local_relay_connected: false,
        local_relay_config: undefined,
        about_to_jump_dict: {},
        next_session: undefined,
        broker_host: undefined,
        sessions: {},
        tickets_to_sign : undefined,
        next_ticket_serial: undefined,
        next_ticket_signature: undefined,
        urls_measured:[], //fixme
    };
}



function onError(error) {
    console.log(`Error: ${error}`);
}


function jumpToNewTab(target_url) {
    return chrome.tabs.create({
        url: target_url
    });
}

function arr_diff(a1, a2) {
    let a = [], diff = [];

    for (let i = 0; i < a1.length; i++) {
        a[a1[i]] = true;
    }

    for (let i = 0; i < a2.length; i++) {
        if (a[a2[i]]) {
            delete a[a2[i]];
        } else {
            a[a2[i]] = true;
        }
    }

    for (let k in a) {
        if(a.hasOwnProperty(k)){
            diff.push(k);
        }
    }
    return diff;
}


function domain_is(candidate_host, target_host) {
    let remain_len = candidate_host.length;
    let result = false;
    while (remain_len > 0) {
        if (candidate_host === target_host) {
            result = true;
            break;
        } else {
            let res = candidate_host.split(".");
            res.shift();
            candidate_host = res.join(".");
            remain_len = candidate_host.length;
        }
    }
    return result;
}


function listener_switch_proxy_for_requests(request) {
    /**
     * @param {{
     *      relay_config:{
     *          EnablePerTabPerHostInstance: boolean
     *      },
     *  }
     * } window.hebtor
     */
    //console.log(request.tabId);
    let hostname_to_test = new URL(request.url).hostname;
    if (hostname_to_test === "eebt.extension.close") {
        chrome.tabs.query({active: true, currentWindow: true}, function (tabs) {
            let currTab = tabs[0];
            if (currTab) {
                chrome.tabs.remove(currTab.id);
            }
        });
    }
    for (let i in window.hebtor.active_hosts) {
        if (window.hebtor.active_hosts.hasOwnProperty(i)){
            if (window.hebtor.relay_config.EnablePerTabPerHostInstance) {
                let host_with_tab_id = window.hebtor.active_hosts[i].split("/");
                let hostname = host_with_tab_id[0];
                let tab_id = Number(host_with_tab_id[1]);
                if (tab_id === request.tabId) {
                    if (domain_is(hostname_to_test, hostname)) {
                        console.log({"cmd": "session_measurement", "hostname":window.hebtor.active_hosts[i], "total_cnt":1, "failure_cnt": 0});
                        conn.send(JSON.stringify({"cmd": "session_measurement", "hostname":window.hebtor.active_hosts[i], "total_cnt":1, "failure_cnt": 0}));
                        return {
                            "type": "socks",
                            "host": "127.0.0.1",
                            "port": "12345",
                            "username": request.tabId.toString(),
                            "password": request.tabId.toString(),
                            "proxyDNS": true,
                            "failoverTimeout": 10
                        }
                    }
                }
            } else {
                if (domain_is(hostname_to_test, window.hebtor.active_hosts[i])) {
                    window.hebtor.urls_measured.push({"url": request.url.toString(), "hostname": window.hebtor.active_hosts[i]});
                    console.log({"cmd": "session_measurement", "hostname":window.hebtor.active_hosts[i], "total_cnt":1, "failure_cnt": 0});
                    conn.send(JSON.stringify({"cmd": "session_measurement", "hostname":window.hebtor.active_hosts[i], "total_cnt":1, "failure_cnt": 0}));
                    return {
                        "type": "socks",
                        "host": "127.0.0.1",
                        "port": "12345",
                        "username": window.hebtor.sessions[window.hebtor.active_hosts[i]].credential.user,
                        "password": window.hebtor.sessions[window.hebtor.active_hosts[i]].credential.passwd,
                        "proxyDNS": true,
                        "failoverTimeout": 10
                    }
                }
            }
        }
    }
    for (let i in window.hebtor.not_active_hosts) {
        if (window.hebtor.not_active_hosts.hasOwnProperty(i)){
            if (domain_is(hostname_to_test, window.hebtor.not_active_hosts[i])) {
                chrome.tabs.query({active: true, currentWindow: true}, function (tabs) {
                    let currTab = tabs[0];
                    if (currTab) {
                        window.conn.send(JSON.stringify({"cmd": "newnym"}));
                        window.conn.send(JSON.stringify({"cmd": "get_ticket"}));
                        console.log(JSON.stringify({"cmd": "newnym"}));
                        window.conn.send(JSON.stringify({"cmd": "new_session", "host": window.hebtor.not_active_hosts[i]}));
                        let server_auth_url = "http://127.0.0.1:12346/prepare";
                        if (window.hebtor.relay_config.EnablePerTabPerHostInstance) {
                            if (request.tabId === -1) {
                                let hostname_to_test = new URL(request.url).hostname + "/-1";
                                if (!(hostname_to_test in window.hebtor.about_to_jump_dict)) {
                                    jumpToNewTab(server_auth_url + "?url=" + request.url + "?tab_id=" + request.tabId);
                                    window.hebtor.about_to_jump_dict.hostname_to_test = true;
                                }
                            } else {
                                chrome.tabs.update({url: server_auth_url + "?url=" + request.url + "?tab_id=" + request.tabId});
                            }
                        } else {
                            chrome.tabs.update({url: server_auth_url + "?url=" + request.url});
                        }
                    }
                });
            }
        }

    }

    return {"type": "direct"};
}

function listener_failed_requests(request){
    let req_url = request.url.toString();
    for (let i in window.hebtor.urls_measured) {
        if (window.hebtor.urls_measured.hasOwnProperty(i)) {
            if (i.url === req_url) {
                console.log({"cmd": "session_measurement", "hostname":i.hostname, "total_cnt":0, "failure_cnt": 1});
                conn.send(JSON.stringify({"cmd": "session_measurement", "hostname":i.hostname, "total_cnt":0, "failure_cnt": 1}));
                break;
            }
        }
    }
}

browser.proxy.onRequest.addListener(listener_switch_proxy_for_requests, {"urls": ["<all_urls>"]});
browser.webRequest.onErrorOccurred.addListener(listener_failed_requests, {"urls": ["<all_urls>"]});
// Log any errors from the proxy script
browser.proxy.onError.addListener(error => {
    console.error(`Proxy error: ${error.message}`);
});


function inject_headers_towards_broker(e) {
    /**
     * @param {{session_id:string, signature:string}} window.hebtor.next_session.assignment_request
     */

    console.log("Injecting headers");
    e.requestHeaders.push({"name": "Hebtor-Session-Id", "value": window.hebtor.next_session.assignment_request.session_id});
    e.requestHeaders.push({"name": "Hebtor-Signature", "value": window.hebtor.next_session.assignment_request.signature});

    if (e.method === "GET"){
        if (window.hebtor.next_ticket_serial !== undefined){
            e.requestHeaders.push({"name": "Hebtor-Ticket-Serial", "value": window.hebtor.next_ticket_serial});
            e.requestHeaders.push({"name": "Hebtor-Ticket-Signature", "value": window.hebtor.next_ticket_signature});
            window.hebtor.next_ticket_serial = undefined;
            window.hebtor.next_ticket_signature = undefined;
        }
    }
    else if (e.method === "POST"){
        if (window.hebtor.tickets_to_sign !== undefined){
            // todo, change this.
            e.requestHeaders.push({"name": "Hebtor-Ticket-To-Sign0", "value": window.hebtor.tickets_to_sign[0]});
            e.requestHeaders.push({"name": "Hebtor-Ticket-To-Sign1", "value": window.hebtor.tickets_to_sign[1]});
            e.requestHeaders.push({"name": "Hebtor-Ticket-To-Sign2", "value": window.hebtor.tickets_to_sign[2]});
            e.requestHeaders.push({"name": "Hebtor-Ticket-To-Sign3", "value": window.hebtor.tickets_to_sign[3]});
            e.requestHeaders.push({"name": "Hebtor-Ticket-To-Sign4", "value": window.hebtor.tickets_to_sign[4]});
            e.requestHeaders.push({"name": "Hebtor-Ticket-To-Sign5", "value": window.hebtor.tickets_to_sign[5]});
            e.requestHeaders.push({"name": "Hebtor-Ticket-To-Sign6", "value": window.hebtor.tickets_to_sign[6]});
            e.requestHeaders.push({"name": "Hebtor-Ticket-To-Sign7", "value": window.hebtor.tickets_to_sign[7]});
            e.requestHeaders.push({"name": "Hebtor-Ticket-To-Sign8", "value": window.hebtor.tickets_to_sign[8]});
            e.requestHeaders.push({"name": "Hebtor-Ticket-To-Sign9", "value": window.hebtor.tickets_to_sign[9]});
        }
    }
    for (let header of e.requestHeaders) {
        console.log(header);
    }
    return {
        requestHeaders: e.requestHeaders
    };
}

function inject_headers_towards_proxy(e) {
    console.log("Injecting headers toward proxy");
    e.requestHeaders.push({"name": "Hebtor-Session-Id", "value": window.hebtor.next_session.poa.session_id});
    e.requestHeaders.push({"name": "Hebtor-Hidden-Address", "value": window.hebtor.next_session.poa.hidden_address});
    e.requestHeaders.push({"name": "Hebtor-Payment-Token", "value": window.hebtor.next_session.poa.payment_token});
    e.requestHeaders.push({"name": "Hebtor-Proof-Of-Assignment", "value": window.hebtor.next_session.poa.poa_signature});
    for (let header of e.requestHeaders) {
        console.log(header);
    }
    return {
        requestHeaders: e.requestHeaders
    };
}


function retrieve_poa_from_broker_response(e) {
    console.log(e);
    let poa = {};
    for (let header of e.responseHeaders) {
        if (header.name === "Hebtor-Session-Id") {
            poa["session_id"] = header.value;
        }
        if (header.name === "Hebtor-Hidden-Address") {
            poa["hidden_address"] = header.value;
        }
        if (header.name === "Hebtor-Payment-Token") {
            poa["payment_token"] = header.value;
        }
        if (header.name === "Hebtor-Proof-Of-Assignment") {
            poa["poa_signature"] = header.value;
        }
        if (header.name === "Hebtor-Ticket-To-Sign0") {
            conn.send(JSON.stringify({"cmd": "signed_ticket", "headers":e.responseHeaders}));
        }
    }
    if (poa.hidden_address === undefined) {
        console.log("###############");
        console.log("no poa");
    } else {
        console.log("###############");
        console.log(poa);
        window.hebtor.next_session.poa = poa;
        if (browser.webRequest.onBeforeSendHeaders.hasListener(inject_headers_towards_proxy)) {
            browser.webRequest.onBeforeSendHeaders.removeListener(inject_headers_towards_proxy);
        }
        browser.webRequest.onBeforeSendHeaders.addListener(
            inject_headers_towards_proxy,
            {
                urls: ["http://" + poa.hidden_address + "/"],
                types: ['main_frame']
            },
            ["blocking", "requestHeaders"]
        );
        browser.webRequest.onBeforeRequest.addListener(
            retrieve_pop_from_proxy_header,
            {
                urls: ["http://" + poa.hidden_address + "/"],
                types: ['main_frame']
            },
            ["blocking", "requestBody"]
        );

        browser.webRequest.onCompleted.addListener(
            retrieve_proxy_info_from_proxy_response,
            {
                urls: ["http://" + poa.hidden_address + "/"],
                types: ['main_frame']
            },
            ["responseHeaders"]
        );

        console.log("before jump to broker");
        chrome.tabs.update({url: "http://" + poa.hidden_address + "/"});
    }
}

function retrieve_pop_from_proxy_header(e) {
    console.log("+++++++++++ POP ++++++++++++++");
    if (e.requestBody == null){
        console.log("No POP found here");
    }
    else {
        console.log(e["requestBody"]["formData"]["h-captcha-response"][0]);
        window.hebtor.next_session.pop.token = e["requestBody"]["formData"]["h-captcha-response"][0]
    }

}

function retrieve_proxy_info_from_proxy_response(e) {
    for (let header of e.responseHeaders) {
        if (header.name === "Hebtor-Proxy-User") {
            window.hebtor.next_session.credential.user = header.value;
        }
        if (header.name === "Hebtor-Proxy-Passwd") {
            window.hebtor.next_session.credential.passwd = header.value;
        }
        if (header.name === "Hebtor-Proxy-View-Key") {
            window.hebtor.next_session.pop.view_key = header.value;
        }
    }
    if (window.hebtor.next_session.credential.user !== null){
        window.conn.send(JSON.stringify({"cmd": "update_session", "session": window.hebtor.next_session}));
        let url = "http://127.0.0.1:12346/?user=" +  window.hebtor.next_session.credential.user + '?pass=' +
                window.hebtor.next_session.credential.passwd + '?host=' + window.hebtor.next_session.poa.hidden_address +
                '?port=1080?type=tcp';
        chrome.tabs.update({url: url});
        if (browser.webRequest.onBeforeSendHeaders.hasListener(inject_headers_towards_proxy)) {
            browser.webRequest.onBeforeSendHeaders.removeListener(inject_headers_towards_proxy);
        }

        if (browser.webRequest.onBeforeRequest.hasListener(retrieve_pop_from_proxy_header)) {
            browser.webRequest.onBeforeRequest.removeListener(retrieve_pop_from_proxy_header);
        }

        if (browser.webRequest.onCompleted.hasListener(retrieve_proxy_info_from_proxy_response)) {
            browser.webRequest.onCompleted.removeListener(retrieve_proxy_info_from_proxy_response);
        }
        window.hebtor.sessions[window.hebtor.next_session.attached_host] = window.hebtor.next_session;
        window.hebtor.next_session = undefined;
    }

}

function submit_pop(pop) {
    console.log(pop);
    //var x = new XMLHttpRequest();
    //x.open("GET","http://" + window.hebtor.broker_host + "/assign_verify/");
    //x.setRequestHeader("Session-Id",pop.session_id);
    //x.setRequestHeader("Pop-Token",pop.token);
    //x.setRequestHeader("View-Key",pop.view_key);
    //x.setRequestHeader("Pop-Signature",pop.signature);
    //x.send();
}

function get_ticket_cb(data) {
    console.log(data);
    if (data.ticket_status === "req"){
        window.hebtor.tickets_to_sign = data.tickets_to_sign;
    }
    else if (data.ticket_status === "ticket"){
        window.hebtor.next_ticket_serial = data.ticket_serial;
        window.hebtor.next_ticket_signature = data.ticket_signature;
    }
}



function start(websocketServerLocation) {
    window.conn = new WebSocket('ws://127.0.0.1:12348');
    conn.onopen = function (e) {
        console.log("Connection established!");
        conn.send(JSON.stringify({"cmd": "sync"}));
    };
    conn.onmessage = function (e) {

        data = JSON.parse(e.data);
        if (data.type === "status") {

            window.hebtor.active_hosts = data.active_hosts;
            window.hebtor.not_active_hosts = data.not_active_hosts;
            window.hebtor.local_relay_connected = true;
            window.about_to_jump_dict = {};
            window.hebtor.relay_config = data.relay_config;
            window.hebtor.broker_host = data.broker_host;
            window.hebtor.urls_measured = [];
            for (let s of data.active_sessions) {
                if (!(s.attached_host in window.hebtor.sessions)){
                    window.hebtor.sessions[s.attached_host] = s;
                }
            }
            if (browser.webRequest.onBeforeSendHeaders.hasListener(inject_headers_towards_broker)) {
                browser.webRequest.onBeforeSendHeaders.removeListener(inject_headers_towards_broker);
            }
            console.log("add listener");
            browser.webRequest.onBeforeSendHeaders.addListener(
                inject_headers_towards_broker,
                {
                    urls: ["http://" + data.broker_host + "/assign_init"],
                    types: ['main_frame']
                },
                ["blocking", "requestHeaders"]
            );
            if (browser.webRequest.onCompleted.hasListener(retrieve_poa_from_broker_response)) {
                browser.webRequest.onCompleted.removeListener(retrieve_poa_from_broker_response);
            }
            browser.webRequest.onCompleted.addListener(
                retrieve_poa_from_broker_response,
                {
                    urls: ["http://" + data.broker_host + "/assign_init"],
                    types: ['main_frame']
                },
                ["responseHeaders"]
            );


        } else if (data.type === "new_session") {
            window.hebtor.next_session = data;
        } else if (data.type === "signed_pop") {
            submit_pop(data);
        } else if (data.type === "get_ticket") {
            get_ticket_cb(data);
        }
    };

    conn.onerror = function (e) {
        console.log(e)
    };

    conn.onclose = function () {
        // Try to reconnect in 5 seconds
        console.log("onclose");
        clear_settings();
        setTimeout(function () {
            start(websocketServerLocation)
        }, 500);
    };
}


clear_settings();
start();
// fixme: listener for broker site should be add when new broker settings appear, old listener should be removed.