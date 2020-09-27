
// fixme listener example for assignment result
browser.webRequest.onCompleted.addListener(
    function (e) {
        for (var header of e.responseHeaders) {
            console.log(header)
        }
    },
    {
        urls: [
            'http://jfto75nya3lupyjq.onion/assign_init/'
        ],
        types: [
            'main_frame'
        ]
    },
    ["responseHeaders"]
);


// fixme listener example for proxy payment
browser.webRequest.onBeforeSendHeaders.addListener(
    function (e) {
        console.log(e);
        e.requestHeaders.push({"name":"Hebtor-Session-Id","value":"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDqQ3C0pP6n10OKeTuRuqXzhHpElaPRExrcnGbtnR9GBl3tr/cuO1ML3aRBK/o/ECZjFWvhHFSf6MbZQzUEG664="});
        e.requestHeaders.push({"name":"Hebtor-Hidden-Address","value":"kcht6av2syzhyyw2.onion"});
        e.requestHeaders.push({"name":"Hebtor-Signature","value":"a30dcc80a36c23275cb8476f5413abecacee6453c47ade20bec419f78cfcae8d2276c8d7a34ebf511312e7d619cb4a1dce1b22022f6e410901794e26d8b32f6c"});
        for (var header of e.requestHeaders) {
            console.log(header);
        }
        return {
            requestHeaders : e.requestHeaders
        };
    },
    {
        urls: ['http://kcht6av2syzhyyw2.onion/'],
        types: ['main_frame']
    },
    ["blocking", "requestHeaders"]
);



// fixme listener example for proxy payment
browser.webRequest.onCompleted.addListener(
    function (e) {
        console.log("++++++++++++++++++++++++++");
        for (var header of e.responseHeaders) {
            console.log(header)
        }
    },
    {
        urls: [
            'http://kcht6av2syzhyyw2.onion/'
        ],
        types: [
            'main_frame'
        ]
    },
    ["responseHeaders"]
);



