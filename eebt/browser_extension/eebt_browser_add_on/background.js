
window.active_hosts = [];
window.not_active_hosts = [];
window.local_relay_up = false;
window.broker_host = "";
window.success_assign_uri = "";
window.enable_per_tab_instance = false;
window.about_to_jump_dict = {};

function jumpToNewTab(target_url){
  return chrome.tabs.create({
    url: target_url
  });
}

function arr_diff (a1, a2) {
    var a = [], diff = [];

    for (var i = 0; i < a1.length; i++) {
        a[a1[i]] = true;
    }

    for (var i = 0; i < a2.length; i++) {
        if (a[a2[i]]) {
            delete a[a2[i]];
        } else {
            a[a2[i]] = true;
        }
    }

    for (var k in a) {
        diff.push(k);
    }

    return diff;
}



function domain_is (cand_host, target_host) {
  var remain_len = cand_host.length;
  var result = false;
  while (remain_len > 0) {
    if (cand_host === target_host) {
      result = true;
      break;
    }
    else {
      var res = cand_host.split(".");
      res.shift();
      cand_host = res.join(".");
      remain_len = cand_host.length;
    }
  }
  return result;
}
browser.proxy.onRequest.addListener((request) =>{
    //console.log(request.tabId);
  var hostname_to_test = new URL(request.url).hostname;
  if (hostname_to_test === "eebt.extension.close"){
      chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
          var currTab = tabs[0];
          if (currTab) {
              chrome.tabs.remove(currTab.id);
          }
      });
  }
  for (var i in window.active_hosts) {
      if (window.enable_per_tab_instance){
              var host_with_tab_id = window.active_hosts[i].split("/");
              var hostname = host_with_tab_id[0];
              var tab_id = Number(host_with_tab_id[1]);
              if (tab_id === request.tabId) {
                  if (domain_is(hostname_to_test, hostname)) {
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

      }
      else{
          if (domain_is(hostname_to_test, window.active_hosts[i])) {
            return {
              "type":"socks",
              "host":"127.0.0.1",
              "port":"12345",
              "username":"",
              "password":"",
              "proxyDNS":true,
              "failoverTimeout":10
            }
          }
      }
  }
  for (var i in window.not_active_hosts) {
    if (domain_is(hostname_to_test, window.not_active_hosts[i])) {
        chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        var currTab = tabs[0];
        if (currTab) {
            window.conn.send(JSON.stringify({"cmd":"newnym"}));
            console.log(JSON.stringify({"cmd":"newnym"}));
            var server_auth_url = "http://127.0.0.1:12346/prepare";
            if (window.enable_per_tab_instance) {
                if (request.tabId === -1){
                    var hostname_to_test = new URL(request.url).hostname +"/-1";
                    if (!(hostname_to_test in window.about_to_jump_dict))
                    {
                        jumpToNewTab(server_auth_url + "?url=" + request.url + "?tab_id=" + request.tabId);
                        window.about_to_jump_dict.hostname_to_test = true;
                    }

                }
                else {
                     chrome.tabs.update({ url: server_auth_url + "?url=" + request.url + "?tab_id=" + request.tabId});
                }

            }
            else{
                chrome.tabs.update({ url: server_auth_url + "?url=" + request.url });
            }

        }
        });
    }
  }

  return {"type":"direct"};
  }, {"urls":["<all_urls>"]});

// Log any errors from the proxy script
browser.proxy.onProxyError.addListener(error => {
  console.error(`Proxy error: ${error.message}`);
});


function start(websocketServerLocation){
    window.conn = new WebSocket('ws://127.0.0.1:12348');
    conn.onopen = function(e) {
      console.log("Connection established!");
      conn.send(JSON.stringify({"cmd": "sync"}));
    };
    conn.onmessage = function(e) {
        console.log(e.data);
        states = JSON.parse(e.data);
        console.log(states);
        window.broker_host = states.broker_host;
        window.active_hosts = states.active_hosts;
        window.not_active_hosts = states.not_active_hosts;
        window.local_relay_up = states.local_relay_up;
        window.enable_per_tab_instance = states.enable_per_tab_instance;
        window.about_to_jump_dict = {};
    };

    conn.onerror = function (e) {
        console.log(e)
    };

   conn.onclose = function(){
       // Try to reconnect in 5 seconds
       console.log("onclose");
       window.active_hosts = [];
        window.not_active_hosts = [];
        window.local_relay_up = false;
        window.broker_host = "";
        window.success_assign_uri = "";
        window.enable_per_tab_instance = false;
       setTimeout(function(){start(websocketServerLocation)}, 500);
    };
}

start();




