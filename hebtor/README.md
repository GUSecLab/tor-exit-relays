### Description

This package contains the open-sourced code release corresponding to our paper Bypassing Tor Exit Blocking with Exit Bridge Onion Services (CCS2020).

This package contains 3 independent modules, which are broker module, bridge module and user module. 

The broker module contains all source codes needed to operate a "Hebtor service broker". At least one broker is required to maintain hebtor service, 
and the broker information should be somehow "broadcasted" to both bridge operators and users. Please refer 
[this](https://github.com/GUSecLab/tor-exit-relays/blob/master/hebtor/broker/) to setup a working broker.

The bridge module contains source codes of an easy demo to operate a "hebtor bridge". Before registering your bridge you need to know the onion address
of at least one broker service, also you need a [hCaptcha](https://www.hcaptcha.com/) account to receive your payments (for this demo). Please refer 
[this](https://github.com/GUSecLab/tor-exit-relays/tree/master/hebtor/hebtor_proxy) to setup a working bridge.

As a user of Hebtor service, you need to know the onion address of the broker service. You also need to install a TorBrowser 
[addon](https://github.com/GUSecLab/tor-exit-relays/tree/master/hebtor/hebtor_browser_add_on) and run a 
[local relay](https://github.com/GUSecLab/tor-exit-relays/tree/master/hebtor/relay_local). Besides, please make sure your TorBrowser doesn't proxy any 
local traffic (such as 127.0.0.1 and localhost). For the TorBrowser addon, you can just load it as a temporary addon, or compile it through Mozilla extension
workshop [site](https://extensionworkshop.com/documentation/publish/submitting-an-add-on/).


