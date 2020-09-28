### Description

This package contains the open-sourced code release corresponding to our paper Ephemeral Exit Bridges for Tor (DSN2020).

### Deploy

1. A running broker as Tor Onion Service is needed. Please refer to [this](https://github.com/GUSecLab/tor-exit-relays/blob/master/eebt/broker/README)
on how to setup a broker.

2. Our demo uses AWS to host exit bridges. Please refer to [aws_instance](https://github.com/GUSecLab/tor-exit-relays/tree/master/eebt/aws_instance) and
[aws_instance_no_mysql](https://github.com/GUSecLab/tor-exit-relays/tree/master/eebt/aws_instance_no_mysql) to create AWS image and setup AWS API on broker.



### Usage (As a TorBrowser User)

1. We recommend to test this demo under Ubuntu, with python3.6.7(say a fresh Ubuntu 18.04 VM), thanks.
 
2. Please download an updated torbrowser, v8.5.1 and upper is recommended.

3. Before first usage, please specify that accessing `127.0.0.1` and `localhost` will not through any proxy on TorBrowser:
please browse `about:preferences`, then go to `Network Proxy -> Settings -> No Proxy for`, and add `127.0.0.1, localhost` 
then press ok.
For any newer version of TorBrowser, you may unable to find this setting, in this case you can browse `about:config` and 
set `network.proxy.allow_hijacking_localhost` to `false`.

4. Before first usage, please install follow dependencies.
```
For ubuntu:
    sudo apt-get install python3 python3-pip tor torsocks
    sudo -H pip3 install pycrypto # in case pycrypto is missing
    sudo service tor restart
    
For OS X:
    # warning: note that if you use a python managed by pyenv, torsocks may not torify you connection.
    # please use a direct installed version of python.
    # install dependencies
    brew install python3
    pip3 install pycrypto
    brew install torsocks
    brew install tor
    brew services start tor
```
    

5. Then you need to start the local relay:


    1. First please uncompress demo.tar.gz: `tar -xvf demo.tar.gz`.
    2. Then specify TBB_auth_cookie_path if you want to connect to broker site with fresh circuit each time.
    ```
        For Ubuntu, this path is:

            '/path/to/tor-browser-linux64-8.0_en-US/tor-browser_en-US/Browser/TorBrowser/Data/Tor/control_auth_cookie'

        For OS X, this path should be( if you are using an updated TBB and installed by dragging into Application folder):

            "~/Library/Application Support/TorBrowser-Data/Tor/control_auth_cookie"

        Please double check the path then paste it as value of "TBBAuthCookiePath" in config.json.
    ```
    3. Then start local relay:
    ```
        please make sure tor is running and listen on port 9050, especially when using OS X, please double check this.

        open a new terminal window,

        cd relay_local/

        torsocks python3 relay_ssl.py

        if everything is correct, you should see such log:
            Guard Sockets(Data/Config): 140692621599656/140692621599560, # Conf Sockets: 0
            ##### Hosts: ##############
            ['usnews.com', 'niche.com']
            ##### Routes: #############
            ###########################
    ````

6. Then please install browser extension:

    start torbrowser, install browser extension `eebt_browser_addon-1.0.0.5-fx.xpi`


7. By default there is a placeholder version of tor-blocking site list(relay_local/block_list.txt), which contains:
```    
    usnews.com
    niche.com
```
   You can popluate it with whatever hosts you need. If you directly modify the list, please restart local relay after
   changes.


8. Now access tor-blocking sites:

    simply type usnews.com into address bar, if no bridge instance is configured, you will be
    redirect to our broker site for instance assignment.

9. If you want to add/delete user-defined blocking site:

    you can manually specify a hostname if you find this site blocks tor, by typing below url into torbrowser
    address bar(we use twitter.com, for example):
    
    http://127.0.0.1:12346/hosts?action=add?hostname=twitter.com
    
    if you want to remove a site from tor-blocking site list, you can do this by typing:
    
    http://127.0.0.1:12346/hosts?action=del?hostname=twitter.com

    this will update relay_local/block_list.txt, too.  
