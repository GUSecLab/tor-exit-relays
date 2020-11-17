### Description

This repo corresponds to the [Tor Exit Relay](https://seclab.cs.georgetown.edu/hebtor/) project, 
a project of [Georgetown SecLab](https://seclab.cs.georgetown.edu/).

This project addresses the Tor exit blocking problem, in which websites disallow clients arriving from Tor. 
This problem is a growing and potentially existential threat to the anonymity network. 
We introduce two architectures that provide ephemeral exit bridges for Tor, which are difficult to enumerate 
and block. Our techniques employ a micropayment system that compensates exit bridge operators for their services, 
and a privacy-preserving reputation scheme that prevents freeloading. We show that our exit bridge architectures 
effectively thwart server-side blocking of Tor with little performance overhead.

This repo contains two independent packages, [eebt](https://github.com/GUSecLab/tor-exit-relays/blob/master/eebt) 
and [hebtor](https://github.com/GUSecLab/tor-exit-relays/tree/master/hebtor). To be specific, 
[eebt](https://github.com/GUSecLab/tor-exit-relays/blob/master/eebt) corresponds to our first publication, 
Ephemeral Exit Bridges for Tor (DSN2020), and [hebtor](https://github.com/GUSecLab/tor-exit-relays/tree/master/hebtor) 
corresponds to our second publication, Bypassing Tor Exit Blocking 
with Exit Bridge Onion Services (CCS2020). Both packages are fully open-sourced under [GPLv2 license]().
