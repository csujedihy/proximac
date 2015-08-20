## Proximac


#### Overview

Proximac is an command-line open-source alternative to Proxifier. With Proximac, it can force App to use SOCKS5 proxy. In the other words, it can forward any App's traffic to a certain SOCKS5 proxy. Moreover, Proximac now can forward all network traffic in your system to a proxy which means you may not need a VPN to do this job. I hope more developers can join this project.

Features:

1. Support global traffic forwarding (VPN mode).
2. Support SOCKS5 authentication using username/password.

Note: Proximac only works on Mac OSX.

#### Usage 
1. Install libuv first. Run ```brew install libuv``` or whatever.
2. Run ```curl -fsSL https://raw.githubusercontent.com/proximac-org/proximac-install/master/install.py |python ```
3. Set up your config file which indicates Proximac's work mode (VPN or per-App) and proxy configuration.
4. Run ```proximac start [path of your config file]``` to start Proximac.
5. Run ```proximac stop``` to stop Proximac.

#### How to build from source
NOTE: Proximac is based on libuv. So, before compile this project, make sure [libuv](https://github.com/libuv/libuv) was successfully installed:

	$ git clone https://github.com/libuv/libuv.git
	$ cd libuv
	$ sh autogen.sh
	$ ./configure
	$ make install

Then, open Xcode project file and build it.



#### An example of the config file
We use almost the same config file as shadowsocks do but add new arguments. (**Not in VPN mode**)

```
{
    "process_name":
    ["Unibox", "Google Chrome", "Thunder"], 
    "local_port":1080,
    "local_address":"127.0.0.1",
    "proximac_port":8558,
    "username":"foo",
    "password":"bar"
}
```
Note: 

***process_name*** are names of processes that you want to force to use SOCKS5 proxy, which can be found in ***Contents/MacOS*** folder inside those Apps (right click on Apps to get inside).

***local_address*** and ***local_port*** is the ip address and the listen port of your SOCKS5 proxy, respectively. 

Leave ***proximac_port*** alone because this is now hardcoded in kext source. ***username*** and ***password*** are for SOCKS5 proxy required authentication if needed. If your SOCKS5 proxy does not require authentification, just remove these two lines.

There is another example (**VPN mode**)

```
{
    "local_port":1080,
    "local_address":"127.0.0.1",
    "proximac_port":8558,
    "VPN_mode":1,
    "proxyapp_name":"ShadowsocksX"
}
```
Set ***VPN_mode*** to 1 to enable VPN mode. 
Set ***proxyapp_name*** to your proxy's process name in case network traffic are trapped in a loop or we can call it a white-list but now Proximac only supports one proxy.

#### References
This software is partly based on projects below.

1. [Shadowsocks-libev](https://github.com/shadowsocks/shadowsocks-libev).
2. [Shadowsocks-libuv](https://github.com/dndx/shadowsocks-libuv).
3. [libuv](https://github.com/libuv/libuv).
4. [js0n](https://github.com/quartzjer/js0n).
5. tcplognke (Apple).
6. [drcom4mac](https://code.google.com/p/drcom4mac/) (As my kext dev guide book)

####Contact:
csujedi at icloud dot com