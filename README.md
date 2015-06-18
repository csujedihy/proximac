##Proximac


####Overview

Proximac is an open-source alternative to Proxifier. With Proximac, users can force App to use SOCKS5 proxy. I hope more developers can join this project.

Features:

1. Support multi processes.
2. Support SOCKS5 authentication using username/password.
2. White list (TODO).

Note: Proximac only works on Mac OSX.

####How to build
NOTE: Proximac is based on libuv. So, before compile this project, make sure [libuv](https://github.com/libuv/libuv) was successfully installed:

	$ git clone https://github.com/libuv/libuv.git
	$ cd libuv
	$ sh autogen.sh
	$ ./configure
	$ make install

Then, open Xcode project file and build it.

####Usage
1. Build both kext and user-space program (proximac).
2. Modify the config file to set your proxy info and the names of processes to be hooked (See more details below).
3. Run the following commands.

**Or,** 

1. Download Zip archive of binary files from [release page](https://github.com/csujedihy/proximac/releases).
2. Extarct files.
2. Run the following commands.


```
  sudo chown -R root:wheel proximac.kext
  sudo kextload proximac.kext
  sudo ./proximac-cli -c config.conf
```
Detailed usage of proximac:

```
  proximac
    -c <config_file> Path of configuration file that is written in JSON
    -d daemon mode
```
####Example of configuration file
We use almost the same config file as shadowsocks do but add new arguments.

```
{
    "process_name":
    ["Unibox", "Google Chrome", "Thunder"], 
    "local_port":1080,
    "local_address":"127.0.0.1",
    "proximac_listen_address":"127.0.0.1",
    "proximac_port":8558,
    "username":"foo",
    "password":"bar"
}
```
Note: 

```process_name``` are names of processes that you want to force to use SOCKS5 proxy, which can be found in ```Contents/MacOS``` folder inside those Apps (right click on Apps to get inside).
```local_address``` and ```local_port``` is the ip address and the listen port of your SOCKS5 proxy, respectively. 
Leave ```proximac_listen_address``` and ```proximac_port``` alone because these are hardcoded in kext source unless you know what you are doing. ```username```and```password```are for SOCKS5 proxy required authentication. 


####References
This software is partly based on projects below.

1. [Shadowsocks-libev](https://github.com/shadowsocks/shadowsocks-libev).
2. [Shadowsocks-libuv](https://github.com/dndx/shadowsocks-libuv).
3. [libuv](https://github.com/libuv/libuv).
4. [js0n](https://github.com/quartzjer/js0n).
5. tcplognke (Apple).
6. [drcom4mac](https://code.google.com/p/drcom4mac/) (As my kext dev guide book)

####Contact:
csujedi at icloud dot com