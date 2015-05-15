##Proximac


####Overview

Proximac is an open-source alternative to Proxifier. With Proximac, users can force App to use SOCKS5 proxy. I hope more developers can join this project.

**New feature**:

Now support forcing multiple Apps to use SOCKS5 proxy.

Note: Proximac only works on Mac OSX.


####How to build:
NOTE: Proximac is based on libuv. So, before compile this project, make sure [libuv](https://github.com/libuv/libuv) was successfully installed:

	$ git clone https://github.com/libuv/libuv.git
	$ cd libuv
	$ sh autogen.sh
	$ ./configure
	$ make install

Then,
 
	$ git clone https://github.com/csujedihy/proximac.git
	$ cd build
	$ cmake ..
	$ make

####Usage
1. Build both kext and user-space program (proximac).
2. Modify the config file to set your proxy info and the name of process to be hooked (See more details below).
3. Run the following commands.

```
  sudo chown -R root:wheel tcplognke.kext
  sudo kextload tcplognke.kext
  sudo ./proximac -c config.conf
```
####Example of configuration file
We use almost the same config file as shadowsocks do but add new arguments.

```
{
    "process_name":
    ["Unibox", "Chrome Canary", "Thunder"], 
    "local_port":1080,
    "local_address":"127.0.0.1",
    "proximac_listen_address":"127.0.0.1",
    "proximac_port":8558
}
```
Note: 

```process_name``` shoule better be the full name outputed from ```ps -e```.

```local_address``` and ```local_port``` is the ip address and the listen port of your SOCKS5 proxy, respectively. 

leave ```proximac_listen_address``` and ```proximac_port``` alone because these are hardcoded in kext source. 


####References
This software is partly based on projects below.

1. [Shadowsocks-libev](https://github.com/shadowsocks/shadowsocks-libev).
2. [js0n](https://github.com/quartzjer/js0n).
3. tcplognke (Apple).

####Contact:
csujedi at icloud dot com