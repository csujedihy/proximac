##Proximac


####Overview

Proximac is an open-source alternative to Proxifier. With Proximac, users can force App to use SOCKS5 proxy. I hope more developers can join this project.

Note: Proximac only works on Mac OSX.

##### Major change

User now must specifiy exact process name. We abandon the old way to compare pid to determine whether the process should be hooked since pid is frequently changed due to program restart and will make proximac unable to find specified process.

**process name under the new way**:

```Unibox``` found from the path ```/Applications/Unibox.app/Contents/MacOS/Unibox```

```Google Chrome``` found from the path ```/Applications/Google Chrome.app/Contents/MacOS/Google Chrome```

Binary file in ```Contents/MacOS``` determines the process name.


##### New feature

Now support forcing multiple Apps to use SOCKS5 proxy.



####How to build
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
    ["Unibox", "Google Chrome", "Thunder"], 
    "local_port":1080,
    "local_address":"127.0.0.1",
    "proximac_listen_address":"127.0.0.1",
    "proximac_port":8558
}
```
Note: 

```process_name``` are names of processes that you want to force to use SOCKS5 proxy, which can be found in ```Contents/MacOS``` folder inside those Apps (right click on Apps to get inside).

```local_address``` and ```local_port``` is the ip address and the listen port of your SOCKS5 proxy, respectively. 

leave ```proximac_listen_address``` and ```proximac_port``` alone because these are hardcoded in kext source. 


####References
This software is partly based on projects below.

1. [Shadowsocks-libev](https://github.com/shadowsocks/shadowsocks-libev).
2. [Shadowsocks-libuv](https://github.com/dndx/shadowsocks-libuv).
3. [libuv](https://github.com/libuv/libuv).
2. [js0n](https://github.com/quartzjer/js0n).
3. tcplognke (Apple).

####Contact:
csujedi at icloud dot com