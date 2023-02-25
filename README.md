# ieee1905d

[ieee1905d] (https://dev.iopsys.eu/iopsys/ieee1905.git)

## Introduction

This package implements the IEEE Std 1905.1.

It provides the following software components -

- `libieee1905.so` (shared library for 1905 TLVs and CMDU generation functions)
- `libmidgen.so` (shared library for generating message-ids for 1905 CMDUs)
- `ieee1905d` (daemon implementing the 1905 stack and provides CLI through UBUS)


Additionally, the package also provides the following 1905 extension plugins -
- `map.so` (shared library for Multi-AP Easymesh R2)
- `snoop.so` (dump all received 1905 CMUDs over UBUS, mainly for debugging)


## ieee1905d command line options

````bash
   -h               usage
   -s <socket path> ubus socket
   -D               run as a daemon
   -c <conf-file>   specify configuration file
   -d               debug level; more 'd's mean more verbose
   -p <pidfile>     pid file path
   -o <file>        log to file
   -f               treat above file as fifo for rolling logs
````


### UCI Configuration

An example UCI configuration file for ieee1905 with Multi-AP 'map' extension enabled and supporting WSC Registrar in 2.4 and 5 GHz band:

````bash
config ieee1905 'ieee1905'
        option enabled '1'
        option extension '1'
	list extmodule 'map'
        option macaddress 'aa:aa:aa:10:20:30'
        option registrar '2 5'

config ap
        option band '2'
        option ssid 'TestSSID.2'
        option encryption 'psk2'
        option key '1234567890'

config ap
        option band '5'
        option ssid 'TestSSID.5'
        option encryption 'psk2'
        option key '1234567890'

config al-iface
        option enabled 1
        option ifname 'br-lan'
        option type 'bridge'
````

Section | Name | Type | Required | Default | Description
--------|------|------|----------|---------|-------------
ieee1905 | - | - | - | - | - |
 "       |enabled | boolean | yes | 1 | When set to 0, disables the 1905 stack|
 "       |extension | boolean | no | 0 | When set to 1, allows extension of the 1905 stack through plugins |
 "       |extmodule | string | no | 0 | Specifies name of the extension plugin to lookup, load and start. Example plugin are 'map', 'snoop'. |
 "       |macaddress | MAC address | no | auto | Specifies the 1905 AL macaddress. This can be set to any valid locally administered macaddress or 'auto' for a randomly generated one. |
 "       |registrar | list | no | (none) | List of frequency bands for which the 1905 in this device can act as a WSC Registrar. Possible values are: 2, 5. |
al-iface | - | - | - | - | - |
 "       | ifname | string | no | | Specifies the name of the interface that will be part of the 1905 AL. If _type_ = 'bridge', then all interfaces within _ifname_ will be part of the 1905 AL. |
 "       | type | string | no | (autodetected) | Specifies the type of the interface specified in _ifname_. Only 'bridge' type is the allowed value. *NOTE* This option will be deprecated soon. |
ap       | - | - | - | - | - |
 "       | band | integer | yes | (none) | Specifies the frequency band for which this AP configuration is applicable. The value here must be one of the values from 'registrar' list. Possible values are: 2, 5. |
 "       | ssid | string | yes | (none) | Specifies the SSID of the AP that can be auto-configured in this frequency band. |
 "       | encryption | string | yes | psk2 | Specifies the encryption type of the AP that can be auto-configured in this frequency band. |
 "       | key | string | yes | (none) | When encryption type is 'psk2', specifies the passphrase of the AP that can be auto-configured in this frequency band. |

-----------

A minimal UCI configuration for ieee1905 in Registrar mode:

````bash
config ieee1905 'ieee1905'
        option enabled '1'
        option registrar '2 5'

config ap
        option band '2'
        option ssid 'TestSSID.2'
        option encryption 'psk2'
        option key '1234567890'

config ap
        option band '5'
        option ssid 'TestSSID.5'
        option encryption 'psk2'
        option key '1234567890'

config al-iface
        option enabled 1
````

After ieee1905d is started with the above config, interfaces that are to be
managed and treated as 1905 interfaces can be added at runtime through the
`add_interface` method of `ieee1905` UBUS object.

Conversely, `del_interface` can be used to remove an interface from the 1905 AL.

### UBUS Objects and APIs

The 1905 daemon publishes the `ieee1905` object over UBUS.

````bash
root@iopsys:~# ubus -v list ieee1905
'ieee1905' @1d99fac8
	"start":{}
	"stop":{}
	"status":{}
	"info":{}
	"neighbors":{}
	"others":{}
	"apconfig":{"ifname":"String","band":"Integer","action":"String"}
	"refresh":{}
	"cmdu":{"dst":"String","src":"String","type":"Integer","mid":"Integer","data":"String"}
	"buildcmdu":{"type":"Integer","ifname":"String","args":"Array"}
	"rxcmdu":{"src":"String","ifname":"String","type":"String","mid":"Integer","data":"String"}
	"add_interface":{"ifname":"String"}
	"del_interface":{"ifname":"String"}
````

Per-interface UBUS objects corresponding to the 1905 AL interfaces are also
created -

````bash
root@iopsys:~# ubus -v list ieee1905.al.*
'ieee1905.al.eth1' @eb801e37
        "status":{}
        "neighbors":{}
        "cmdu":{"dst":"String","src":"String","type":"Integer","mid":"Integer","data":"String"}
'ieee1905.al.eth2' @766bd2ee
        "status":{}
        "neighbors":{}
        "cmdu":{"dst":"String","src":"String","type":"Integer","mid":"Integer","data":"String"}
'ieee1905.al.eth3' @6892e392
        "status":{}
        "neighbors":{}
        "cmdu":{"dst":"String","src":"String","type":"Integer","mid":"Integer","data":"String"}
'ieee1905.al.eth4' @2024760d
        "status":{}
        "neighbors":{}
        "cmdu":{"dst":"String","src":"String","type":"Integer","mid":"Integer","data":"String"}
'ieee1905.al.wl0' @5126b855
        "status":{}
        "neighbors":{}
        "cmdu":{"dst":"String","src":"String","type":"Integer","mid":"Integer","data":"String"}
'ieee1905.al.wl0.1' @f7195877
        "status":{}
        "neighbors":{}
        "cmdu":{"dst":"String","src":"String","type":"Integer","mid":"Integer","data":"String"}
'ieee1905.al.wl1' @1f88e67b
        "status":{}
        "neighbors":{}
        "cmdu":{"dst":"String","src":"String","type":"Integer","mid":"Integer","data":"String"}
'ieee1905.al.wl1.1' @b06dcc91
        "status":{}
        "neighbors":{}
        "cmdu":{"dst":"String","src":"String","type":"Integer","mid":"Integer","data":"String"}
````

When the package is built with 1905 CMDU extension support enabled, then the following `ieee1905.extension`
object is created. This extension object provides CLI methods through which an extension plugin can be
dynamically loaded, unloaded, started or stopped.

````bash
root@iopsys:~# ubus -v list ieee1905.extension
'ieee1905.extension' @d3d28211
        "load":{"name":"String"}
        "unload":{"name":"String"}
        "start":{"name":"String"}
        "stop":{"name":"String"}
        "list":{}
````

**Multi-AP Plugin**

The Multi-AP plugin implements 1905 CMDUs and extensions as required by the Wi-Fi
Alliance's Multi-AP EasyMesh specification.

After the Multi-AP plugin (**map.so**) is loaded through `ieee1905.extension`'s **load**
ubus method, a new UBUS object corresponding to the MAP plugin `ieee1905.map` is
published.

````bash
root@iopsys:~# ubus -v list ieee1905.map
'ieee1905.map' @1cd3d8ae
        "register":{"module":"String","data":"String"}
````

Through the `ieee1905.map` object's **register** method, Multi-AP client applications
viz. mapagent, mapcontroller, decollector etc. can register themselves and be able
to receive, process and transmit EasyMesh Multi-AP CMDUs.


## Code structure ##

The source code is within the `src` directory.

Files within the `src` directory -

*1905_tlvs.h* - defines IEEE-1905 CMDU types and TLV data structures.

*cmdu.c,h* - CMDU buffer manipulation functions reside in these files.

*i1905.c,h* - files define data structures and implement functions used by the 1905 daemon.

*config.c,h* - for 1905 configuration related structures and functions.

*cmdu_input.c* - processing of the received CMDUs are in this c file.

*cmdu_output.c* - creation of CMDUs for transmit are implemented in this file

*genmid.c* - this source file implements generation of CMDU message-ids.

*bufutil.h,c* - defines and implements helper functions for unaligned buffer manipulation.

*i1905_extension.c,h* - implements functions needed for registering and working with 1905 extension plugins.

*neigh.c,h* - for managing directly connected network neighbor devices.

*i1905_netlink.c* - implements rtnetlink events handling.

*i1905_ubus.c* - UBUS objects and methods are implemented in this file.

*main.c* - includes the main() entry point for the ieee1905d daemon.

*cryptutil.c,h* - defines and implements cryptographic functions needed by IEEE-1905.

*i1905_wsc.c,h* - defines structures and implements WSC M1 and M2 message generation functions.

*i1905_dm.c,h* - these files define and implement the IEEE-1905 DataModel as per TR-181.

*debug.c,h* - contain functions used for debugging and logging.

*hlist.h
util.c,h
timer.c,h
timer_impl.h
worker.c,h* - these files implement utility and helper functions used by the ieee1905d daemon.

*cmdu_ackq.c,h* - implements timer-queue for transmit CMDUs awaiting either some response or acknowledgement.

*cmduqueue.c* - implements queueing functions for CMDUs.


**extmodules**

extmodules/map - contains Multi-AP extension plugin.

*extmodules/map/map.h* - header file defining Multi-AP EasyMesh-2 TLVs and CMDU types.

*extmodules/map/map.c* - main file implementing the 1905 plugin extension for Multi-AP.

*extmodule/map/map_module.c* - provides functions for registration and events notification of the Multi-AP client applications.

*extmodules/map/tests/mapclient1.c,
extmodules/map/tests/mapclient2.c* - example client applications showing how the MAP plugin can be used.

**tests**

*fuzz* - this directory contains components that can be used for fuzzing test.

**scripts**

*docker* - contains Dockerfiles and related scripts to build and run 1905 docker images.


## Dependencies ##

To successfully build ieee1905d, the following libraries are needed:

| Dependency  		| Link                                       						| License        |
| -----------------	| ----------------------------------------------------------------			| -------------- |
| libuci      		| https://git.openwrt.org/project/uci.git     					 	| LGPL 2.1       |
| libubox     		| https://git.openwrt.org/project/libubox.git 					 	| BSD            |
| libubus     		| https://git.openwrt.org/project/ubus.git    					 	| LGPL 2.1       |
| libjson-c   		| https://s3.amazonaws.com/json-c_releases    					 	| MIT            |
| libwifi	  	| https://dev.iopsys.eu/iopsys/easy-soc-libs/tree/devel/libwifi				| GNU GPL2       |
| libnl3	  	| 											|		 |
| libblobmsg_json	|											|		 |
| libnl-genl  		|                                             					 	|                |



