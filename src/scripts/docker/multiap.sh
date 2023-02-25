#!/bin/sh

echo "$0 called with args: $@" > /tmp/multiap.log

while [ "$1" != "" ]; do
	case $1 in
		--multiap_mode )
			shift
			multiap_mode=$1
			echo "Case:::: multiap_mode: $multiap_mode" >> /tmp/multiap.log
			;;
		--alid )
			shift
			alid=$1
			sed -i "s/option.*macaddress.*$/option macaddress '$alid'/" /etc/config/ieee1905
			;;
		* )
			;;
	esac
	shift
done

multiap_mode=${multiap_mode:-full}

case $multiap_mode in
	auto )
		run_cntlr=2
		run_agent=1
		;;
	controller )
		run_agent=0
		run_cntlr=1
		;;
	agent )
		run_agent=1
		run_cntlr=0
		sed -i '/option.*registrar.*$/d' /etc/config/ieee1905
		sed -i "s/option.*local.*$/option local '0'/" /etc/config/mapagent
		;;
	none )
		run_agent=0
		run_cntlr=0
		sed -i '/option.*registrar.*$/d' /etc/config/ieee1905
		;;
	* | full )
		run_agent=1
		run_cntlr=1
		;;
esac

echo "multi_mode = ${multiap_mode}   run_agent = ${run_agent}   run_cntlr = ${run_cntlr} alid = ${alid}" >> /tmp/multiap.log


ubusd &

ieee1905d -D &
sleep 3
ubus call ieee1905 add_interface '{"ifname":"eth0"}'

exec bash
