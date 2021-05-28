# XDP simple flow stat

start: 
```
/usr/bin/ip -force link set dev $iface xdpdrv object xdp_flow_stat_kern.o sec xdp/flowstat verbose
```

pin map to bpffs: 
```
bpftool map pin id $mapid /sys/fs/bpf/flowtable
```

read data:
```
python3 reader.py
```

stop: 
```
unlink /sys/fs/bpf/flowtable
ip link set dev $iface xdp off
```

reference: https://github.com/iovisor/bcc/blob/master/src/python/bcc/table.py


TEST ENVIRONMENT
```
ip netns add VROUTER
ip link set dev enp3s0f0 netns VROUTER
ip netns exec VROUTER ip addr add 192.168.50.106/24 dev enp3s0f0
ip netns exec VROUTER ip link set dev enp3s0f0 up
ip netns exec VROUTER ip link add link enp3s0f0 name rvlan11 type vlan id 11
ip netns exec VROUTER ip addr add 192.168.11.7/24 dev rvlan11
ip netns exec VROUTER ip link set dev rvlan11 up
ip netns exec VROUTER ip route add 
ip netns exec VROUTER ip route add 1.1.1.0/24 dev enp3s0f0
 
ip netns exec VROUTER ip addr show
ip netns exec VROUTER ip link show

ip netns exec VROUTER ip -force link set dev enp3s0f0 xdpdrv object /srv/firewall/modules/xdp/xdp_flow_stat_kern.o sec rx/out verbose

ip netns exec VROUTER  ip link set dev enp3s0f0 xdp off

ip -force link set dev enp3s0f1 xdpdrv object /srv/firewall/modules/xdp/xdp_flow_stat_kern.o sec rx/in verbose
```
