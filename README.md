# XDP simple flow stat

start: 
```
/usr/bin/ip -force link set dev $iface xdpdrv object xdp_flow_stat_kern.o verbose
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
