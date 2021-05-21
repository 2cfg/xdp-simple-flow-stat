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

reference: https://github.com/iovisor/bcc/blob/bc04fc51c9d937253ccac8cafdc2bd0ad4729f73/src/python/bcc/table.py
