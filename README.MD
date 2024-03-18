# RP1 eBPF Layer 7 DNS Water torture attack mitigation

## Running the program

### Requirements
Requirements for XDP VNF
```shell
sudo apt install linux-tools-common linux-tools-generic make clang llvm xdp-tools gcc-multilib libbpf-dev linux-headers-$(uname -r)
```

### Compile C to bytecode
```shell
make
```

### Load or unload eBPF program on nic
```shell
make load iface=eth1
make unload iface=eth1
```

### Fill the bloom filter
```shell
make bloom_fill
```

### See debug messages
```shell
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## The lab

The lab consists of:
- 1 DNS tester
- 1 VNF with the XDP program
- 1 Nameserver

And 2 network segments:
- Safenet: 10.0.10.0/24
- Stormnet: 10.0.20.0/24

The DNS server has a connection to safenet.

The DNS tester has a connection to stormnet.

And the NVF has a connection to both and functions as a router between the 2 networks.

|server|ip|
|---|---|
| DNS tester|10.0.20.69/24|
|NVF|10.0.10.1/24|
|NVF|10.0.20.1/24|
|Nameserver|10.0.10.53/24|
```