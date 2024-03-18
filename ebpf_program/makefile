iface := eth1
rp1_ebpf.o: rp1_ebpf_code.c 
	clang -O2 -g -Wall -target bpf -c rp1_ebpf_code.c -o rp1_ebpf.o
load: rp1_ebpf.o
	sudo xdp-loader load ${iface} -v rp1_ebpf.o
unload:
	sudo xdp-loader unload ${iface} --all
bloom_fill:
	sudo ./parallel.sh 
clean:
	rm rp1_ebpf.o
