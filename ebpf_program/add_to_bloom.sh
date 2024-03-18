#! /bin/bash
qname=".${1%.}"
qname_hex=$(printf '%s' "$qname" | hexdump -ve '/1 "0x%02X "')
remaining_chars=$(expr 254 - $(echo -n $qname | wc -c))
for i in $(seq 1 $remaining_chars); do
	qname_hex+=" 0x00"
done
bpftool map push name all_qnames value $qname_hex
