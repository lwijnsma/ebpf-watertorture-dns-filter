#! /bin/bash
NS="${NS:-'10.0.55.53'}"
ZONE="${ZONE:-'rp1.test'}"

dig @$NS -t AXFR $ZONE | awk '{print $1}' | grep '\.' | sort | uniq | parallel --bar ./add_to_bloom.sh
