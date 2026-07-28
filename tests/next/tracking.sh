#!/bin/bash
source $(dirname $0)/include/lib.sh
source $(dirname $0)/include/helpers.sh

tracking_sanity() {
	three_ns

	# Add a DNAT rule and a route in ns0.
	ip -net ns0 route add 10.0.255.1/32 via 10.0.42.2
	ip netns exec ns1 nft -f - <<EOF
table nat {
        chain prerouting {
                type nat hook prerouting priority -100;
                ip daddr 10.0.255.1/32 dnat to 10.0.43.2
        }
}
EOF

	$retis collect -o -c skb,skb-tracking,dev,ns \
		-f "icmp and host 10.0.255.1" \
		-p net:netif_rx \
		--cmd "ip netns exec ns0 ping -c1 10.0.255.1; sleep 1"

	cat >test.py <<EOF
from helpers import assert_events_present

expected_events = [
    {
        "dev": {
            "name": "veth10",
        },
        "parsed_packet": {
            "icmp": {
                "code": "0",
                "type": "echo-request",
            },
            "ip": {
                "src": "10.0.42.1",
                "dst": "10.0.255.1",
            },
        },
        "skb-tracking": {
            "orig_head": "&orig_head",
            "timestamp": "&timestamp",
            "skb": "&skb",
        },
    },
    {
        "dev": {
            "name": "veth21",
        },
        "parsed_packet": {
            "icmp": {
                "code": "0",
                "type": "echo-request",
            },
            "ip": {
                "src": "10.0.42.1",
                "dst": "10.0.43.2",
            },
        },
        "skb-tracking": {
            "orig_head": "*orig_head",
            "timestamp": "*timestamp",
            "skb": "*skb",
        },
    },
    {
        "dev": {
            "name": "veth01",
        },
        "parsed_packet": {
            "icmp": {
                "code": "0",
                "type": "echo-reply",
            },
            "ip": {
                "src": "10.0.255.1",
                "dst": "10.0.42.1",
            },
        },
        "skb-tracking": {
            "orig_head": "!orig_head",
            "timestamp": "!timestamp",
        },
    },
]

assert_events_present("retis.data", expected_events)
EOF
	python test.py

	$retis sort -o sorted
	$retis stats sorted > sorted_stats
	grep -q "Number of series: 2" sorted_stats
	grep -q "Number of events: 3" sorted_stats
	grep -q "raw_tracepoint/net:netif_rx: 3" sorted_stats
}

ftrace_sanity() {
	two_ns

	# ftrace is not supported by tracepoints.
	! $retis collect -c skb,skb-tracking \
		-p "tp:net:netif_receive_skb/ftrace" \
		--cmd "ip netns exec ns0 ping -c1 10.0.42.2" 2>/dev/null

	# ftrace is not supported by kretprobes.
	! $retis collect -c skb,skb-tracking \
		-p "kr:__ip_local_out/ftrace" \
		--cmd "ip netns exec ns0 ping -c1 10.0.42.2" 2>/dev/null

	# ftrace option requires the function to have a valid skb argument.
	! $retis collect -c skb,skb-tracking \
		-p "k:ip_send_check/ftrace" \
		--cmd "ip netns exec ns0 ping -c1 10.0.42.2" 2>/dev/null

	$retis collect -o -c skb,skb-tracking \
		-p "k:__ip_local_out/ftrace" \
		-p "k:ip_send_check" \
		-f "icmp" \
		--stop-after 2 \
		--cmd 'ip netns exec ns0 ping -c 10 -i 0.2 -w 10 10.0.42.2'

	cat >test.py <<EOF
from helpers import assert_events_present

expected_events = [
    {
        "kernel": {
            "symbol": "__ip_local_out",
        },
        "parsed_packet": {
            "icmp": {
                "type": "echo-request",
            },
        },
        "skb-tracking": {
            "orig_head": "&orig_head",
            "timestamp": "&timestamp",
            "skb": "&skb",
        },
    },
    {
        "kernel": {
            "symbol": "ip_send_check",
        },
        "skb-tracking": {
            "orig_head": "*orig_head",
            "timestamp": "*timestamp",
            "skb": 0,
        },
    },
]

assert_events_present("retis.data", expected_events)
EOF
	python test.py
}

ftrace_nested_window_warning() {
	two_ns

	$retis collect -c skb,skb-tracking \
		-p "k:__ip_local_out/ftrace" \
		-p "k:nf_hook_slow/ftrace" \
		-f "icmp" \
		--stop-after 1 \
		--cmd 'ip netns exec ns0 ping -c1 10.0.42.2'

	grep -q "Nested ftrace window detected" log
}

run_tests tracking_sanity ftrace_sanity ftrace_nested_window_warning
