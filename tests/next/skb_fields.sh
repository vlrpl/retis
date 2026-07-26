#!/bin/bash
source $(dirname $0)/include/lib.sh
source $(dirname $0)/include/helpers.sh

# Verify that --skb-fields captures scalar fields (mark, priority) and
# reports them in the field_report section of skb events.
skb_fields_scalar() {
	require $retis python -h || return 0
	two_ns

	$retis collect -o -c skb --skb-fields mark,priority \
		-f icmp -p ip_rcv \
		--cmd 'ip netns exec ns0 ping -c1 10.0.42.2; sleep 1'

	cat >test.py <<EOF
r = reader.events()
next(r)  # skip startup event

found = False
for e in r:
    skb = e.skb
    if skb is None:
        continue
    fr = skb.field_report
    if fr is None:
        continue
    # Both fields must be present and return native int values.
    assert "mark" in fr, "mark not in field_report"
    assert "priority" in fr, "priority not in field_report"
    assert isinstance(fr["mark"], int), f"mark: expected int, got {type(fr['mark'])}"
    assert isinstance(fr["priority"], int), f"priority: expected int, got {type(fr['priority'])}"
    found = True
    break

assert found, "No skb event with mark+priority in field_report"
EOF
	$retis python test.py
}

# Verify that --skb-fields captures a string field (dev.name).
skb_fields_string() {
	require $retis python -h || return 0
	two_ns

	$retis collect -o -c skb,dev --skb-fields dev.name \
		-f icmp -p ip_rcv \
		--cmd 'ip netns exec ns0 ping -c1 10.0.42.2; sleep 1'

	cat >test.py <<EOF
r = reader.events()
next(r)  # skip startup event

found = False
for e in r:
    skb = e.skb
    if skb is None:
        continue
    fr = skb.field_report
    if fr is None:
        continue
    assert "dev.name" in fr
    name = fr["dev.name"]
    assert isinstance(name, str), f"Expected str, got {type(name)}"
    assert len(name) > 0, "dev.name should not be empty"
    found = True
    break

assert found, "No event with dev.name in field_report"
EOF
	$retis python test.py
}

# Verify Python API: __getitem__, __contains__, names() and native types.
skb_fields_python_access() {
	require $retis python -h || return 0
	two_ns

	$retis collect -o -c skb --skb-fields len,dev.name \
		-f icmp -p ip_rcv \
		--cmd 'ip netns exec ns0 ping -c1 10.0.42.2; sleep 1'

	cat >test.py <<EOF
r = reader.events()
next(r)  # skip startup event

found = False
for e in r:
    skb = e.skb
    if skb is None:
        continue
    fr = skb.field_report
    if fr is None:
        continue

    # names() returns a list of field name strings
    names = fr.names()
    assert isinstance(names, list)
    assert "len" in names
    assert "dev.name" in names

    # __contains__
    assert "len" in fr
    assert "dev.name" in fr
    assert "nonexistent" not in fr

    # __getitem__ returns native Python types
    pkt_len = fr["len"]
    assert isinstance(pkt_len, int), f"Expected int for 'len', got {type(pkt_len)}"
    assert pkt_len > 0

    dev_name = fr["dev.name"]
    assert isinstance(dev_name, str), f"Expected str for 'dev.name', got {type(dev_name)}"

    found = True
    break

assert found, "No skb event with field_report found"
EOF
	$retis python test.py
}

# Regression: existing --skb-sections meta must still work when --skb-fields
# is NOT specified.
skb_fields_no_regression() {
	require $retis python -h || return 0
	two_ns

	$retis collect -o -c skb --skb-sections meta \
		-f icmp -p ip_rcv \
		--cmd 'ip netns exec ns0 ping -c1 10.0.42.2; sleep 1'

	cat >test.py <<EOF
r = reader.events()
next(r)  # skip startup event

found_meta = False
for e in r:
    skb = e.skb
    if skb is None:
        continue
    # meta should be present
    assert skb.meta is not None, "Expected skb.meta to be present"
    # field_report should be absent
    assert skb.field_report is None, "field_report should be None without --skb-fields"
    found_meta = True
    break

assert found_meta, "No skb event with meta found"
EOF
	$retis python test.py
}

# Verify that --skb-fields captures a byte slice from a pointer-to-byte field.
# At ip_rcv, skb->data points to the IP header. The first byte of an IPv4
# packet is 0x45 (version=4, IHL=5). We capture data[0:4] and verify:
# - the field name includes the slice notation
# - Python returns a bytes object
# - the first byte is 0x45 (standard IPv4/IHL=5)
skb_fields_slice() {
	require $retis python -h || return 0
	two_ns

	$retis collect -o -c skb --skb-fields 'data[0:4],data[12:4],data[9:1],data[8:20]' \
		-f icmp -p ip_rcv \
		--cmd 'ip netns exec ns0 ping -c1 10.0.42.2; sleep 1'

	cat >test.py <<EOF
import socket

r = reader.events()
next(r)  # skip startup event

found = False
for e in r:
    skb = e.skb
    if skb is None:
        continue
    fr = skb.field_report
    if fr is None:
        continue
    if not all(k in fr for k in ("data[0:4]", "data[12:4]", "data[9:1]", "data[8:20]")):
        continue
    hdr   = fr["data[0:4]"]
    saddr = fr["data[12:4]"]
    assert isinstance(hdr,   bytes), f"Expected bytes, got {type(hdr)}"
    assert isinstance(saddr, bytes), f"Expected bytes, got {type(saddr)}"
    assert len(hdr)   == 4, f"Expected 4 bytes, got {len(hdr)}"
    assert len(saddr) == 4, f"Expected 4 bytes, got {len(saddr)}"
    # First byte: IPv4 version (4) + IHL (5) = 0x45
    assert hdr[0] == 0x45, f"Expected 0x45 (IPv4/IHL=5), got {hdr[0]:#x}"
    # Bytes 12-15 of the IP header are the source address (10.0.42.1)
    assert saddr == socket.inet_aton("10.0.42.1"), \
        f"Expected src 10.0.42.1, got {saddr.hex()}"
    # The two slices must differ — offset actually selects different bytes
    assert hdr != saddr, "data[0:4] and data[12:4] should differ"
    # Byte 9 of the IPv4 header is the protocol field; ICMP = 1
    proto = fr["data[9:1]"]
    assert isinstance(proto, bytes) and len(proto) == 1, \
        f"Expected 1 byte for proto, got {proto!r}"
    assert proto[0] == 1, f"Expected ICMP proto (1), got {proto[0]}"
    # 20-byte slice at offset 8 spans TTL+proto+checksum+src+dst
    wide = fr["data[8:20]"]
    assert isinstance(wide, bytes) and len(wide) == 20, \
        f"Expected 20 bytes, got {len(wide)}"
    # proto byte at offset 1 within this slice == byte 9 overall == 1
    assert wide[1] == 1, f"Expected ICMP proto at wide[1], got {wide[1]}"
    # src IP at offset 4 within this slice == bytes 12-15 overall
    assert wide[4:8] == socket.inet_aton("10.0.42.1"), \
        f"Expected src 10.0.42.1 at wide[4:8], got {wide[4:8].hex()}"
    found = True
    break

assert found, "No skb event with all slice fields in field_report"
EOF
	$retis python test.py
}

# Verify that a field-ref offset works: head[mac_header:14] reads 14 bytes
# (Ethernet header) starting at skb->head + skb->mac_header.
# At net:netif_receive_skb both head and mac_header are valid.
# We verify: Python returns bytes, length is 14, and the EtherType field
# (bytes 12-13) matches the IPv4 EtherType (0x0800).
skb_fields_slice_field_offset() {
	require $retis python -h || return 0
	two_ns

	$retis collect -o -c skb --skb-fields 'head[mac_header:14]' \
		-f icmp -p net:netif_receive_skb \
		--cmd 'ip netns exec ns0 ping -c1 10.0.42.2; sleep 1'

	cat >test.py <<EOF
import struct

r = reader.events()
next(r)  # skip startup event

found = False
for e in r:
    skb = e.skb
    if skb is None:
        continue
    fr = skb.field_report
    if fr is None:
        continue
    if "head[mac_header:14]" not in fr:
        continue
    eth = fr["head[mac_header:14]"]
    assert isinstance(eth, bytes), f"Expected bytes, got {type(eth)}"
    assert len(eth) == 14, f"Expected 14 bytes (Ethernet header), got {len(eth)}"
    # Bytes 12-13 are the EtherType; 0x0800 = IPv4
    ethertype = struct.unpack("!H", eth[12:14])[0]
    assert ethertype == 0x0800, f"Expected IPv4 EtherType 0x0800, got {ethertype:#x}"
    found = True
    break

assert found, "No skb event with head[mac_header:14] in field_report"
EOF
	$retis python test.py
}

run_tests skb_fields_scalar skb_fields_string skb_fields_python_access skb_fields_no_regression skb_fields_slice skb_fields_slice_field_offset
