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

run_tests skb_fields_scalar skb_fields_string skb_fields_python_access skb_fields_no_regression
