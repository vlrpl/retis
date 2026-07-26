use std::fmt;

use retis_pnet::ethernet::EtherType;

use super::*;
use crate::{event_section, event_type, Formatter};

// ---- Dynamic field report types ----

/// The type of a dynamically captured sk_buff field value.
#[event_type]
#[serde(rename_all = "snake_case")]
pub enum SkbFieldValue {
    U8 { value: u8 },
    U16 { value: u16 },
    U32 { value: u32 },
    U64 { value: u64 },
    I8 { value: i8 },
    I16 { value: i16 },
    I32 { value: i32 },
    I64 { value: i64 },
    Str { value: String },
    /// Raw byte slice captured from a pointer field.
    Bytes { value: Vec<u8> },
    /// The BPF read failed (e.g. NULL pointer dereference).
    Invalid { reason: String },
}

impl fmt::Display for SkbFieldValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SkbFieldValue::U8 { value } => write!(f, "{value:#x}"),
            SkbFieldValue::U16 { value } => write!(f, "{value:#x}"),
            SkbFieldValue::U32 { value } => write!(f, "{value:#x}"),
            SkbFieldValue::U64 { value } => write!(f, "{value:#x}"),
            SkbFieldValue::I8 { value } => write!(f, "{value}"),
            SkbFieldValue::I16 { value } => write!(f, "{value}"),
            SkbFieldValue::I32 { value } => write!(f, "{value}"),
            SkbFieldValue::I64 { value } => write!(f, "{value}"),
            SkbFieldValue::Str { value } => write!(f, "{value:?}"),
            SkbFieldValue::Bytes { value } => {
                for b in value {
                    write!(f, "{b:02x}")?;
                }
                Ok(())
            }
            SkbFieldValue::Invalid { .. } => write!(f, "<err>"),
        }
    }
}

/// A named, typed field captured from an sk_buff.
#[event_type]
pub struct SkbCapturedField {
    /// Dot-path name, e.g. "dev.name", "mark".
    pub name: String,
    /// The captured value.
    pub value: SkbFieldValue,
}

/// Dynamic field report — all user-requested fields captured from an sk_buff.
#[event_section]
#[derive(Default)]
pub struct SkbFieldReportEvent {
    /// Captured fields.
    pub fields: Vec<SkbCapturedField>,
}

impl EventFmt for SkbFieldReportEvent {
    fn event_fmt(&self, f: &mut Formatter, _format: &DisplayFormat) -> fmt::Result {
        write!(f, "fields [")?;
        let mut sep = "";
        for field in &self.fields {
            write!(f, "{sep}{}: {}", field.name, field.value)?;
            sep = " ";
        }
        write!(f, "]")
    }

    fn can_format(&self, _format: &DisplayFormat) -> bool {
        !self.fields.is_empty()
    }
}

#[cfg(feature = "python")]
#[pyo3::pymethods]
impl SkbFieldReportEvent {
    /// Dict-style access: report["mark"] returns a native Python type.
    fn __getitem__(&self, py: pyo3::Python<'_>, key: &str) -> pyo3::PyResult<pyo3::Py<pyo3::PyAny>> {
        self.fields
            .iter()
            .find(|f| f.name == key)
            .map(|f| field_value_to_py(py, &f.value))
            .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err(key.to_string()))
    }

    /// Check if a field exists: "mark" in report.
    fn __contains__(&self, key: &str) -> bool {
        self.fields.iter().any(|f| f.name == key)
    }

    /// List all captured field names.
    fn names(&self) -> Vec<String> {
        self.fields.iter().map(|f| f.name.clone()).collect()
    }
}

#[cfg(feature = "python")]
fn field_value_to_py(py: pyo3::Python<'_>, val: &SkbFieldValue) -> pyo3::Py<pyo3::PyAny> {
    use pyo3::IntoPyObjectExt;
    match val {
        SkbFieldValue::U8 { value } => (*value as u64).into_py_any(py).unwrap(),
        SkbFieldValue::U16 { value } => (*value as u64).into_py_any(py).unwrap(),
        SkbFieldValue::U32 { value } => (*value as u64).into_py_any(py).unwrap(),
        SkbFieldValue::U64 { value } => value.into_py_any(py).unwrap(),
        SkbFieldValue::I8 { value } => (*value as i64).into_py_any(py).unwrap(),
        SkbFieldValue::I16 { value } => (*value as i64).into_py_any(py).unwrap(),
        SkbFieldValue::I32 { value } => (*value as i64).into_py_any(py).unwrap(),
        SkbFieldValue::I64 { value } => value.into_py_any(py).unwrap(),
        SkbFieldValue::Str { value } => value.into_py_any(py).unwrap(),
        SkbFieldValue::Bytes { value } => value.as_slice().into_py_any(py).unwrap(),
        SkbFieldValue::Invalid { .. } => py.None().into_py_any(py).unwrap(),
    }
}

// ---- End dynamic field report types ----

/// Skb section.
#[event_section]
#[derive(Default)]
pub struct SkbEvent {
    /// VLAN acceleration.
    pub vlan_accel: Option<SkbVlanAccelEvent>,
    /// Metadata.
    pub meta: Option<SkbMetaEvent>,
    /// Data and refcnt information.
    pub data_ref: Option<SkbDataRefEvent>,
    /// GSO.
    pub gso: Option<SkbGsoEvent>,
    /// Dynamic field report (from --skb-fields).
    pub field_report: Option<SkbFieldReportEvent>,
}

impl EventFmt for SkbEvent {
    fn event_fmt(&self, f: &mut Formatter, format: &DisplayFormat) -> fmt::Result {
        let mut space = DelimWriter::new(' ');

        if format.print_ll {
            if let Some(vlan) = &self.vlan_accel {
                space.write(f)?;
                write!(f, "vlan_accel (")?;

                match helpers::net::etype_str(EtherType::new(vlan.proto)) {
                    Some(etype) => write!(f, "ethertype {etype} ({:#06x})", vlan.proto)?,
                    None => write!(f, "ethertype ({:#06x})", vlan.proto)?,
                }

                write!(
                    f,
                    " vlan {} p {}{})",
                    vlan.vid,
                    vlan.pcp,
                    if vlan.dei { " DEI" } else { "" }
                )?;
            }
        }

        if self.meta.is_some() || self.data_ref.is_some() {
            space.write(f)?;
            write!(f, "skb [")?;

            if let Some(meta) = &self.meta {
                write!(f, "csum ")?;
                match meta.ip_summed {
                    0 => write!(f, "none ")?,
                    1 => write!(f, "unnecessary (level {}) ", meta.csum_level)?,
                    2 => write!(f, "complete ({:#x}) ", meta.csum)?,
                    3 => {
                        let start = meta.csum & 0xffff;
                        let off = meta.csum >> 16;
                        write!(f, "partial (start {start} off {off}) ")?;
                    }
                    x => write!(f, "unknown ({x}) ")?,
                }

                if meta.hash != 0 {
                    write!(f, "hash {:#x} ", meta.hash)?;
                }
                write!(f, "len {} ", meta.len,)?;
                if meta.data_len != 0 {
                    write!(f, "data_len {} ", meta.data_len)?;
                }
                write!(f, "priority {}", meta.priority)?;
            }

            if self.meta.is_some() && self.data_ref.is_some() {
                write!(f, " ")?;
            }

            if let Some(dataref) = &self.data_ref {
                if dataref.nohdr {
                    write!(f, "nohdr ")?;
                }
                if dataref.cloned {
                    write!(f, "cloned ")?;
                }
                if dataref.fclone > 0 {
                    write!(f, "fclone {} ", dataref.fclone)?;
                }
                write!(f, "users {} dataref {}", dataref.users, dataref.dataref)?;
            }

            write!(f, "]")?;
        }

        if let Some(gso) = &self.gso {
            space.write(f)?;
            write!(f, "gso [type {:#x} ", gso.r#type)?;

            if gso.flags != 0 {
                write!(f, "flags {:#x} ", gso.flags)?;
            }

            if gso.frags != 0 {
                write!(f, "frags {} ", gso.frags)?;
            }

            if gso.segs != 0 {
                write!(f, "segs {} ", gso.segs)?;
            }

            write!(f, "size {}]", gso.size)?;
        }

        if let Some(field_report) = &self.field_report {
            if field_report.can_format(format) {
                space.write(f)?;
                field_report.event_fmt(f, format)?;
            }
        }

        Ok(())
    }

    fn can_format(&self, format: &DisplayFormat) -> bool {
        (self.vlan_accel.is_some() && format.print_ll)
            || self.meta.is_some()
            || self.data_ref.is_some()
            || self.gso.is_some()
            || self
                .field_report
                .as_ref()
                .is_some_and(|fr| fr.can_format(format))
    }
}

/// Ethernet fields.
#[event_type]
pub struct SkbEthEvent {
    /// Ethertype.
    pub etype: u16,
    /// Source MAC address.
    pub src: String,
    /// Destination MAC address.
    pub dst: String,
}

/// VLAN acceleration.
#[event_type]
pub struct SkbVlanAccelEvent {
    /// Tag protocol identifier.
    pub proto: u16,
    /// Priority Code Point. Also called CoS.
    pub pcp: u8,
    /// Drop Eligible Indicator (DEI).
    pub dei: bool,
    /// VLAN ID.
    pub vid: u16,
}

/// ARP fields.
#[event_type]
pub struct SkbArpEvent {
    /// Operation type.
    pub operation: ArpOperation,
    /// Sender hardware address.
    pub sha: String,
    /// Sender protocol address.
    pub spa: String,
    /// Target hardware address.
    pub tha: String,
    /// Target protocol address.
    pub tpa: String,
}

/// ARP operation type.
#[event_type]
pub enum ArpOperation {
    Request,
    Reply,
    ReverseRequest,
    ReverseReply,
}

/// IPv4/IPv6 fields.
#[event_type]
pub struct SkbIpEvent {
    /// Source IP address.
    pub saddr: String,
    /// Destination IP address.
    pub daddr: String,
    /// IP version: 4 or 6.
    #[serde(flatten)]
    pub version: SkbIpVersion,
    /// L4 protocol, from IPv4 "protocol" field or IPv6 "next header" one.
    pub protocol: u8,
    /// "total len" from the IPv4 header or "payload length" from the IPv6 one.
    pub len: u16,
    /// TTL in the IPv4 header and hop limit in the IPv6 one.
    pub ttl: u8,
    /// ECN.
    pub ecn: u8,
}

/// IP version and specific fields.
#[event_type]
#[serde(rename_all = "snake_case")]
pub enum SkbIpVersion {
    V4 {
        #[serde(flatten)]
        v4: SkbIpv4Event,
    },
    V6 {
        #[serde(flatten)]
        v6: SkbIpv6Event,
    },
}

/// IPv4 specific fields.
#[event_type]
pub struct SkbIpv4Event {
    /// Type of service.
    pub tos: u8,
    /// Identification.
    pub id: u16,
    /// Flags (CE, DF, MF).
    pub flags: u8,
    /// Fragment offset.
    pub offset: u16,
}

/// IPv6 specific fields.
#[event_type]
pub struct SkbIpv6Event {
    /// Flow label.
    pub flow_label: u32,
}

/// TCP fields.
#[event_type]
pub struct SkbTcpEvent {
    /// Source port.
    pub sport: u16,
    /// Destination port.
    pub dport: u16,
    /// Sequence number.
    pub seq: u32,
    /// Acknowledgment number.
    pub ack_seq: u32,
    /// Window size.
    pub window: u16,
    /// Data offset.
    pub doff: u8,
    /// Bitfield of TCP flags as defined in `struct tcphdr` in the kernel.
    pub flags: u8,
}

/// UDP fields.
#[event_type]
pub struct SkbUdpEvent {
    /// Source port.
    pub sport: u16,
    /// Destination port.
    pub dport: u16,
    /// Length. From the UDP header.
    pub len: u16,
}

/// ICMP fields.
#[event_type]
pub struct SkbIcmpEvent {
    /// Type.
    pub r#type: u8,
    /// Code.
    pub code: u8,
}

/// ICMPv6 fields.
#[event_type]
pub struct SkbIcmpV6Event {
    /// Type.
    pub r#type: u8,
    /// Code.
    pub code: u8,
}

/// Skb metadata & releated fields.
#[event_type]
pub struct SkbMetaEvent {
    /// Total packet length.
    pub len: u32,
    /// Total length in the page buffer area.
    pub data_len: u32,
    /// Packet hash.
    pub hash: u32,
    /// Checksum status.
    pub ip_summed: u8,
    /// Packet checksum.
    /// (ip_summed == CHECKSUM_COMPLETE) or checksum
    /// (start << 16)|offset (ip_summed == CHECKSUM_PARTIAL).
    pub csum: u32,
    /// Checksum level.
    /// (ip_summed == CHECKSUM_PARTIAL)
    pub csum_level: u8,
    /// QoS priority.
    pub priority: u32,
}

/// Skb data & refcnt.
#[event_type]
pub struct SkbDataRefEvent {
    /// Payload reference only.
    pub nohdr: bool,
    /// Is skb a clone?
    pub cloned: bool,
    /// Skb fast clone.
    pub fclone: u8,
    /// Users count.
    pub users: u8,
    /// Data refcount.
    pub dataref: u8,
}

/// GSO information.
#[event_type]
pub struct SkbGsoEvent {
    /// GSO flags. See `SKBFL_*` in include/linux/skbuff.h
    pub flags: u8,
    /// Number of fragments. Value of `skb_shared_info->frags`.
    pub frags: u8,
    /// GSO size.
    pub size: u32,
    /// Number of GSO segments.
    pub segs: u32,
    /// GSO type. See `SKB_GSO_*` in include/linux/skbuff.h
    pub r#type: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn field_report_display() {
        let report = SkbFieldReportEvent {
            fields: vec![
                SkbCapturedField {
                    name: "mark".to_string(),
                    value: SkbFieldValue::U32 { value: 0xc0de },
                },
                SkbCapturedField {
                    name: "dev.name".to_string(),
                    value: SkbFieldValue::Str {
                        value: "eth0".to_string(),
                    },
                },
                SkbCapturedField {
                    name: "bad_field".to_string(),
                    value: SkbFieldValue::Invalid {
                        reason: "null pointer".to_string(),
                    },
                },
            ],
        };

        let format = DisplayFormat::new();
        let output = format!(
            "{}",
            report.display(&format, &crate::FormatterConf::new())
        );
        assert_eq!(output, r#"fields [mark: 0xc0de dev.name: "eth0" bad_field: <err>]"#);
    }

    #[test]
    fn field_report_serialization() -> Result<()> {
        let report = SkbFieldReportEvent {
            fields: vec![
                SkbCapturedField {
                    name: "mark".to_string(),
                    value: SkbFieldValue::U32 { value: 42 },
                },
                SkbCapturedField {
                    name: "dev.name".to_string(),
                    value: SkbFieldValue::Str {
                        value: "lo".to_string(),
                    },
                },
            ],
        };

        let json = serde_json::to_string(&report)?;
        let deserialized: SkbFieldReportEvent = serde_json::from_str(&json)?;

        assert_eq!(deserialized.fields.len(), 2);
        assert_eq!(deserialized.fields[0].name, "mark");
        assert_eq!(deserialized.fields[1].name, "dev.name");

        // Verify the JSON structure includes the type tag.
        let json_val: serde_json::Value = serde_json::from_str(&json)?;
        let first_val = &json_val["fields"][0]["value"];
        assert!(first_val.is_object());

        Ok(())
    }

    #[test]
    fn field_report_empty() {
        let report = SkbFieldReportEvent { fields: vec![] };
        let format = DisplayFormat::new();
        assert!(!report.can_format(&format));
    }
}
