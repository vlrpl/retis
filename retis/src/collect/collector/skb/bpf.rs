//! Rust<>BPF types definitions for the skb module. Fields are not translated in
//! the BPF part and can be represented in various orders, depending from where
//! they come from. Some handling might be needed in the unmarshalers.
//!
//! Please keep this file in sync with its BPF counterpart in bpf/skb_hook.bpf.c

use std::sync::Arc;

use anyhow::{bail, Result};

use crate::{
    bindings::{if_vlan_uapi::*, skb_hook_uapi::*},
    core::{
        events::{
            parse_raw_section, BpfRawSection, EventSectionFactory, FactoryId,
            RawEventSectionFactory,
        },
        filters::meta::{
            capture::{FieldCaptureProgram, SLOT_HEADER_SIZE},
            filter::{LoadCtx, ResolvedField},
        },
    },
    event_section_factory,
    events::*,
};

pub(super) fn unmarshal_meta(raw_section: &BpfRawSection) -> Result<SkbMetaEvent> {
    let raw = parse_raw_section::<skb_meta_event>(raw_section)?;

    Ok(SkbMetaEvent {
        len: raw.len,
        data_len: raw.data_len,
        hash: raw.hash,
        ip_summed: raw.ip_summed,
        csum: raw.csum,
        csum_level: raw.csum_level,
        priority: raw.priority,
    })
}

pub(super) fn unmarshal_vlan(raw_section: &BpfRawSection) -> Result<SkbVlanAccelEvent> {
    let raw = parse_raw_section::<skb_vlan_event>(raw_section)?;

    Ok(SkbVlanAccelEvent {
        proto: raw.proto,
        pcp: raw.pcp,
        dei: raw.dei == 1,
        vid: raw.vid,
    })
}

pub(super) fn unmarshal_data_ref(raw_section: &BpfRawSection) -> Result<SkbDataRefEvent> {
    let raw = parse_raw_section::<skb_data_ref_event>(raw_section)?;

    Ok(SkbDataRefEvent {
        nohdr: raw.nohdr == 1,
        cloned: raw.cloned == 1,
        fclone: raw.fclone,
        users: raw.users,
        dataref: raw.dataref,
    })
}

pub(super) fn unmarshal_gso(raw_section: &BpfRawSection) -> Result<SkbGsoEvent> {
    let raw = parse_raw_section::<skb_gso_event>(raw_section)?;

    Ok(SkbGsoEvent {
        flags: raw.flags,
        frags: raw.nr_frags,
        size: raw.gso_size,
        segs: raw.gso_segs,
        r#type: raw.gso_type,
    })
}

pub(super) fn unmarshal_packet(raw_section: &BpfRawSection) -> Result<PacketEvent> {
    let raw = parse_raw_section::<skb_packet_event>(raw_section)?;

    Ok(PacketEvent {
        len: raw.len,
        capture_len: raw.capture_len,
        data: RawPacket(raw.packet[..(raw.capture_len as usize)].to_vec()),
    })
}

#[derive(Default)]
#[event_section_factory(FactoryId::Skb)]
pub(crate) struct SkbEventFactory {
    /// Schema for dynamic field capture — set when --skb-fields is active.
    field_schema: Option<Arc<Vec<ResolvedField>>>,
}

impl SkbEventFactory {
    /// Set the field schema for SECTION_FIELD_REPORT unmarshaling.
    pub(crate) fn set_field_schema(&mut self, schema: Arc<Vec<ResolvedField>>) {
        self.field_schema = Some(schema);
    }
}

impl RawEventSectionFactory for SkbEventFactory {
    fn create(&mut self, raw_sections: Vec<BpfRawSection>, event: &mut Event) -> Result<()> {
        let mut skb: Option<SkbEvent> = None;

        for section in raw_sections.iter() {
            match section.header.data_type as u32 {
                SECTION_VLAN => {
                    skb.get_or_insert_default().vlan_accel = Some(unmarshal_vlan(section)?)
                }
                SECTION_META => skb.get_or_insert_default().meta = Some(unmarshal_meta(section)?),
                SECTION_DATA_REF => {
                    skb.get_or_insert_default().data_ref = Some(unmarshal_data_ref(section)?)
                }
                SECTION_GSO => skb.get_or_insert_default().gso = Some(unmarshal_gso(section)?),
                SECTION_PACKET => event.packet = Some(unmarshal_packet(section)?),
                SECTION_FIELD_REPORT => {
                    if let Some(schema) = &self.field_schema {
                        skb.get_or_insert_default().field_report =
                            Some(unmarshal_field_report(section, schema)?);
                    }
                }
                x => bail!("Unknown data type ({x})"),
            }
        }

        event.skb = skb;
        Ok(())
    }
}

/// Unmarshal a SECTION_FIELD_REPORT section into an SkbFieldReportEvent.
///
/// Wire layout:
///   byte 0:     n_fields (written by BPF)
///   byte 1..:   slots, one per field
///     slot:     [ u8 valid ] [ u8 pad ] [ value bytes ]
///
/// Slot sizes are variable: scalars use 8 bytes, strings use their nmemb.
fn unmarshal_field_report(
    raw_section: &BpfRawSection,
    schema: &[ResolvedField],
) -> Result<SkbFieldReportEvent> {
    let data = &raw_section.data;

    if data.is_empty() {
        bail!("field_report section is empty");
    }

    let n_fields = data[0] as usize;
    let slot_data = &data[1..];

    let mut fields = Vec::with_capacity(n_fields);
    let mut offset = 0usize;

    for (idx, field) in schema.iter().enumerate().take(n_fields) {
        let value_size = FieldCaptureProgram::field_value_size(&field.load)?;
        let slot_end = offset + SLOT_HEADER_SIZE + value_size;

        if slot_end > slot_data.len() {
            bail!(
                "field_report section too short for field {idx}: need {slot_end}, have {}",
                slot_data.len()
            );
        }

        let valid = slot_data[offset];
        let value_bytes = &slot_data[offset + SLOT_HEADER_SIZE..offset + SLOT_HEADER_SIZE + value_size];

        let value = if valid == 0 {
            SkbFieldValue::Invalid {
                reason: "BPF read failed".to_string(),
            }
        } else {
            parse_field_value(value_bytes, &field.load)?
        };

        fields.push(SkbCapturedField {
            name: field.name.clone(),
            value,
        });

        offset += SLOT_HEADER_SIZE + value_size;
    }

    Ok(SkbFieldReportEvent { fields })
}

/// Convert raw slot bytes to an SkbFieldValue based on the field's LoadCtx.
fn parse_field_value(bytes: &[u8], load: &LoadCtx) -> Result<SkbFieldValue> {
    // String / char-array field.
    if load.is_arr() || (load.is_ptr() && load.is_byte()) {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        let s = String::from_utf8_lossy(&bytes[..end]).into_owned();
        return Ok(SkbFieldValue::Str { value: s });
    }

    // All scalars and bitfields are stored as a full 8-byte little-endian u64
    // in the slot (see emit_scalar_capture which uses BpfSize::Double).
    if bytes.len() < 8 {
        bail!(
            "scalar slot too short: expected 8 bytes, got {}",
            bytes.len()
        );
    }
    let raw = u64::from_ne_bytes(bytes[..8].try_into()?);

    if load.is_signed() {
        if load.is_byte() {
            Ok(SkbFieldValue::I8 { value: raw as i8 })
        } else if load.is_short() {
            Ok(SkbFieldValue::I16 { value: raw as i16 })
        } else if load.is_int() {
            Ok(SkbFieldValue::I32 { value: raw as i32 })
        } else {
            Ok(SkbFieldValue::I64 { value: raw as i64 })
        }
    } else if load.is_byte() {
        Ok(SkbFieldValue::U8 { value: raw as u8 })
    } else if load.is_short() {
        Ok(SkbFieldValue::U16 { value: raw as u16 })
    } else if load.is_int() || load.bf_size > 0 {
        Ok(SkbFieldValue::U32 { value: raw as u32 })
    } else {
        Ok(SkbFieldValue::U64 { value: raw })
    }
}

#[cfg(feature = "benchmark")]
pub(crate) mod benchmark {
    use anyhow::Result;

    use super::*;
    use crate::{benchmark::helpers::*, core::events::FactoryId};

    impl RawSectionBuilder for skb_packet_event {
        fn build_raw(out: &mut Vec<u8>) -> Result<()> {
            let data = Self {
                len: 66,
                capture_len: 66,
                packet: [
                    46, 137, 59, 254, 34, 122, 42, 186, 90, 193, 129, 79, 8, 0, 69, 0, 0, 52, 32,
                    32, 64, 0, 55, 6, 237, 160, 1, 1, 1, 1, 10, 0, 42, 2, 1, 187, 157, 12, 31, 149,
                    22, 86, 145, 251, 180, 241, 128, 17, 0, 8, 17, 72, 0, 0, 1, 1, 8, 10, 28, 109,
                    231, 120, 127, 134, 144, 92, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
            };
            build_raw_section(
                out,
                FactoryId::Skb as u8,
                SECTION_PACKET as u8,
                &mut as_u8_vec(&data),
            );
            Ok(())
        }
    }
}
