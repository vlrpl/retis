use std::{mem, slice};

use anyhow::Result;

use crate::{
    core::{events::*, probe::kernel::RawKernelEvent},
    events::*,
    module::{ct::bpf::*, ovs::bpf::*, skb::bpf::*},
};

/// Raw event sections can implement this trait to provide a way to build a raw
/// event represented as an u8 vector.
///
/// It's important here to build the raw sections using `Default::default()`
/// whenever possible so that changes to the raw event sections do not impact
/// the `RawSectionBuilder` implementations.
///
/// The actual sections content does not matter much, except when field values
/// impact the unmarshaling logic (and thus performances). Eg. if a common
/// unmarshaling part is skipped if a field is not set, it should be set.
pub(crate) trait RawSectionBuilder {
    fn build_raw(out: &mut Vec<u8>) -> Result<()>;
}

/// Build a raw event section in an existing raw event vector.
pub(crate) fn build_raw_section(event: &mut Vec<u8>, owner: u8, data_type: u8, data: &mut Vec<u8>) {
    let header = BpfRawSectionHeader {
        owner,
        data_type,
        size: data.len() as u16,
    };

    event.append(&mut as_u8_vec(&header));
    event.append(data);
}

/// Represent any type as a Vec of u8. Works best for packed structs.
pub(crate) fn as_u8_vec<T: Sized>(input: &T) -> Vec<u8> {
    unsafe { slice::from_raw_parts((input as *const T) as *const u8, mem::size_of::<T>()) }.to_vec()
}

/// Construct a raw event and represent it as an u8 vector.
///
/// It's important below to construct all the sub-sections using
/// `Default::default()` and only then to set the fields we want to be set. This
/// is to ensure modification in sub-sections won't impact this function for
/// every change.
pub(super) fn build_raw_event() -> Result<Vec<u8>> {
    let mut event = Vec::with_capacity(BPF_RAW_EVENT_DATA_SIZE);

    // Build sections.
    RawCommonEvent::build_raw(&mut event)?;
    RawTaskEvent::build_raw(&mut event)?;
    RawKernelEvent::build_raw(&mut event)?;
    SkbTrackingEvent::build_raw(&mut event)?;
    RawDevEvent::build_raw(&mut event)?;
    RawNsEvent::build_raw(&mut event)?;
    RawPacketEvent::build_raw(&mut event)?;
    RawCtMetaEvent::build_raw(&mut event)?;
    RawCtEvent::build_raw(&mut event)?;
    BpfActionEvent::build_raw(&mut event)?;

    // Construct the raw event.
    let size = event.len() as u16;
    event.append(&mut vec![0; BPF_RAW_EVENT_DATA_SIZE - event.len()]);
    let raw = RawEvent {
        size,
        data: event
            .try_into()
            .expect("Could not convert event Vec to [u8]"),
    };

    // And convert it to a Vec<u8>.
    Ok(as_u8_vec(&raw))
}