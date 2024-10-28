/* automatically generated by rust-bindgen 0.70.1 */

pub type __u8 = ::std::os::raw::c_uchar;
pub type __u32 = ::std::os::raw::c_uint;
pub type __u64 = ::std::os::raw::c_ulonglong;
pub type u8_ = __u8;
pub type u32_ = __u32;
pub type u64_ = __u64;
pub type bool_ = bool;
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct ovs_operation_event {
    pub batch_ts: u64_,
    pub queue_id: u32_,
    pub batch_idx: u8_,
    pub type_: u8_,
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct user_upcall_info {
    pub queue_id: u32_,
    pub skip_event: bool_,
    pub processed_ops: u8_,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct upcall_batch {
    pub leader_ts: u64_,
    pub processing: bool_,
    pub upcalls: [user_upcall_info; 64usize],
    pub current_upcall: u8_,
    pub total: u8_,
}
impl Default for upcall_batch {
    fn default() -> Self {
        let mut s = ::std::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}