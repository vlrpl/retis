/* automatically generated by rust-bindgen 0.70.1 */

pub type __u8 = ::std::os::raw::c_uchar;
pub type __u32 = ::std::os::raw::c_uint;
pub type u8_ = __u8;
pub type u32_ = __u32;
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct upcall_event {
    pub port: u32_,
    pub cpu: u32_,
    pub cmd: u8_,
}