pub(crate) mod filter;
#[cfg(any(test, target_os = "macos"))]
pub(crate) mod frame;
pub(crate) mod ioctl;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
pub(crate) use macos::interface_default_gateway;
#[cfg(target_os = "macos")]
pub(crate) use macos::interface_ethernet_addr;
#[cfg(target_os = "macos")]
pub(crate) use macos::interface_ip_prefix_len;
#[cfg(target_os = "macos")]
pub(crate) use macos::BpfDevice;

#[cfg(target_os = "linux")]
pub(crate) use linux::interface_default_gateway;
#[cfg(target_os = "linux")]
pub(crate) use linux::interface_ethernet_addr;
#[cfg(target_os = "linux")]
pub(crate) use linux::interface_ip_prefix_len;
#[cfg(target_os = "linux")]
pub(crate) use linux::BpfDevice;

use crate::Result;

pub(crate) trait FrameIo {
    fn read_frames(&mut self, out: &mut Vec<Vec<u8>>) -> Result<usize>;
    fn write_frame(&mut self, frame: &[u8]) -> Result<()>;
    fn mtu(&self) -> usize;

    fn sees_sent_configured(&self) -> Option<bool> {
        None
    }

    fn filter_configured(&self) -> Option<bool> {
        None
    }
}
