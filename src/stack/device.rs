use std::collections::VecDeque;

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

use crate::bpf::FrameIo;
use crate::Result;

use super::icmp::{classify_ethernet_ipv4_icmp_unreachable, IcmpDisposition};

pub(crate) struct StackDevice<D: FrameIo> {
    inner: D,
    rx_queue: VecDeque<Vec<u8>>,
    tx_error: Option<crate::Error>,
    icmp_service_ports: Vec<u16>,
    ignored_icmp_count: usize,
}

impl<D: FrameIo> StackDevice<D> {
    #[cfg(test)]
    pub(crate) fn new(inner: D) -> Self {
        Self {
            inner,
            rx_queue: VecDeque::new(),
            tx_error: None,
            icmp_service_ports: Vec::new(),
            ignored_icmp_count: 0,
        }
    }

    pub(crate) fn new_for_service_ports(inner: D, service_ports: Vec<u16>) -> Self {
        Self {
            inner,
            rx_queue: VecDeque::new(),
            tx_error: None,
            icmp_service_ports: service_ports,
            ignored_icmp_count: 0,
        }
    }

    #[cfg(test)]
    fn into_inner(self) -> D {
        self.inner
    }

    fn refill_rx_queue(&mut self) -> Result<()> {
        let mut frames = Vec::new();
        self.inner.read_frames(&mut frames)?;
        for frame in frames {
            if self.should_ignore_icmp(&frame) {
                self.ignored_icmp_count += 1;
            } else {
                self.rx_queue.push_back(frame);
            }
        }
        Ok(())
    }

    pub(crate) fn take_tx_error(&mut self) -> Option<crate::Error> {
        self.tx_error.take()
    }

    pub(crate) fn take_ignored_icmp_count(&mut self) -> usize {
        let count = self.ignored_icmp_count;
        self.ignored_icmp_count = 0;
        count
    }

    fn should_ignore_icmp(&self, frame: &[u8]) -> bool {
        if self.icmp_service_ports.is_empty() {
            return false;
        }
        matches!(
            classify_ethernet_ipv4_icmp_unreachable(frame, &self.icmp_service_ports),
            IcmpDisposition::IgnoreAndCount
        )
    }
}

impl<D: FrameIo> Device for StackDevice<D> {
    type RxToken<'a>
        = StackRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = StackTxToken<'a, D>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.rx_queue.is_empty() && self.refill_rx_queue().is_err() {
            return None;
        }

        let frame = self.rx_queue.pop_front()?;
        Some((
            StackRxToken { frame },
            StackTxToken {
                inner: &mut self.inner,
                tx_error: &mut self.tx_error,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(StackTxToken {
            inner: &mut self.inner,
            tx_error: &mut self.tx_error,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ethernet;
        capabilities.max_transmission_unit = self.inner.mtu();
        capabilities
    }
}

pub(crate) struct StackRxToken {
    frame: Vec<u8>,
}

impl RxToken for StackRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.frame)
    }
}

pub(crate) struct StackTxToken<'a, D: FrameIo> {
    inner: &'a mut D,
    tx_error: &'a mut Option<crate::Error>,
}

impl<D: FrameIo> TxToken for StackTxToken<'_, D> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut frame = vec![0; len];
        let result = f(&mut frame);
        if let Err(err) = self.inner.write_frame(&frame) {
            *self.tx_error = Some(err);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use smoltcp::phy::{Device, Medium, TxToken};
    use smoltcp::time::Instant;

    use crate::bpf::FrameIo;

    #[derive(Debug)]
    struct FakeFrameIo {
        mtu: usize,
        readable: Vec<Vec<u8>>,
        written: Vec<Vec<u8>>,
    }

    impl FakeFrameIo {
        fn new(mtu: usize) -> Self {
            Self {
                mtu,
                readable: Vec::new(),
                written: Vec::new(),
            }
        }

        fn with_readable(mtu: usize, readable: Vec<Vec<u8>>) -> Self {
            Self {
                mtu,
                readable,
                written: Vec::new(),
            }
        }
    }

    impl FrameIo for FakeFrameIo {
        fn read_frames(&mut self, out: &mut Vec<Vec<u8>>) -> crate::Result<usize> {
            let count = self.readable.len();
            out.append(&mut self.readable);
            Ok(count)
        }

        fn write_frame(&mut self, frame: &[u8]) -> crate::Result<()> {
            self.written.push(frame.to_vec());
            Ok(())
        }

        fn mtu(&self) -> usize {
            self.mtu
        }
    }

    #[derive(Debug)]
    struct FailingFrameIo;

    impl FrameIo for FailingFrameIo {
        fn read_frames(&mut self, _out: &mut Vec<Vec<u8>>) -> crate::Result<usize> {
            Ok(0)
        }

        fn write_frame(&mut self, _frame: &[u8]) -> crate::Result<()> {
            Err(crate::Error::PacketParse("write failed"))
        }

        fn mtu(&self) -> usize {
            1500
        }
    }

    #[test]
    fn stack_device_capabilities_are_ethernet_with_configured_mtu() {
        let device = super::StackDevice::new(FakeFrameIo::new(1420));
        let capabilities = device.capabilities();

        assert_eq!(capabilities.medium, Medium::Ethernet);
        assert_eq!(capabilities.max_transmission_unit, 1420);
    }

    #[test]
    fn stack_device_tx_writes_complete_ethernet_frame_to_device() {
        let mut device = super::StackDevice::new(FakeFrameIo::new(1500));
        let token = device
            .transmit(Instant::from_millis(0))
            .expect("tx token is available");

        token.consume(14, |frame| {
            frame.copy_from_slice(&[0xaa; 14]);
        });

        assert_eq!(device.into_inner().written, vec![vec![0xaa; 14]]);
    }

    #[test]
    fn stack_device_records_tx_write_errors() {
        let mut device = super::StackDevice::new(FailingFrameIo);
        let token = device
            .transmit(Instant::from_millis(0))
            .expect("tx token is available");

        token.consume(14, |_| {});

        assert!(matches!(
            device.take_tx_error(),
            Some(crate::Error::PacketParse(_))
        ));
    }

    #[test]
    fn stack_device_ignores_related_icmp_port_unreachable_before_receive() {
        let frame = ethernet_ipv4_frame(related_port_unreachable_packet(40000));
        let mut device = super::StackDevice::new_for_service_ports(
            FakeFrameIo::with_readable(1500, vec![frame]),
            vec![40001, 40000],
        );

        assert!(device.receive(Instant::from_millis(0)).is_none());
        assert_eq!(device.take_ignored_icmp_count(), 1);
    }

    fn ethernet_ipv4_frame(ipv4_packet: Vec<u8>) -> Vec<u8> {
        let mut frame = vec![0; 14];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&ipv4_packet);
        frame
    }

    fn related_port_unreachable_packet(service_port: u16) -> Vec<u8> {
        let mut packet = vec![0; 20 + 8 + 20 + 8];
        packet[0] = 0x45;
        packet[9] = 1;
        packet[20] = 3;
        packet[21] = 3;

        let quoted_ip = 28;
        packet[quoted_ip] = 0x45;
        packet[quoted_ip + 9] = 17;

        let quoted_udp = quoted_ip + 20;
        packet[quoted_udp..quoted_udp + 2].copy_from_slice(&12345u16.to_be_bytes());
        packet[quoted_udp + 2..quoted_udp + 4].copy_from_slice(&service_port.to_be_bytes());
        packet[quoted_udp + 4..quoted_udp + 6].copy_from_slice(&8u16.to_be_bytes());
        packet
    }
}
