use std::collections::HashMap;

use crate::{Error, Result};

pub(crate) const BPF_LD: u16 = 0x00;
pub(crate) const BPF_JMP: u16 = 0x05;
pub(crate) const BPF_RET: u16 = 0x06;
pub(crate) const BPF_H: u16 = 0x08;
pub(crate) const BPF_B: u16 = 0x10;
pub(crate) const BPF_ABS: u16 = 0x20;
pub(crate) const BPF_K: u16 = 0x00;
pub(crate) const BPF_JEQ: u16 = 0x10;
pub(crate) const BPF_JSET: u16 = 0x40;

const ETHERTYPE_OFFSET: u32 = 12;
const ETHERTYPE_ARP: u32 = 0x0806;
const ETHERTYPE_IPV4: u32 = 0x0800;
const ETHERTYPE_IPV6: u32 = 0x86dd;
const IPV4_VERSION_IHL_OFFSET: u32 = 14;
const IPV4_VERSION_IHL_NO_OPTIONS: u32 = 0x45;
const IPV4_PROTOCOL_OFFSET: u32 = 23;
const IPV4_PROTOCOL_ICMP: u32 = 1;
const IPV4_PROTOCOL_UDP: u32 = 17;
const IPV4_FRAGMENT_OFFSET: u32 = 20;
const IPV4_FRAGMENT_MASK: u32 = 0x3fff;
const IPV4_UDP_SRC_PORT_OFFSET: u32 = 34;
const IPV4_UDP_DST_PORT_OFFSET: u32 = 36;
const IPV6_NEXT_HEADER_OFFSET: u32 = 20;
const IPV6_NEXT_HEADER_ICMPV6: u32 = 58;
const IPV6_NEXT_HEADER_UDP: u32 = 17;
const IPV6_NEXT_HEADER_HOP_BY_HOP: u32 = 0;
const IPV6_NEXT_HEADER_ROUTING: u32 = 43;
const IPV6_NEXT_HEADER_DESTINATION_OPTIONS: u32 = 60;
const IPV6_UDP_SRC_PORT_OFFSET: u32 = 54;
const IPV6_UDP_DST_PORT_OFFSET: u32 = 56;
const IPV6_EXTENSION_NEXT_HEADER_OFFSET: u32 = 54;
const IPV6_EXTENSION_LENGTH_OFFSET: u32 = 55;
const IPV6_EXTENSION_UDP_SRC_PORT_OFFSET: u32 = 62;
const IPV6_EXTENSION_UDP_DST_PORT_OFFSET: u32 = 64;
const BPF_ACCEPT_ALL: u32 = u32::MAX;
const BPF_DROP: u32 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct ClassicBpfInsn {
    pub(crate) code: u16,
    pub(crate) jt: u8,
    pub(crate) jf: u8,
    pub(crate) k: u32,
}

pub(crate) fn service_filter_program(service_ports: &[u16]) -> Result<Vec<ClassicBpfInsn>> {
    let service_ports = normalize_service_ports(service_ports)?;
    // Match service UDP only for unfragmented IPv4 packets without IPv4
    // options, direct IPv6 UDP, and one 8-byte IPv6 Hop-by-Hop/Routing/
    // Destination Options extension header before UDP. ARP, IPv4 ICMP, and
    // ICMPv6 are kept for neighbor discovery and host-stack error handling.
    let mut program = ProgramBuilder::default();
    program.stmt(BPF_LD | BPF_H | BPF_ABS, ETHERTYPE_OFFSET);
    program.jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        ETHERTYPE_ARP,
        Label::Accept,
        None,
    );
    program.jump(BPF_JMP | BPF_JEQ | BPF_K, ETHERTYPE_IPV4, Label::Ipv4, None);
    program.jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        ETHERTYPE_IPV6,
        Label::Ipv6,
        Label::Drop,
    );

    program.label(Label::Ipv4);
    program.stmt(BPF_LD | BPF_B | BPF_ABS, IPV4_VERSION_IHL_OFFSET);
    program.jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        IPV4_VERSION_IHL_NO_OPTIONS,
        Label::Ipv4Protocol,
        Label::Drop,
    );
    program.label(Label::Ipv4Protocol);
    program.stmt(BPF_LD | BPF_B | BPF_ABS, IPV4_PROTOCOL_OFFSET);
    program.jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        IPV4_PROTOCOL_ICMP,
        Label::Accept,
        None,
    );
    program.jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        IPV4_PROTOCOL_UDP,
        Label::Ipv4Fragment,
        Label::Drop,
    );
    program.label(Label::Ipv4Fragment);
    program.stmt(BPF_LD | BPF_H | BPF_ABS, IPV4_FRAGMENT_OFFSET);
    program.jump(
        BPF_JMP | BPF_JSET | BPF_K,
        IPV4_FRAGMENT_MASK,
        Label::Drop,
        None,
    );
    add_port_match(
        &mut program,
        IPV4_UDP_DST_PORT_OFFSET,
        IPV4_UDP_SRC_PORT_OFFSET,
        &service_ports,
    );
    program.jump(BPF_JMP | BPF_JEQ | BPF_K, 0, Label::Drop, Label::Drop);

    program.label(Label::Ipv6);
    program.stmt(BPF_LD | BPF_B | BPF_ABS, IPV6_NEXT_HEADER_OFFSET);
    program.jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        IPV6_NEXT_HEADER_ICMPV6,
        Label::Accept,
        None,
    );
    program.jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        IPV6_NEXT_HEADER_UDP,
        Label::Ipv6Udp,
        None,
    );
    program.jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        IPV6_NEXT_HEADER_HOP_BY_HOP,
        Label::Ipv6Extension,
        None,
    );
    program.jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        IPV6_NEXT_HEADER_ROUTING,
        Label::Ipv6Extension,
        None,
    );
    program.jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        IPV6_NEXT_HEADER_DESTINATION_OPTIONS,
        Label::Ipv6Extension,
        Label::Drop,
    );

    program.label(Label::Ipv6Udp);
    add_port_match(
        &mut program,
        IPV6_UDP_DST_PORT_OFFSET,
        IPV6_UDP_SRC_PORT_OFFSET,
        &service_ports,
    );
    program.jump(BPF_JMP | BPF_JEQ | BPF_K, 0, Label::Drop, Label::Drop);

    program.label(Label::Ipv6Extension);
    program.stmt(BPF_LD | BPF_B | BPF_ABS, IPV6_EXTENSION_LENGTH_OFFSET);
    program.jump(BPF_JMP | BPF_JEQ | BPF_K, 0, None, Label::Drop);
    program.stmt(BPF_LD | BPF_B | BPF_ABS, IPV6_EXTENSION_NEXT_HEADER_OFFSET);
    program.jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        IPV6_NEXT_HEADER_UDP,
        Label::Ipv6ExtensionUdp,
        Label::Drop,
    );
    program.label(Label::Ipv6ExtensionUdp);
    add_port_match(
        &mut program,
        IPV6_EXTENSION_UDP_DST_PORT_OFFSET,
        IPV6_EXTENSION_UDP_SRC_PORT_OFFSET,
        &service_ports,
    );
    program.jump(BPF_JMP | BPF_JEQ | BPF_K, 0, Label::Drop, Label::Drop);

    program.label(Label::Drop);
    program.stmt(BPF_RET | BPF_K, BPF_DROP);
    program.label(Label::Accept);
    program.stmt(BPF_RET | BPF_K, BPF_ACCEPT_ALL);
    program.finish()
}

pub(crate) fn normalize_service_ports(service_ports: &[u16]) -> Result<Vec<u16>> {
    if service_ports.is_empty() {
        return Err(Error::Config("service_ports must not be empty"));
    }
    let mut normalized = service_ports.to_vec();
    normalized.sort_unstable();
    normalized.dedup();
    if normalized.contains(&0) {
        return Err(Error::Config("service_ports must not contain zero"));
    }
    if normalized.len() > 16 {
        return Err(Error::Config("service_ports supports at most 16 ports"));
    }
    Ok(normalized)
}

fn add_port_match(
    program: &mut ProgramBuilder,
    dst_port_offset: u32,
    src_port_offset: u32,
    service_ports: &[u16],
) {
    program.stmt(BPF_LD | BPF_H | BPF_ABS, dst_port_offset);
    for port in service_ports {
        program.jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            u32::from(*port),
            Label::Accept,
            None,
        );
    }
    program.stmt(BPF_LD | BPF_H | BPF_ABS, src_port_offset);
    for port in service_ports {
        program.jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            u32::from(*port),
            Label::Accept,
            None,
        );
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum Label {
    Ipv4,
    Ipv4Protocol,
    Ipv4Fragment,
    Ipv6,
    Ipv6Udp,
    Ipv6Extension,
    Ipv6ExtensionUdp,
    Drop,
    Accept,
}

#[derive(Default)]
struct ProgramBuilder {
    instructions: Vec<PendingInstruction>,
    labels: HashMap<Label, usize>,
}

impl ProgramBuilder {
    fn label(&mut self, label: Label) {
        self.labels.insert(label, self.instructions.len());
    }

    fn stmt(&mut self, code: u16, k: u32) {
        self.instructions.push(PendingInstruction::Stmt { code, k });
    }

    fn jump(
        &mut self,
        code: u16,
        k: u32,
        jt: impl Into<Option<Label>>,
        jf: impl Into<Option<Label>>,
    ) {
        self.instructions.push(PendingInstruction::Jump {
            code,
            k,
            jt: jt.into(),
            jf: jf.into(),
        });
    }

    fn finish(self) -> Result<Vec<ClassicBpfInsn>> {
        self.instructions
            .iter()
            .enumerate()
            .map(|(index, instruction)| match instruction {
                PendingInstruction::Stmt { code, k } => Ok(ClassicBpfInsn {
                    code: *code,
                    jt: 0,
                    jf: 0,
                    k: *k,
                }),
                PendingInstruction::Jump { code, k, jt, jf } => Ok(ClassicBpfInsn {
                    code: *code,
                    jt: self.offset(index, *jt)?,
                    jf: self.offset(index, *jf)?,
                    k: *k,
                }),
            })
            .collect()
    }

    fn offset(&self, index: usize, label: Option<Label>) -> Result<u8> {
        let Some(label) = label else {
            return Ok(0);
        };
        let target = *self
            .labels
            .get(&label)
            .ok_or(Error::Config("internal BPF label is missing"))?;
        let offset = target
            .checked_sub(index + 1)
            .ok_or(Error::Config("internal BPF label points backwards"))?;
        u8::try_from(offset).map_err(|_| Error::Config("internal BPF jump is too large"))
    }
}

enum PendingInstruction {
    Stmt {
        code: u16,
        k: u32,
    },
    Jump {
        code: u16,
        k: u32,
        jt: Option<Label>,
        jf: Option<Label>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVICE_PORT: u16 = 40000;
    const SECOND_SERVICE_PORT: u16 = 40001;

    #[test]
    fn service_filter_accepts_control_and_matching_udp_only() {
        let program = service_filter_program(&[SERVICE_PORT]).unwrap();

        assert_ne!(run_filter(&program, &ethernet_frame(0x0806)), 0);
        assert_ne!(run_filter(&program, &ipv4_frame(1, 12345, 54321)), 0);
        assert_ne!(
            run_filter(&program, &ipv4_frame(17, 50000, SERVICE_PORT)),
            0
        );
        assert_ne!(
            run_filter(&program, &ipv4_frame(17, SERVICE_PORT, 50000)),
            0
        );
        assert_eq!(run_filter(&program, &ipv4_frame(17, 50000, 50001)), 0);
        assert_eq!(run_filter(&program, &ethernet_frame(0x86dd)), 0);
    }

    #[test]
    fn service_filter_drops_fragmented_or_optioned_udp() {
        let program = service_filter_program(&[SERVICE_PORT]).unwrap();

        assert_eq!(
            run_filter(&program, &ipv4_fragment_frame(17, 50000, SERVICE_PORT)),
            0
        );
        assert_eq!(
            run_filter(&program, &ipv4_options_frame(17, 50000, SERVICE_PORT)),
            0
        );
        assert_eq!(
            run_filter(
                &program,
                &ipv4_options_frame_with_fixed_offset_service_port(17, 50000, 50001)
            ),
            0
        );
        assert_eq!(run_filter(&program, &[0; 24]), 0);
    }

    #[test]
    fn service_filter_accepts_ipv6_icmpv6_and_matching_udp_only() {
        let program = service_filter_program(&[SERVICE_PORT]).unwrap();

        assert_ne!(run_filter(&program, &ipv6_frame(58, 12345, 54321)), 0);
        assert_ne!(
            run_filter(&program, &ipv6_frame(17, 50000, SERVICE_PORT)),
            0
        );
        assert_ne!(
            run_filter(&program, &ipv6_frame(17, SERVICE_PORT, 50000)),
            0
        );
        assert_eq!(run_filter(&program, &ipv6_frame(17, 50000, 50001)), 0);
        assert_eq!(run_filter(&program, &ipv6_frame(6, SERVICE_PORT, 50000)), 0);
    }

    #[test]
    fn service_filter_accepts_ipv6_udp_behind_common_extension_headers() {
        let program = service_filter_program(&[SERVICE_PORT]).unwrap();

        for next_header in [0, 43, 60] {
            assert_ne!(
                run_filter(
                    &program,
                    &ipv6_extension_udp_frame(next_header, 50000, SERVICE_PORT)
                ),
                0
            );
            assert_ne!(
                run_filter(
                    &program,
                    &ipv6_extension_udp_frame(next_header, SERVICE_PORT, 50000)
                ),
                0
            );
            assert_eq!(
                run_filter(
                    &program,
                    &ipv6_extension_udp_frame(next_header, 50000, 50001)
                ),
                0
            );
        }

        assert_eq!(
            run_filter(&program, &ipv6_extension_udp_frame(44, 50000, SERVICE_PORT)),
            0
        );
    }

    #[test]
    fn service_filter_accepts_any_configured_service_port() {
        let program = service_filter_program(&[SERVICE_PORT, SECOND_SERVICE_PORT]).unwrap();

        assert_ne!(
            run_filter(&program, &ipv4_frame(17, 50000, SERVICE_PORT)),
            0
        );
        assert_ne!(
            run_filter(&program, &ipv4_frame(17, SECOND_SERVICE_PORT, 50000)),
            0
        );
        assert_ne!(
            run_filter(&program, &ipv6_frame(17, 50000, SECOND_SERVICE_PORT)),
            0
        );
        assert_ne!(
            run_filter(
                &program,
                &ipv6_extension_udp_frame(60, SECOND_SERVICE_PORT, 50000)
            ),
            0
        );
        assert_eq!(run_filter(&program, &ipv4_frame(17, 50000, 50001)), 0);
    }

    #[test]
    fn service_ports_are_normalized_and_bounded() {
        assert_eq!(
            normalize_service_ports(&[SECOND_SERVICE_PORT, SERVICE_PORT, SERVICE_PORT]).unwrap(),
            vec![SERVICE_PORT, SECOND_SERVICE_PORT]
        );
        assert!(matches!(
            normalize_service_ports(&[0]).unwrap_err(),
            crate::Error::Config("service_ports must not contain zero")
        ));
        assert!(matches!(
            normalize_service_ports(&(1..=17).collect::<Vec<_>>()).unwrap_err(),
            crate::Error::Config("service_ports supports at most 16 ports")
        ));
    }

    fn run_filter(program: &[ClassicBpfInsn], frame: &[u8]) -> u32 {
        let mut accumulator = 0;
        let mut pc = 0usize;
        loop {
            let instruction = program[pc];
            match instruction.code {
                code if code == BPF_LD | BPF_H | BPF_ABS => {
                    let offset = instruction.k as usize;
                    let Some(bytes) = frame.get(offset..offset + 2) else {
                        return 0;
                    };
                    accumulator = u16::from_be_bytes([bytes[0], bytes[1]]) as u32;
                    pc += 1;
                }
                code if code == BPF_LD | BPF_B | BPF_ABS => {
                    let Some(byte) = frame.get(instruction.k as usize) else {
                        return 0;
                    };
                    accumulator = *byte as u32;
                    pc += 1;
                }
                code if code == BPF_JMP | BPF_JEQ | BPF_K => {
                    pc += if accumulator == instruction.k {
                        1 + instruction.jt as usize
                    } else {
                        1 + instruction.jf as usize
                    };
                }
                code if code == BPF_JMP | BPF_JSET | BPF_K => {
                    pc += if accumulator & instruction.k != 0 {
                        1 + instruction.jt as usize
                    } else {
                        1 + instruction.jf as usize
                    };
                }
                code if code == BPF_RET | BPF_K => return instruction.k,
                code => panic!("unsupported test instruction code {code:#x}"),
            }
        }
    }

    fn ethernet_frame(ethertype: u16) -> Vec<u8> {
        let mut frame = vec![0; 64];
        frame[12..14].copy_from_slice(&ethertype.to_be_bytes());
        frame
    }

    fn ipv4_frame(protocol: u8, src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut frame = ethernet_frame(0x0800);
        frame[14] = 0x45;
        frame[23] = protocol;
        frame[34..36].copy_from_slice(&src_port.to_be_bytes());
        frame[36..38].copy_from_slice(&dst_port.to_be_bytes());
        frame
    }

    fn ipv4_fragment_frame(protocol: u8, src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut frame = ipv4_frame(protocol, src_port, dst_port);
        frame[20..22].copy_from_slice(&1u16.to_be_bytes());
        frame
    }

    fn ipv4_options_frame(protocol: u8, src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut frame = ethernet_frame(0x0800);
        frame[14] = 0x46;
        frame[23] = protocol;
        frame[38..40].copy_from_slice(&src_port.to_be_bytes());
        frame[40..42].copy_from_slice(&dst_port.to_be_bytes());
        frame
    }

    fn ipv4_options_frame_with_fixed_offset_service_port(
        protocol: u8,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut frame = ipv4_options_frame(protocol, src_port, dst_port);
        frame[36..38].copy_from_slice(&SERVICE_PORT.to_be_bytes());
        frame
    }

    fn ipv6_frame(next_header: u8, src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut frame = ethernet_frame(0x86dd);
        frame[14] = 0x60;
        frame[20] = next_header;
        frame[54..56].copy_from_slice(&src_port.to_be_bytes());
        frame[56..58].copy_from_slice(&dst_port.to_be_bytes());
        frame
    }

    fn ipv6_extension_udp_frame(next_header: u8, src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut frame = ethernet_frame(0x86dd);
        frame.resize(14 + 40 + 8 + 8, 0);
        frame[14] = 0x60;
        frame[20] = next_header;
        frame[54] = 17;
        frame[62..64].copy_from_slice(&src_port.to_be_bytes());
        frame[64..66].copy_from_slice(&dst_port.to_be_bytes());
        frame
    }
}
