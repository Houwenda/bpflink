use crate::{Error, Result};

const HEADER_LEN: usize = 20;
const PACKET_TYPE_CONNECT: u8 = 1;
const PACKET_TYPE_ACCEPT: u8 = 2;
const PACKET_TYPE_DATA: u8 = 3;
const PACKET_TYPE_FIN: u8 = 4;
const PACKET_TYPE_RESET: u8 = 5;
const PACKET_TYPE_PING: u8 = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PacketType {
    Connect,
    Accept,
    Data,
    Fin,
    Reset,
    Ping,
}

impl PacketType {
    fn as_u8(self) -> u8 {
        match self {
            Self::Connect => PACKET_TYPE_CONNECT,
            Self::Accept => PACKET_TYPE_ACCEPT,
            Self::Data => PACKET_TYPE_DATA,
            Self::Fin => PACKET_TYPE_FIN,
            Self::Reset => PACKET_TYPE_RESET,
            Self::Ping => PACKET_TYPE_PING,
        }
    }

    fn from_u8(value: u8) -> Result<Self> {
        match value {
            PACKET_TYPE_CONNECT => Ok(Self::Connect),
            PACKET_TYPE_ACCEPT => Ok(Self::Accept),
            PACKET_TYPE_DATA => Ok(Self::Data),
            PACKET_TYPE_FIN => Ok(Self::Fin),
            PACKET_TYPE_RESET => Ok(Self::Reset),
            PACKET_TYPE_PING => Ok(Self::Ping),
            _ => Err(Error::PacketParse("unknown bpflink packet type")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BpflinkHeader {
    pub(crate) packet_type: PacketType,
    pub(crate) service_port: u16,
    pub(crate) connection_id: u64,
    pub(crate) stream_id: u32,
}

impl BpflinkHeader {
    pub(crate) const MAGIC: [u8; 4] = *b"BPLK";
    pub(crate) const VERSION: u8 = 1;

    pub(crate) const fn encoded_len() -> usize {
        HEADER_LEN
    }

    pub(crate) fn encode(&self, payload: &[u8], out: &mut Vec<u8>) -> Result<()> {
        out.reserve(HEADER_LEN + payload.len());
        out.extend_from_slice(&Self::MAGIC);
        out.push(Self::VERSION);
        out.push(self.packet_type.as_u8());
        out.extend_from_slice(&self.service_port.to_be_bytes());
        out.extend_from_slice(&self.connection_id.to_be_bytes());
        out.extend_from_slice(&self.stream_id.to_be_bytes());
        out.extend_from_slice(payload);
        Ok(())
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::PacketParse("short bpflink header"));
        }
        if bytes[..4] != Self::MAGIC {
            return Err(Error::PacketParse("invalid bpflink magic"));
        }
        if bytes[4] != Self::VERSION {
            return Err(Error::PacketParse("unsupported bpflink version"));
        }

        let header = Self {
            packet_type: PacketType::from_u8(bytes[5])?,
            service_port: u16::from_be_bytes(bytes[6..8].try_into().expect("slice length")),
            connection_id: u64::from_be_bytes(bytes[8..16].try_into().expect("slice length")),
            stream_id: u32::from_be_bytes(bytes[16..20].try_into().expect("slice length")),
        };

        Ok((header, &bytes[HEADER_LEN..]))
    }
}

#[cfg(test)]
mod tests {
    use super::{BpflinkHeader, PacketType};

    #[test]
    fn transport_header_round_trips_with_payload() {
        let header = BpflinkHeader {
            packet_type: PacketType::Data,
            service_port: 40000,
            connection_id: 0x0102_0304_0506_0708,
            stream_id: 0x1122_3344,
        };
        let mut encoded = Vec::new();

        header.encode(b"hello", &mut encoded).unwrap();
        let (decoded, payload) = BpflinkHeader::decode(&encoded).unwrap();

        assert_eq!(decoded, header);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn transport_header_malformed_magic_version_or_short_header_is_rejected() {
        let mut encoded = Vec::new();
        BpflinkHeader {
            packet_type: PacketType::Ping,
            service_port: 7,
            connection_id: 1,
            stream_id: 2,
        }
        .encode(b"", &mut encoded)
        .unwrap();

        assert!(matches!(
            BpflinkHeader::decode(&encoded[..encoded.len() - 1]),
            Err(crate::Error::PacketParse(_))
        ));

        let mut bad_magic = encoded.clone();
        bad_magic[0] = b'x';
        assert!(matches!(
            BpflinkHeader::decode(&bad_magic),
            Err(crate::Error::PacketParse(_))
        ));

        let mut bad_version = encoded;
        bad_version[4] = 0xff;
        assert!(matches!(
            BpflinkHeader::decode(&bad_version),
            Err(crate::Error::PacketParse(_))
        ));
    }
}
