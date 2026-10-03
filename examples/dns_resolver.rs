use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bpflink::{parse_scoped_ip, Error, Link, PeerAddr, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QueryType {
    A,
    Aaaa,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QuerySelection {
    A,
    Aaaa,
    Both,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DnsRecord {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Config {
    interface: String,
    local_ip: IpAddr,
    local_port: u16,
    dns_server: IpAddr,
    dns_port: u16,
    name: String,
    query: QuerySelection,
    timeout: Duration,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let config = Config::parse_from(env::args())?;
    run(config).await
}

async fn run(config: Config) -> Result<()> {
    eprintln!(
        "bpflink dns_resolver: interface={} local_ip={} local_port={} dns_server={} dns_port={} name={} type={}",
        config.interface,
        config.local_ip,
        config.local_port,
        config.dns_server,
        config.dns_port,
        config.name,
        config.query.name()
    );

    let link = Link::builder()
        .interface(config.interface.clone())
        .local_ip(config.local_ip)
        .service_ports([config.local_port])
        .build()
        .await?;
    let socket = link.udp_socket(config.local_port).await?;
    let mut records = Vec::new();

    for query_type in config.query.query_types().iter().copied() {
        let id = transaction_id(query_type);
        let query = encode_query(&config.name, query_type, id)?;
        socket
            .send_to(
                &query,
                PeerAddr {
                    ip: config.dns_server,
                },
                config.dns_port,
            )
            .await?;
        let packet = socket.recv_from_timeout(config.timeout).await?;
        if packet.source.ip() != config.dns_server || packet.source.port() != config.dns_port {
            return Err(Error::PacketParse("dns response source mismatch"));
        }
        records.extend(parse_response(&packet.payload, id, query_type)?);
    }

    for record in records {
        match record {
            DnsRecord::A(addr) => println!("A {addr}"),
            DnsRecord::Aaaa(addr) => println!("AAAA {addr}"),
        }
    }

    link.shutdown().await?;
    Ok(())
}

impl Config {
    fn parse_from<I, S>(args: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let args: Vec<String> = args.into_iter().map(Into::into).collect();
        let interface = value(&args, "--interface")?.to_string();
        let local_ip = parse_scoped_ip(
            value_any(&args, &["--local-ip", "--local-ipv4"])?,
            &interface,
        )?;
        let dns_server = parse_scoped_ip(value(&args, "--dns-server")?, &interface)?;
        let local_port = parse_nonzero_u16(value(&args, "--local-port")?, "--local-port")?;
        let dns_port = optional_value(&args, "--dns-port")
            .map(|value| parse_nonzero_u16(value, "--dns-port"))
            .transpose()?
            .unwrap_or(53);
        let name = value(&args, "--name")?.to_string();
        let query = QuerySelection::parse(optional_value(&args, "--type").unwrap_or("both"))?;
        let timeout = optional_value(&args, "--timeout-ms")
            .map(|value| {
                value
                    .parse::<u64>()
                    .map(Duration::from_millis)
                    .map_err(|_| Error::Config("invalid --timeout-ms"))
            })
            .transpose()?
            .unwrap_or(Duration::from_millis(3000));

        Ok(Self {
            interface,
            local_ip,
            local_port,
            dns_server,
            dns_port,
            name,
            query,
            timeout,
        })
    }
}

impl QuerySelection {
    fn parse(input: &str) -> Result<Self> {
        match input {
            "A" | "a" => Ok(Self::A),
            "AAAA" | "aaaa" => Ok(Self::Aaaa),
            "both" => Ok(Self::Both),
            _ => Err(Error::Config("invalid --type")),
        }
    }

    fn query_types(self) -> &'static [QueryType] {
        match self {
            Self::A => &[QueryType::A],
            Self::Aaaa => &[QueryType::Aaaa],
            Self::Both => &[QueryType::A, QueryType::Aaaa],
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Both => "both",
        }
    }
}

impl QueryType {
    fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
        }
    }
}

fn encode_query(name: &str, query_type: QueryType, id: u16) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    encode_name(name, &mut out)?;
    out.extend_from_slice(&query_type.code().to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    Ok(out)
}

fn encode_name(name: &str, out: &mut Vec<u8>) -> Result<()> {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > 253 {
        return Err(Error::Config("invalid dns name"));
    }
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(Error::Config("invalid dns label"));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

fn parse_response(
    packet: &[u8],
    expected_id: u16,
    query_type: QueryType,
) -> Result<Vec<DnsRecord>> {
    if packet.len() < 12 {
        return Err(Error::PacketParse("truncated dns packet"));
    }
    let id = read_u16(packet, 0)?;
    if id != expected_id {
        return Err(Error::PacketParse("dns transaction id mismatch"));
    }
    let flags = read_u16(packet, 2)?;
    if flags & 0x000f != 0 {
        return Err(Error::PacketParse("dns rcode error"));
    }
    let question_count = read_u16(packet, 4)? as usize;
    let answer_count = read_u16(packet, 6)? as usize;
    let mut offset = 12;

    for _ in 0..question_count {
        offset = skip_name(packet, offset)?;
        offset = checked_add(offset, 4, packet.len())?;
    }

    let mut records = Vec::new();
    for _ in 0..answer_count {
        offset = skip_name(packet, offset)?;
        offset = checked_add(offset, 10, packet.len())?;
        let typ = read_u16(packet, offset - 10)?;
        let class = read_u16(packet, offset - 8)?;
        let rdlen = read_u16(packet, offset - 2)? as usize;
        let rdata_offset = offset;
        offset = checked_add(offset, rdlen, packet.len())?;
        if class != 1 || typ != query_type.code() {
            continue;
        }
        match (query_type, rdlen) {
            (QueryType::A, 4) => records.push(DnsRecord::A(Ipv4Addr::new(
                packet[rdata_offset],
                packet[rdata_offset + 1],
                packet[rdata_offset + 2],
                packet[rdata_offset + 3],
            ))),
            (QueryType::Aaaa, 16) => {
                let mut octets = [0; 16];
                octets.copy_from_slice(&packet[rdata_offset..rdata_offset + 16]);
                records.push(DnsRecord::Aaaa(Ipv6Addr::from(octets)));
            }
            _ => {}
        }
    }

    Ok(records)
}

fn skip_name(packet: &[u8], mut offset: usize) -> Result<usize> {
    loop {
        if offset >= packet.len() {
            return Err(Error::PacketParse("truncated dns packet"));
        }
        let len = packet[offset];
        if len & 0xc0 == 0xc0 {
            return checked_add(offset, 2, packet.len());
        }
        if len & 0xc0 != 0 {
            return Err(Error::PacketParse("invalid dns name"));
        }
        offset += 1;
        if len == 0 {
            return Ok(offset);
        }
        offset = checked_add(offset, len as usize, packet.len())?;
    }
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16> {
    if offset + 2 > packet.len() {
        return Err(Error::PacketParse("truncated dns packet"));
    }
    Ok(u16::from_be_bytes([packet[offset], packet[offset + 1]]))
}

fn checked_add(offset: usize, len: usize, packet_len: usize) -> Result<usize> {
    let end = offset
        .checked_add(len)
        .ok_or(Error::PacketParse("truncated dns packet"))?;
    if end > packet_len {
        return Err(Error::PacketParse("truncated dns packet"));
    }
    Ok(end)
}

fn transaction_id(query_type: QueryType) -> u16 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos())
        .unwrap_or(0);
    let salt = match query_type {
        QueryType::A => 0x1001,
        QueryType::Aaaa => 0x1c1c,
    };
    (nanos as u16) ^ salt
}

fn parse_nonzero_u16(input: &str, flag: &'static str) -> Result<u16> {
    let value = input.parse().map_err(|_| Error::Config(flag))?;
    if value == 0 {
        return Err(Error::Config(flag));
    }
    Ok(value)
}

fn value<'a>(args: &'a [String], flag: &str) -> Result<&'a str> {
    optional_value(args, flag).ok_or(Error::Config("missing required argument"))
}

fn value_any<'a>(args: &'a [String], flags: &[&str]) -> Result<&'a str> {
    flags
        .iter()
        .find_map(|flag| optional_value(args, flag))
        .ok_or(Error::Config("missing required argument"))
}

fn optional_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find_map(|pair| (pair[0] == flag).then_some(pair[1].as_str()))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn encodes_a_query_with_one_question() {
        let query = super::encode_query("example.com", super::QueryType::A, 0x1234).unwrap();

        assert_eq!(
            &query[0..12],
            &[0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            &query[12..],
            &[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,]
        );
    }

    #[test]
    fn parses_compressed_a_answer() {
        let response = response_with_answer(0x1234, 1, &[192, 0, 2, 10]);

        let records = super::parse_response(&response, 0x1234, super::QueryType::A).unwrap();

        assert_eq!(
            records,
            vec![super::DnsRecord::A(Ipv4Addr::new(192, 0, 2, 10))]
        );
    }

    #[test]
    fn parses_compressed_aaaa_answer() {
        let response = response_with_answer(
            0x1234,
            28,
            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        );

        let records = super::parse_response(&response, 0x1234, super::QueryType::Aaaa).unwrap();

        assert_eq!(
            records,
            vec![super::DnsRecord::Aaaa(Ipv6Addr::new(
                0x2001, 0x0db8, 0, 0, 0, 0, 0, 1
            ))]
        );
    }

    #[test]
    fn rejects_transaction_id_mismatch() {
        let response = response_with_answer(0x1234, 1, &[192, 0, 2, 10]);
        let err = super::parse_response(&response, 0x4321, super::QueryType::A).unwrap_err();

        assert!(matches!(
            err,
            bpflink::Error::PacketParse("dns transaction id mismatch")
        ));
    }

    #[test]
    fn rejects_nonzero_rcode() {
        let mut response = response_with_answer(0x1234, 1, &[192, 0, 2, 10]);
        response[3] = 0x83;
        let err = super::parse_response(&response, 0x1234, super::QueryType::A).unwrap_err();

        assert!(matches!(
            err,
            bpflink::Error::PacketParse("dns rcode error")
        ));
    }

    #[test]
    fn rejects_truncated_answers() {
        let mut response = response_with_answer(0x1234, 1, &[192, 0, 2, 10]);
        response.truncate(response.len() - 2);
        let err = super::parse_response(&response, 0x1234, super::QueryType::A).unwrap_err();

        assert!(matches!(
            err,
            bpflink::Error::PacketParse("truncated dns packet")
        ));
    }

    fn response_with_answer(id: u16, answer_type: u16, rdata: &[u8]) -> Vec<u8> {
        let mut out = vec![
            (id >> 8) as u8,
            id as u8,
            0x81,
            0x80,
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            7,
            b'e',
            b'x',
            b'a',
            b'm',
            b'p',
            b'l',
            b'e',
            3,
            b'c',
            b'o',
            b'm',
            0,
            0,
            answer_type as u8,
            0,
            1,
            0xc0,
            0x0c,
            0,
            answer_type as u8,
            0,
            1,
            0,
            0,
            0,
            60,
            (rdata.len() >> 8) as u8,
            rdata.len() as u8,
        ];
        out.extend_from_slice(rdata);
        out
    }
}
