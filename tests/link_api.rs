#![cfg(feature = "test-util")]

use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use bpflink::{parse_scoped_ip, Error, Link, LinkConfig, PeerAddr, TestCommand};
use bpflink::{BpfUdpPacket, TransportMode};

#[tokio::test]
async fn builder_requires_interface_local_ip_and_service_ports() {
    let err = Link::builder()
        .local_ipv4(Ipv4Addr::new(192, 0, 2, 10))
        .service_ports([40000])
        .build()
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Config("interface is required")));

    let err = Link::builder()
        .interface("en0")
        .service_ports([40000])
        .build()
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Config("local_ip is required")));

    let err = Link::builder()
        .interface("en0")
        .local_ipv4(Ipv4Addr::new(192, 0, 2, 10))
        .build()
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        Error::Config("service_ports must not be empty")
    ));
}

#[tokio::test]
async fn builder_accepts_ipv4_compatibility_and_ipv6_local_addresses() {
    let _ipv4_builder = Link::builder()
        .interface("en0")
        .local_ipv4(Ipv4Addr::new(127, 0, 0, 1))
        .service_ports([40000]);
    let _ipv6_builder = Link::builder()
        .interface("en0")
        .local_ipv6(Ipv6Addr::LOCALHOST)
        .service_ports([40000]);
}

#[test]
fn parses_ipv6_link_local_scope_at_api_boundary() {
    assert_eq!(
        parse_scoped_ip("fe80::1%en0", "en0").unwrap(),
        IpAddr::V6("fe80::1".parse().unwrap())
    );
    assert_eq!(
        PeerAddr::parse_with_interface("fe80::2%en0", "en0").unwrap(),
        PeerAddr {
            ip: IpAddr::V6("fe80::2".parse().unwrap()),
        }
    );
}

#[test]
fn scoped_ip_rejects_mismatched_or_non_link_local_scope() {
    let mismatch = parse_scoped_ip("fe80::1%en1", "en0").unwrap_err();
    assert!(matches!(
        mismatch,
        Error::Config("IPv6 scope id must match interface")
    ));

    let non_link_local = parse_scoped_ip("fd00::1%en0", "en0").unwrap_err();
    assert!(matches!(
        non_link_local,
        Error::Config("IPv6 scope id is only supported for link-local addresses")
    ));
}

#[test]
fn builder_accepts_scoped_local_ip_after_interface() {
    let _builder = Link::builder()
        .interface("en0")
        .local_scoped_ip("fe80::1%en0")
        .unwrap()
        .service_ports([40000]);
}

#[test]
fn transport_mode_defaults_to_kcp() {
    assert_eq!(TransportMode::default(), TransportMode::Kcp);
}

#[tokio::test]
async fn builder_accepts_stable_transport_mode_selection() {
    let _kcp_builder = Link::builder()
        .interface("en0")
        .local_ipv4(Ipv4Addr::new(127, 0, 0, 1))
        .service_ports([40000])
        .transport_mode(TransportMode::Kcp);

    let _simple_builder = Link::builder()
        .interface("en0")
        .local_ipv4(Ipv4Addr::new(127, 0, 0, 1))
        .service_ports([40000])
        .transport_mode(TransportMode::Simple);
}

#[test]
fn link_config_validates_and_normalizes_public_runtime_configuration() {
    let config = LinkConfig::new(
        "en0",
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        [40002, 40001, 40002],
    )
    .transport_mode(TransportMode::Simple)
    .validate()
    .unwrap();

    assert_eq!(config.interface, "en0");
    assert_eq!(config.service_ports, vec![40001, 40002]);
    assert_eq!(config.transport_mode, TransportMode::Simple);
}

#[test]
fn link_config_rejects_invalid_configuration_before_runtime_starts() {
    let empty_interface = LinkConfig::new("", IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), [40000])
        .validate()
        .unwrap_err();
    assert!(matches!(
        empty_interface,
        Error::Config("interface must not be empty")
    ));

    let empty_ports = LinkConfig::new("en0", IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), [])
        .validate()
        .unwrap_err();
    assert!(matches!(
        empty_ports,
        Error::Config("service_ports must not be empty")
    ));
}

#[tokio::test]
async fn builder_rejects_empty_interface_and_zero_service_port_set() {
    let missing_interface = Link::builder()
        .interface("")
        .local_ipv4(Ipv4Addr::new(127, 0, 0, 1))
        .service_ports([40000])
        .build()
        .await
        .unwrap_err();
    assert!(matches!(missing_interface, Error::Config(_)));

    let zero_port = Link::builder()
        .interface("en0")
        .local_ipv4(Ipv4Addr::new(127, 0, 0, 1))
        .service_ports([0])
        .build()
        .await
        .unwrap_err();
    assert!(matches!(
        zero_port,
        Error::Config("service_ports must not contain zero")
    ));
}

#[tokio::test]
async fn stream_and_listener_are_created_from_link_handles() {
    let link = Link::new_for_test_with_service_ports([443]);
    let listener = link.listen(443).await.unwrap();
    let stream = link
        .connect(
            PeerAddr {
                ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)),
            },
            443,
        )
        .await
        .unwrap();

    assert_eq!(listener.service_port(), 443);
    assert_eq!(stream.service_port(), 443);
    assert_eq!(
        link.recorded_commands(),
        vec![
            TestCommand::Listen { service_port: 443 },
            TestCommand::Connect {
                peer: PeerAddr {
                    ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)),
                },
                service_port: 443,
            },
        ]
    );
}

#[tokio::test]
async fn test_link_can_use_any_configured_service_port() {
    let link = Link::new_for_test_with_service_ports([40006, 40007]);

    let listener = link.listen(40006).await.unwrap();
    let stream = link.connect(peer_addr(), 40006).await.unwrap();
    let second_listener = link.listen(40007).await.unwrap();
    let second_stream = link.connect(peer_addr(), 40007).await.unwrap();

    assert_eq!(listener.service_port(), 40006);
    assert_eq!(stream.service_port(), 40006);
    assert_eq!(stream.peer_addr(), Some(peer_addr()));
    assert_eq!(second_listener.service_port(), 40007);
    assert_eq!(second_stream.service_port(), 40007);
    assert_eq!(link.service_ports(), &[40006, 40007]);
}

#[tokio::test]
async fn link_timeout_helpers_cover_common_runtime_operations() {
    let link = Link::new_for_test_with_service_ports([40012]);
    let listener = link.listen(40012).await.unwrap();

    let pending_accept = listener.accept_timeout(Duration::from_millis(1)).await;
    assert!(matches!(pending_accept, Err(Error::Timeout)));

    let stream = link
        .connect_timeout(peer_addr(), 40012, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(stream.service_port(), 40012);

    let accepted = listener
        .accept_timeout(Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(accepted.service_port(), 40012);

    link.shutdown_timeout(Duration::from_secs(1)).await.unwrap();
    assert!(link
        .recorded_commands()
        .iter()
        .any(|command| matches!(command, TestCommand::Shutdown)));
}

#[tokio::test]
async fn configured_test_link_rejects_unconfigured_service_port() {
    let link = Link::new_for_test_with_service_ports([40007]);

    let err = link.listen(40008).await.unwrap_err();
    assert!(matches!(
        err,
        Error::ServicePortNotConfigured { requested: 40008 }
    ));

    let err = link.connect(peer_addr(), 40008).await.unwrap_err();
    assert!(matches!(
        err,
        Error::ServicePortNotConfigured { requested: 40008 }
    ));

    let err = link.udp_socket(40008).await.unwrap_err();
    assert!(matches!(
        err,
        Error::ServicePortNotConfigured { requested: 40008 }
    ));
}

#[tokio::test]
async fn udp_socket_is_created_from_link_and_records_sends() {
    let link = Link::new_for_test_with_service_ports([53000]);
    let socket = link.udp_socket(53000).await.unwrap();
    let peer = PeerAddr {
        ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
    };

    socket.send_to(b"dns-query", peer, 53).await.unwrap();

    assert_eq!(socket.service_port(), 53000);
    assert_eq!(
        link.recorded_commands(),
        vec![
            TestCommand::UdpSocket {
                service_port: 53000,
            },
            TestCommand::UdpSend {
                service_port: 53000,
                peer,
                peer_port: 53,
                len: 9,
            },
        ]
    );
}

#[tokio::test]
async fn test_link_delivers_injected_udp_datagrams() {
    let link = Link::new_for_test_with_service_ports([53001]);
    let socket = link.udp_socket(53001).await.unwrap();
    let source: SocketAddr = "192.0.2.53:53".parse().unwrap();

    link.inject_udp_datagram_for_test(
        53001,
        BpfUdpPacket {
            source,
            payload: b"dns-response".to_vec(),
        },
    )
    .unwrap();

    let packet = socket
        .recv_from_timeout(Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(packet.source, source);
    assert_eq!(packet.payload, b"dns-response");
}

#[tokio::test]
async fn test_link_stats_are_publicly_readable() {
    let link = Link::new_for_test_with_service_ports([40009]);
    let listener = link.listen(40009).await.unwrap();
    let _stream = link.connect(peer_addr(), 40009).await.unwrap();
    let _accepted = listener.accept().await.unwrap();

    let stats = link.stats().await.unwrap();

    assert_eq!(stats.service_ports, vec![40009]);
    assert_eq!(stats.listener_count, 1);
    assert_eq!(stats.session_count, 2);
    assert_eq!(stats.transport_mode, "kcp");
}

#[tokio::test]
async fn test_driver_records_ipv6_peer_addresses() {
    let link = Link::new_for_test_with_service_ports([443]);
    let peer = PeerAddr {
        ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
    };

    let stream = link.connect(peer, 443).await.unwrap_err();

    assert!(matches!(stream, Error::DriverClosed));
    assert_eq!(
        link.recorded_commands(),
        vec![TestCommand::Connect {
            peer,
            service_port: 443,
        }]
    );
}

fn peer_addr() -> PeerAddr {
    PeerAddr {
        ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)),
    }
}
