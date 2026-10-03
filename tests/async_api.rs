#![cfg(feature = "test-util")]

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use bpflink::{BpfUdpPacket, Error, Link, PeerAddr, TestCommand};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn peer() -> PeerAddr {
    PeerAddr {
        ip: Ipv4Addr::new(10, 0, 0, 2).into(),
    }
}

#[tokio::test]
async fn listener_accepts_stream_from_shared_link() {
    let link = Link::new_for_test_with_service_ports([40000]);
    let listener = link.listen(40000).await.unwrap();
    let client = link.connect(peer(), 40000).await.unwrap();
    let server = listener.accept().await.unwrap();

    assert_eq!(client.service_port(), 40000);
    assert_eq!(server.service_port(), 40000);
    assert!(link.recorded_commands().contains(&TestCommand::Listen {
        service_port: 40000
    }));
    assert!(link.recorded_commands().iter().any(|command| matches!(
        command,
        TestCommand::Connect {
            service_port: 40000,
            ..
        }
    )));
}

#[tokio::test]
async fn stream_async_read_write_round_trips_bytes() {
    let link = Link::new_for_test_with_service_ports([40001]);
    let listener = link.listen(40001).await.unwrap();
    let mut client = link.connect(peer(), 40001).await.unwrap();
    let mut server = listener.accept().await.unwrap();

    client.write_all(b"ping").await.unwrap();
    let mut buf = [0; 4];
    server.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");

    server.write_all(b"pong").await.unwrap();
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");

    let commands = link.recorded_commands();
    assert!(commands
        .iter()
        .any(|command| matches!(command, TestCommand::StreamWrite { len: 4, .. })));
    assert!(commands
        .iter()
        .any(|command| matches!(command, TestCommand::StreamReadPoll { .. })));
}

#[tokio::test]
async fn zero_length_read_completes_immediately() {
    let link = Link::new_for_test_with_service_ports([40002]);
    let listener = link.listen(40002).await.unwrap();
    let _client = link.connect(peer(), 40002).await.unwrap();
    let mut server = listener.accept().await.unwrap();
    let mut buf = [];

    assert_eq!(server.read(&mut buf).await.unwrap(), 0);
}

#[tokio::test]
async fn dropping_stream_does_not_shutdown_link_or_other_streams() {
    let link = Link::new_for_test_with_service_ports([40003]);
    let listener = link.listen(40003).await.unwrap();

    let first = link.connect(peer(), 40003).await.unwrap();
    let accepted_first = listener.accept().await.unwrap();
    drop(first);
    drop(accepted_first);

    let mut second = link.connect(peer(), 40003).await.unwrap();
    let mut accepted_second = listener.accept().await.unwrap();

    second.write_all(b"still alive").await.unwrap();
    let mut buf = [0; 11];
    accepted_second.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"still alive");

    assert!(link
        .recorded_commands()
        .iter()
        .any(|command| matches!(command, TestCommand::Close { .. })));
}

#[tokio::test]
async fn stream_abort_closes_peer_and_keeps_link_available() {
    let link = Link::new_for_test_with_service_ports([40006]);
    let listener = link.listen(40006).await.unwrap();

    let client = link.connect(peer(), 40006).await.unwrap();
    let mut server = listener.accept().await.unwrap();
    client.abort().await.unwrap();

    let mut buf = [0; 1];
    assert_eq!(server.read(&mut buf).await.unwrap(), 0);
    assert!(link
        .recorded_commands()
        .iter()
        .any(|command| matches!(command, TestCommand::Abort { .. })));

    let mut second = link.connect(peer(), 40006).await.unwrap();
    let mut accepted_second = listener.accept().await.unwrap();
    second.write_all(b"alive").await.unwrap();
    let mut alive = [0; 5];
    accepted_second.read_exact(&mut alive).await.unwrap();
    assert_eq!(&alive, b"alive");
}

#[tokio::test]
async fn shared_link_routes_two_streams_independently() {
    let link = Link::new_for_test_with_service_ports([40004]);
    let listener = link.listen(40004).await.unwrap();

    let mut first_client = link.connect(peer(), 40004).await.unwrap();
    let mut first_server = listener.accept().await.unwrap();
    let mut second_client = link.connect(peer(), 40004).await.unwrap();
    let mut second_server = listener.accept().await.unwrap();

    first_client.write_all(b"first").await.unwrap();
    second_client.write_all(b"second").await.unwrap();

    let mut first_buf = [0; 5];
    first_server.read_exact(&mut first_buf).await.unwrap();
    assert_eq!(&first_buf, b"first");

    let mut second_buf = [0; 6];
    second_server.read_exact(&mut second_buf).await.unwrap();
    assert_eq!(&second_buf, b"second");

    assert_eq!(
        link.recorded_commands()
            .iter()
            .filter(|command| matches!(
                command,
                TestCommand::Connect {
                    service_port: 40004,
                    ..
                }
            ))
            .count(),
        2
    );
}

#[tokio::test]
async fn shared_link_routes_many_streams_under_pressure() {
    let link = Link::new_for_test_with_service_ports([40005]);
    let listener = link.listen(40005).await.unwrap();
    let mut pairs = Vec::new();

    for stream_index in 0..32usize {
        let client = link.connect(peer(), 40005).await.unwrap();
        let server = listener.accept().await.unwrap();
        pairs.push((stream_index, client, server));
    }

    for (stream_index, client, _) in &mut pairs {
        for round in 0..8usize {
            let payload = format!("stream={stream_index};round={round};");
            client.write_all(payload.as_bytes()).await.unwrap();
        }
    }

    for (stream_index, _, server) in &mut pairs {
        for round in 0..8usize {
            let payload = format!("stream={stream_index};round={round};");
            let mut buf = vec![0; payload.len()];
            server.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, payload.as_bytes());
        }
    }

    assert_eq!(
        link.recorded_commands()
            .iter()
            .filter(|command| matches!(
                command,
                TestCommand::Connect {
                    service_port: 40005,
                    ..
                }
            ))
            .count(),
        32
    );
}

#[tokio::test]
async fn listener_close_wakes_pending_accept() {
    let link = Link::new_for_test_with_service_ports([40010]);
    let listener = link.listen(40010).await.unwrap();
    let waiting_listener = listener.clone();

    let accept_task = tokio::spawn(async move { waiting_listener.accept().await });
    tokio::task::yield_now().await;

    listener.close();

    let err = accept_task.await.unwrap().unwrap_err();
    assert!(matches!(err, Error::ListenerClosed));
}

#[tokio::test]
async fn link_shutdown_closes_listener_and_stream_handles() {
    let link = Link::new_for_test_with_service_ports([40011]);
    let listener = link.listen(40011).await.unwrap();
    let mut client = link.connect(peer(), 40011).await.unwrap();
    let mut server = listener.accept().await.unwrap();

    link.shutdown().await.unwrap();

    let err = listener.accept().await.unwrap_err();
    assert!(matches!(err, Error::LinkClosed | Error::ListenerClosed));

    let mut buf = [0; 1];
    assert_eq!(server.read(&mut buf).await.unwrap(), 0);
    let err = client.write_all(b"after shutdown").await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
}

#[tokio::test]
async fn udp_socket_recv_timeout_and_close_wake_pending_receives() {
    let link = Link::new_for_test_with_service_ports([53002]);
    let socket = link.udp_socket(53002).await.unwrap();

    let timeout = socket.recv_from_timeout(Duration::from_millis(1)).await;
    assert!(matches!(timeout, Err(Error::Timeout)));

    let waiting = socket.clone();
    let recv_task = tokio::spawn(async move { waiting.recv_from().await });
    tokio::task::yield_now().await;
    socket.close();

    let err = recv_task.await.unwrap().unwrap_err();
    assert!(matches!(err, Error::LinkClosed));
}

#[tokio::test]
async fn udp_socket_receives_injected_datagrams_in_order() {
    let link = Link::new_for_test_with_service_ports([53003]);
    let socket = link.udp_socket(53003).await.unwrap();
    let first: SocketAddr = "192.0.2.53:53".parse().unwrap();
    let second: SocketAddr = "192.0.2.54:53".parse().unwrap();

    link.inject_udp_datagram_for_test(
        53003,
        BpfUdpPacket {
            source: first,
            payload: b"first".to_vec(),
        },
    )
    .unwrap();
    link.inject_udp_datagram_for_test(
        53003,
        BpfUdpPacket {
            source: second,
            payload: b"second".to_vec(),
        },
    )
    .unwrap();

    let first_packet = socket.recv_from().await.unwrap();
    let second_packet = socket.recv_from().await.unwrap();

    assert_eq!(first_packet.source, first);
    assert_eq!(first_packet.payload, b"first");
    assert_eq!(second_packet.source, second);
    assert_eq!(second_packet.payload, b"second");
}
