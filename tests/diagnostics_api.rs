use std::net::Ipv4Addr;

use bpflink::TransportMode;
use bpflink::{diagnostics, Error};

#[test]
fn probe_rejects_empty_interface_name() {
    let err = diagnostics::probe_bpf_interface("").unwrap_err();

    assert!(matches!(err, Error::Config("interface must not be empty")));
}

#[tokio::test]
async fn runtime_probe_rejects_empty_interface_name() {
    let err = diagnostics::probe_runtime_command_loop(diagnostics::RuntimeProbeConfig {
        interface: "".to_string(),
        local_ip: Ipv4Addr::new(127, 0, 0, 1).into(),
        service_ports: vec![40000],
        active_service_port: 40000,
        connect_peer_ip: None,
        write_payload: None,
        transport_mode: TransportMode::Simple,
    })
    .await
    .unwrap_err();

    assert!(matches!(err, Error::Config("interface must not be empty")));
}

#[tokio::test]
async fn runtime_probe_config_accepts_kcp_transport_mode() {
    let err = diagnostics::probe_runtime_command_loop(diagnostics::RuntimeProbeConfig {
        interface: "".to_string(),
        local_ip: Ipv4Addr::new(127, 0, 0, 1).into(),
        service_ports: vec![40000],
        active_service_port: 40000,
        connect_peer_ip: None,
        write_payload: None,
        transport_mode: TransportMode::Kcp,
    })
    .await
    .unwrap_err();

    assert!(matches!(err, Error::Config("interface must not be empty")));
}

#[tokio::test]
async fn runtime_probe_rejects_empty_service_port_set() {
    let err = diagnostics::probe_runtime_command_loop(diagnostics::RuntimeProbeConfig {
        interface: "en0".to_string(),
        local_ip: Ipv4Addr::new(127, 0, 0, 1).into(),
        service_ports: vec![],
        active_service_port: 40000,
        connect_peer_ip: None,
        write_payload: None,
        transport_mode: TransportMode::Kcp,
    })
    .await
    .unwrap_err();

    assert!(matches!(
        err,
        Error::Config("service_ports must not be empty")
    ));
}

#[tokio::test]
async fn runtime_probe_rejects_unconfigured_active_service_port() {
    let err = diagnostics::probe_runtime_command_loop(diagnostics::RuntimeProbeConfig {
        interface: "en0".to_string(),
        local_ip: Ipv4Addr::new(127, 0, 0, 1).into(),
        service_ports: vec![40000],
        active_service_port: 40001,
        connect_peer_ip: None,
        write_payload: None,
        transport_mode: TransportMode::Kcp,
    })
    .await
    .unwrap_err();

    assert!(matches!(
        err,
        Error::ServicePortNotConfigured { requested: 40001 }
    ));
}
