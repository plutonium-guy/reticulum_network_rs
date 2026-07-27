use reticulum_tokio::driver::DriverSnapshot;

pub fn format_status(snapshot: &DriverSnapshot) -> String {
    let mut lines = vec![format!("identity {}", hex::encode(snapshot.identity_hash))];
    if snapshot.interfaces.is_empty() {
        lines.push("interfaces none".to_string());
    } else {
        for interface in &snapshot.interfaces {
            lines.push(format!(
                "interface {} state={} rx_packets={} rx_bytes={} tx_packets={} tx_bytes={}",
                interface.id,
                if interface.online { "up" } else { "down" },
                interface.rx_packets,
                interface.rx_bytes,
                interface.tx_packets,
                interface.tx_bytes,
            ));
        }
    }
    lines.push(format!("paths {}", snapshot.paths.len()));
    lines.join("\n")
}

pub fn format_paths(snapshot: &DriverSnapshot, destination: Option<[u8; 16]>) -> String {
    let lines: Vec<_> = snapshot
        .paths
        .iter()
        .filter(|path| destination.is_none_or(|wanted| path.destination == wanted))
        .map(|path| {
            format!(
                "path {} hops={} interface={} next_hop={} timestamp={} expires_at={}",
                hex::encode(path.destination),
                path.hops,
                path.interface,
                path.next_hop_transport_id
                    .map(hex::encode)
                    .unwrap_or_else(|| "direct".to_string()),
                path.timestamp,
                path.expires_at,
            )
        })
        .collect();
    if lines.is_empty() {
        match destination {
            Some(destination) => format!("path {} not found", hex::encode(destination)),
            None => "paths none".to_string(),
        }
    } else {
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_tokio::driver::{InterfaceSnapshot, PathSnapshot};

    fn snapshot() -> DriverSnapshot {
        DriverSnapshot {
            identity_hash: [1; 16],
            interfaces: vec![InterfaceSnapshot {
                id: 7,
                online: true,
                rx_packets: 2,
                rx_bytes: 80,
                tx_packets: 3,
                tx_bytes: 120,
            }],
            paths: vec![PathSnapshot {
                destination: [2; 16],
                interface: 7,
                next_hop_transport_id: Some([3; 16]),
                hops: 2,
                expires_at: 900,
                timestamp: 100,
            }],
        }
    }

    #[test]
    fn formats_interface_state_and_counters() {
        assert_eq!(
            format_status(&snapshot()),
            concat!(
                "identity 01010101010101010101010101010101\n",
                "interface 7 state=up rx_packets=2 rx_bytes=80 ",
                "tx_packets=3 tx_bytes=120\n",
                "paths 1"
            )
        );
    }

    #[test]
    fn formats_filtered_paths_and_missing_destinations() {
        assert_eq!(
            format_paths(&snapshot(), Some([2; 16])),
            concat!(
                "path 02020202020202020202020202020202 hops=2 interface=7 ",
                "next_hop=03030303030303030303030303030303 timestamp=100 expires_at=900"
            )
        );
        assert_eq!(
            format_paths(&snapshot(), Some([9; 16])),
            "path 09090909090909090909090909090909 not found"
        );
    }
}
