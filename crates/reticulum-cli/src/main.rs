mod config;

use std::{error::Error, io, path::PathBuf, time::Duration};

use config::{Config, IfacSettings, InterfaceConfig, save_or_create_identity};
use reticulum_node::{Event, node::Node};
use reticulum_tokio::{
    SystemClock,
    driver::{Driver, DriverHandle},
    interface::{AsyncInterface, IfacConfig, with_ifac},
    tcp::{TcpClientInterface, TcpServerInterface},
    udp::UdpInterface,
};
use tokio::sync::mpsc;

enum Mode {
    Run,
    Announce,
    Send {
        dest_hash: [u8; 16],
        plaintext: Vec<u8>,
        prove: bool,
    },
    SendGroup {
        dest_hash: [u8; 16],
        plaintext: Vec<u8>,
    },
    SendPlain {
        dest_hash: [u8; 16],
        plaintext: Vec<u8>,
    },
    Link {
        dest_hash: [u8; 16],
        plaintext: Option<Vec<u8>>,
    },
    SendFile {
        dest_hash: [u8; 16],
        path: PathBuf,
    },
    ReceiveFile {
        out_dir: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("reticulumd: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let config_path = take_config_path(&mut args)?;
    let mode = parse_mode(&args)?;
    let config = Config::load(config_path.as_deref())?;
    let identity = save_or_create_identity(&config.identity_path)?;
    let mut node = Node::with_clock(identity, SystemClock);
    if config.transport_enabled {
        node.enable_transport(true);
    }
    let aspect_refs: Vec<&str> = config.aspects.iter().map(String::as_str).collect();
    let local_dest = node.register_single_destination(&config.app_name, &aspect_refs);
    if config.prove {
        node.set_prove(&local_dest, true);
    }
    let local_plain = node.register_plain_destination(&config.app_name, &aspect_refs);
    let local_group = config
        .group_key()?
        .map(|key| node.register_group_destination(&config.app_name, &aspect_refs, key));

    let mut interfaces: Vec<Box<dyn AsyncInterface>> = Vec::new();
    let mut servers = Vec::new();
    for interface in config.interface_configs() {
        let ifac = build_ifac(interface.ifac())?;
        match interface {
            InterfaceConfig::TcpClient { address, .. } => {
                let id = next_interface_id(interfaces.len())?;
                let interface = TcpClientInterface::connect(&address).await?.with_id(id);
                interfaces.push(wrap_ifac(Box::new(interface), ifac));
            }
            InterfaceConfig::TcpServer { listen, .. } => {
                servers.push((TcpServerInterface::bind(&listen).await?, ifac));
            }
            InterfaceConfig::Udp {
                listen, forward, ..
            } => {
                let id = next_interface_id(interfaces.len())?;
                let interface = UdpInterface::bind(&listen, &forward).await?.with_id(id);
                interfaces.push(wrap_ifac(Box::new(interface), ifac));
            }
            InterfaceConfig::Auto {
                interface,
                group_id,
                discovery_port,
                data_port,
                ..
            } => {
                let id = next_interface_id(interfaces.len())?;
                let interface = reticulum_tokio::auto::AutoInterface::new_with_ports(
                    &group_id,
                    discovery_port,
                    data_port,
                    &interface,
                )
                .await?
                .with_id(id);
                interfaces.push(wrap_ifac(Box::new(interface), ifac));
            }
            InterfaceConfig::Serial { port, baud, .. } => {
                #[cfg(feature = "serial")]
                {
                    let id = next_interface_id(interfaces.len())?;
                    let interface =
                        reticulum_tokio::serial::SerialInterface::open(&port, baud)?.with_id(id);
                    interfaces.push(wrap_ifac(Box::new(interface), ifac));
                }
                #[cfg(not(feature = "serial"))]
                {
                    let _ = (port, baud, ifac);
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "serial interface requires reticulum-cli feature \"serial\"",
                    )
                    .into());
                }
            }
        }
    }
    let (events_tx, mut events_rx) = mpsc::channel(64);
    let (driver, handle) = if servers.is_empty() {
        Driver::new_interfaces(node, interfaces, events_tx)
    } else {
        let (driver, handle, registrar) = Driver::new_dynamic(node, interfaces, events_tx);
        for (server, ifac) in servers {
            let registrar = registrar.clone();
            tokio::spawn(async move {
                if let Err(error) = server.serve_with_ifac(registrar, ifac).await {
                    eprintln!("reticulumd: TCP server stopped: {error}");
                }
            });
        }
        drop(registrar);
        (driver, handle)
    };
    let driver_task = tokio::spawn(driver.run());
    handle
        .announce_all(config.app_data.as_bytes())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "driver stopped before announce"))?;
    println!("local destination {}", hex::encode(local_dest));
    println!("local plain destination {}", hex::encode(local_plain));
    if let Some(group) = local_group {
        println!("local group destination {}", hex::encode(group));
    }

    match mode {
        Mode::Run => {
            let mut announce_interval =
                tokio::time::interval(Duration::from_secs(config.announce_interval_secs.max(1)));
            announce_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // Consume the immediate first tick; the initial announce was
            // already queued above.
            announce_interval.tick().await;
            loop {
                tokio::select! {
                    event = events_rx.recv() => {
                        let Some(event) = event else {
                            break;
                        };
                        print_event(&event);
                        if config.link_echo
                            && let Event::LinkData { link_id, plaintext } = event
                        {
                            handle.link_send(link_id, &plaintext).await.map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::BrokenPipe,
                                    "driver stopped before link echo",
                                )
                            })?;
                        }
                    }
                    _ = announce_interval.tick() => {
                        handle
                            .announce_all(config.app_data.as_bytes())
                            .await
                            .map_err(|_| io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "driver stopped before periodic announce",
                            ))?;
                    }
                }
            }
        }
        Mode::Announce => {
            tokio::time::sleep(Duration::from_secs(1)).await;
            shutdown(&handle).await?;
        }
        Mode::Send {
            dest_hash,
            plaintext,
            prove,
        } => {
            let mut pending = None;
            while let Some(event) = events_rx.recv().await {
                print_event(&event);
                match event {
                    Event::Announce {
                        dest_hash: announced,
                        ..
                    } if announced == dest_hash && pending.is_none() => {
                        if prove {
                            let packet_hash = handle
                                .send_with_receipt(dest_hash, &plaintext)
                                .await
                                .map_err(|error| {
                                    io::Error::other(format!(
                                        "could not send with receipt: {error:?}"
                                    ))
                                })?;
                            println!("sent proved message {}", hex::encode(packet_hash));
                            pending = Some(packet_hash);
                        } else {
                            handle.send(dest_hash, &plaintext).await.map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::BrokenPipe,
                                    "driver stopped before send",
                                )
                            })?;
                            println!("sent message to {}", hex::encode(dest_hash));
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            shutdown(&handle).await?;
                            break;
                        }
                    }
                    Event::Delivered { packet_hash } if Some(packet_hash) == pending => {
                        println!("delivery confirmed {}", hex::encode(packet_hash));
                        shutdown(&handle).await?;
                        break;
                    }
                    _ => {}
                }
            }
        }
        Mode::SendGroup {
            dest_hash,
            plaintext,
        } => {
            if local_group != Some(dest_hash) {
                return Err("destination does not match group_key_hex and configured name".into());
            }
            handle
                .send_group(dest_hash, &plaintext)
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "driver stopped before GROUP send",
                    )
                })?;
            println!("sent group message to {}", hex::encode(dest_hash));
            tokio::time::sleep(Duration::from_secs(1)).await;
            shutdown(&handle).await?;
        }
        Mode::SendPlain {
            dest_hash,
            plaintext,
        } => {
            handle
                .send_plain(dest_hash, &plaintext)
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "driver stopped before PLAIN send",
                    )
                })?;
            println!("sent plain message to {}", hex::encode(dest_hash));
            tokio::time::sleep(Duration::from_secs(1)).await;
            shutdown(&handle).await?;
        }
        Mode::Link {
            dest_hash,
            plaintext,
        } => {
            let mut link_id = None;
            while let Some(event) = events_rx.recv().await {
                print_event(&event);
                match event {
                    Event::Announce {
                        dest_hash: announced,
                        ..
                    } if announced == dest_hash && link_id.is_none() => {
                        let established =
                            handle.establish_link(dest_hash).await.map_err(|error| {
                                io::Error::other(format!("could not establish link: {error:?}"))
                            })?;
                        println!("link requested {}", hex::encode(established));
                        link_id = Some(established);
                    }
                    Event::LinkEstablished {
                        link_id: established,
                    } if Some(established) == link_id => {
                        if let Some(plaintext) = plaintext.as_deref() {
                            handle
                                .link_send(established, plaintext)
                                .await
                                .map_err(|_| {
                                    io::Error::new(
                                        io::ErrorKind::BrokenPipe,
                                        "driver stopped before link send",
                                    )
                                })?;
                            println!("sent link data {}", hex::encode(established));
                        } else {
                            shutdown(&handle).await?;
                            break;
                        }
                    }
                    Event::LinkData {
                        link_id: received, ..
                    } if Some(received) == link_id && plaintext.is_some() => {
                        handle.close_link(received).await.map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "driver stopped before link close",
                            )
                        })?;
                        shutdown(&handle).await?;
                        break;
                    }
                    _ => {}
                }
            }
        }
        Mode::SendFile { dest_hash, path } => {
            let data = std::fs::read(&path)?;
            let mut link_id = None;
            let mut resource_hash = None;
            while let Some(event) = events_rx.recv().await {
                print_event(&event);
                match event {
                    Event::Announce {
                        dest_hash: announced,
                        ..
                    } if announced == dest_hash && link_id.is_none() => {
                        let established =
                            handle.establish_link(dest_hash).await.map_err(|error| {
                                io::Error::other(format!("could not establish link: {error:?}"))
                            })?;
                        println!("link requested {}", hex::encode(established));
                        link_id = Some(established);
                    }
                    Event::LinkEstablished {
                        link_id: established,
                    } if Some(established) == link_id && resource_hash.is_none() => {
                        let hash =
                            handle
                                .send_resource(established, &data)
                                .await
                                .map_err(|error| {
                                    io::Error::other(format!("could not send resource: {error:?}"))
                                })?;
                        println!("resource sent {}", hex::encode(hash));
                        resource_hash = Some(hash);
                    }
                    Event::ResourceComplete { hash, .. } if Some(hash) == resource_hash => {
                        println!("file transfer complete {}", path.display());
                        shutdown(&handle).await?;
                        break;
                    }
                    _ => {}
                }
            }
        }
        Mode::ReceiveFile { out_dir } => {
            std::fs::create_dir_all(&out_dir)?;
            let mut announce_interval =
                tokio::time::interval(Duration::from_secs(config.announce_interval_secs.max(1)));
            announce_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            announce_interval.tick().await;
            loop {
                tokio::select! {
                    event = events_rx.recv() => {
                        let Some(event) = event else {
                            break;
                        };
                        print_event(&event);
                        if let Event::ResourceComplete { hash, data, .. } = event
                            && !data.is_empty()
                        {
                            let path = out_dir.join(format!("{}.resource", hex::encode(hash)));
                            std::fs::write(&path, data)?;
                            println!("resource written {}", path.display());
                        }
                    }
                    _ = announce_interval.tick() => {
                        handle
                            .announce_all(config.app_data.as_bytes())
                            .await
                            .map_err(|_| io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "driver stopped before periodic announce",
                            ))?;
                    }
                }
            }
        }
    }

    driver_task.await??;
    Ok(())
}

fn next_interface_id(index: usize) -> io::Result<u16> {
    u16::try_from(index)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many interfaces"))
}

fn build_ifac(settings: Option<&IfacSettings>) -> io::Result<Option<IfacConfig>> {
    settings
        .map(|settings| {
            let config = IfacConfig::new(&settings.network_name, &settings.passphrase);
            match settings.size {
                Some(size) => config.with_size(size),
                None => Ok(config),
            }
        })
        .transpose()
}

fn wrap_ifac(
    interface: Box<dyn AsyncInterface>,
    ifac: Option<IfacConfig>,
) -> Box<dyn AsyncInterface> {
    match ifac {
        Some(ifac) => with_ifac(interface, ifac),
        None => interface,
    }
}

fn take_config_path(args: &mut Vec<String>) -> Result<Option<PathBuf>, Box<dyn Error>> {
    let Some(index) = args.iter().position(|arg| arg == "--config") else {
        return Ok(None);
    };
    if index + 1 >= args.len() {
        return Err("--config requires a path".into());
    }
    let path = PathBuf::from(args.remove(index + 1));
    args.remove(index);
    Ok(Some(path))
}

fn parse_mode(args: &[String]) -> Result<Mode, Box<dyn Error>> {
    match args.first().map(String::as_str) {
        Some("run") if args.len() == 1 => Ok(Mode::Run),
        Some("announce") if args.len() == 1 => Ok(Mode::Announce),
        Some("send") if args.len() == 3 || (args.len() == 4 && args[3] == "--prove") => {
            let dest_hash = parse_hash(&args[1], "destination")?;
            Ok(Mode::Send {
                dest_hash,
                plaintext: args[2].as_bytes().to_vec(),
                prove: args.get(3).is_some_and(|argument| argument == "--prove"),
            })
        }
        Some("send-group") if args.len() == 3 => Ok(Mode::SendGroup {
            dest_hash: parse_hash(&args[1], "destination")?,
            plaintext: args[2].as_bytes().to_vec(),
        }),
        Some("send-plain") if args.len() == 3 => Ok(Mode::SendPlain {
            dest_hash: parse_hash(&args[1], "destination")?,
            plaintext: args[2].as_bytes().to_vec(),
        }),
        Some("link") if args.len() == 2 => Ok(Mode::Link {
            dest_hash: parse_hash(&args[1], "destination")?,
            plaintext: None,
        }),
        Some("link-send") if args.len() == 3 => Ok(Mode::Link {
            // A one-shot CLI has no persisted active-link registry, so this
            // command establishes toward the destination before sending.
            dest_hash: parse_hash(&args[1], "destination")?,
            plaintext: Some(args[2].as_bytes().to_vec()),
        }),
        Some("send-file") if args.len() == 3 => Ok(Mode::SendFile {
            dest_hash: parse_hash(&args[1], "destination")?,
            path: PathBuf::from(&args[2]),
        }),
        Some("receive-file") if args.len() == 2 => Ok(Mode::ReceiveFile {
            out_dir: PathBuf::from(&args[1]),
        }),
        _ => Err(
            "usage: reticulumd <run|announce|send DEST_HASH TEXT [--prove]|send-group DEST_HASH TEXT|send-plain DEST_HASH TEXT|link DEST_HASH|link-send DEST_HASH TEXT|send-file DEST_HASH PATH|receive-file OUT_DIR> [--config PATH]"
                .into(),
        ),
    }
}

fn parse_hash(value: &str, label: &str) -> Result<[u8; 16], Box<dyn Error>> {
    hex::decode(value)?
        .try_into()
        .map_err(|_| format!("{label} hash must be exactly 16 bytes").into())
}

async fn shutdown(handle: &DriverHandle) -> io::Result<()> {
    handle
        .shutdown()
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "driver already stopped"))
}

fn print_event(event: &Event) {
    match event {
        Event::Announce { dest_hash, hops } => {
            println!("announce {} hops={hops}", hex::encode(dest_hash));
        }
        Event::Message {
            dest_hash,
            plaintext,
        } => {
            println!(
                "message {} {}",
                hex::encode(dest_hash),
                String::from_utf8_lossy(plaintext)
            );
        }
        Event::Delivered { packet_hash } => {
            println!("delivered {}", hex::encode(packet_hash));
        }
        Event::LinkEstablished { link_id } => {
            println!("link established {}", hex::encode(link_id));
        }
        Event::LinkData { link_id, plaintext } => {
            println!(
                "link data {} {}",
                hex::encode(link_id),
                String::from_utf8_lossy(plaintext)
            );
        }
        Event::LinkClosed { link_id } => {
            println!("link closed {}", hex::encode(link_id));
        }
        Event::ResourceStarted { hash, size, .. } => {
            println!("resource started {} size={size}", hex::encode(hash));
        }
        Event::ResourceProgress { hash, fraction, .. } => {
            println!(
                "resource progress {} {:.1}%",
                hex::encode(hash),
                fraction * 100.0
            );
        }
        Event::ResourceComplete { hash, data, .. } => {
            println!(
                "resource complete {} bytes={}",
                hex::encode(hash),
                data.len()
            );
        }
        Event::ResourceFailed { hash, .. } => {
            eprintln!("resource failed {}", hex::encode(hash));
        }
        Event::Error(error) => eprintln!("node error: {error:?}"),
    }
}
