mod config;

use std::{error::Error, io, path::PathBuf, time::Duration};

use config::{Config, save_or_create_identity};
use reticulum_node::{Event, node::Node};
use reticulum_tokio::{
    SystemClock,
    driver::{Driver, DriverHandle},
    tcp::TcpClientInterface,
};
use tokio::sync::mpsc;

enum Mode {
    Run,
    Announce,
    Send {
        dest_hash: [u8; 16],
        plaintext: Vec<u8>,
    },
    Link {
        dest_hash: [u8; 16],
        plaintext: Option<Vec<u8>>,
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

    let mut interfaces = Vec::new();
    for (index, address) in config.peer_addresses().into_iter().enumerate() {
        let interface_id = u16::try_from(index).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "too many TCP peer interfaces")
        })?;
        interfaces.push((interface_id, TcpClientInterface::connect(address).await?));
    }
    let (events_tx, mut events_rx) = mpsc::channel(64);
    let (driver, handle) = Driver::new_multi(node, interfaces, events_tx);
    let driver_task = tokio::spawn(driver.run());
    handle
        .announce_all(config.app_data.as_bytes())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "driver stopped before announce"))?;
    println!("local destination {}", hex::encode(local_dest));

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
        } => {
            while let Some(event) = events_rx.recv().await {
                print_event(&event);
                if matches!(
                    event,
                    Event::Announce {
                        dest_hash: announced,
                        ..
                    } if announced == dest_hash
                ) {
                    handle.send(dest_hash, &plaintext).await.map_err(|_| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "driver stopped before send")
                    })?;
                    println!("sent message to {}", hex::encode(dest_hash));
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    shutdown(&handle).await?;
                    break;
                }
            }
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
    }

    driver_task.await??;
    Ok(())
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
        Some("send") if args.len() == 3 => {
            let dest_hash = parse_hash(&args[1], "destination")?;
            Ok(Mode::Send {
                dest_hash,
                plaintext: args[2].as_bytes().to_vec(),
            })
        }
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
        _ => Err(
            "usage: reticulumd <run|announce|send DEST_HASH TEXT|link DEST_HASH|link-send DEST_HASH TEXT> [--config PATH]"
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
        Event::Error(error) => eprintln!("node error: {error:?}"),
    }
}
