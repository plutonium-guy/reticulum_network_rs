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
            let bytes = hex::decode(&args[1])?;
            let dest_hash: [u8; 16] = bytes
                .try_into()
                .map_err(|_| "destination hash must be exactly 16 bytes")?;
            Ok(Mode::Send {
                dest_hash,
                plaintext: args[2].as_bytes().to_vec(),
            })
        }
        _ => Err("usage: reticulumd <run|announce|send DEST_HASH TEXT> [--config PATH]".into()),
    }
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
        Event::Error(error) => eprintln!("node error: {error:?}"),
    }
}
