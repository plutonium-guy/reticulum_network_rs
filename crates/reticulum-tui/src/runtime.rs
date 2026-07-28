use std::{
    error::Error,
    io::{self, Stdout, stdout},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crossterm::{
    event::{
        DisableMouseCapture, EnableMouseCapture, Event as TerminalEvent, EventStream, KeyCode,
        KeyEvent, KeyEventKind, KeyModifiers,
    },
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use futures_util::StreamExt;
use ratatui::{Terminal, backend::CrosstermBackend};
use reticulum_cli::{build_interfaces, config::save_or_create_identity};
use reticulum_node::{Event, node::Node};
use reticulum_tokio::{
    SystemClock,
    driver::{Driver, DriverHandle},
};
use tokio::sync::mpsc;

use crate::{
    app::{AppState, LogKind, short_hash},
    config::{Options, load_config},
    ui,
};

const EVENT_CAPACITY: usize = 128;
const UI_TICK: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    None,
    Input(char),
    Backspace,
    SelectNext,
    SelectPrev,
    Announce,
    ToggleHelp,
    Send { dest: [u8; 16], text: String },
    Quit,
}

pub fn key_to_action(key: KeyEvent, state: &AppState) -> Action {
    if key.kind != KeyEventKind::Press {
        return Action::None;
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return Action::Quit;
    }
    match key.code {
        KeyCode::Char('q') => Action::Quit,
        KeyCode::Char('a') => Action::Announce,
        KeyCode::Char('?') => Action::ToggleHelp,
        KeyCode::Char(character) => Action::Input(character),
        KeyCode::Backspace => Action::Backspace,
        KeyCode::Up | KeyCode::BackTab => Action::SelectPrev,
        KeyCode::Down | KeyCode::Tab => Action::SelectNext,
        KeyCode::Enter => match (state.selected_peer(), state.input.is_empty()) {
            (Some(dest), false) => Action::Send {
                dest,
                text: state.input.clone(),
            },
            _ => Action::None,
        },
        _ => Action::None,
    }
}

/// Executes a TUI intent through the same driver handle used by the live loop.
/// Returns `true` when the caller should exit.
pub async fn execute_action(
    handle: &DriverHandle,
    state: &mut AppState,
    action: Action,
    app_data: &[u8],
    now: u64,
) -> bool {
    match action {
        Action::None => {}
        Action::Input(character) => state.push_input(character),
        Action::Backspace => state.backspace(),
        Action::SelectNext => state.select_next(),
        Action::SelectPrev => state.select_prev(),
        Action::ToggleHelp => state.show_help = !state.show_help,
        Action::Announce => {
            if handle.announce_all(app_data).await.is_ok() {
                state.log(LogKind::Sys, "presence announced", now);
            } else {
                state.on_error("driver stopped before announce", now);
            }
        }
        Action::Send { dest, text } => {
            if handle.send(dest, text.as_bytes()).await.is_ok() {
                state.take_input();
                state.log(LogKind::Tx, format!("{}: {text}", short_hash(&dest)), now);
            } else {
                state.on_error("driver stopped before send", now);
            }
        }
        Action::Quit => return true,
    }
    false
}

pub fn apply_event(state: &mut AppState, event: Event, now: u64) {
    match event {
        Event::Announce { dest_hash, hops } => state.on_announce(dest_hash, hops, now),
        Event::Message {
            dest_hash,
            plaintext,
        } => state.on_message(dest_hash, String::from_utf8_lossy(&plaintext), now),
        Event::LxmfMessage {
            source,
            title,
            content,
            ..
        } => state.on_message(
            source,
            format!(
                "{} — {}",
                String::from_utf8_lossy(&title),
                String::from_utf8_lossy(&content)
            ),
            now,
        ),
        Event::Delivered { packet_hash } => state.on_delivered(packet_hash, now),
        Event::LinkEstablished { link_id } => state.log(
            LogKind::Sys,
            format!("link {} established", short_hash(&link_id)),
            now,
        ),
        Event::LinkData { link_id, plaintext } => state.on_message(
            link_id,
            format!("link: {}", String::from_utf8_lossy(&plaintext)),
            now,
        ),
        Event::LinkClosed { link_id } => state.log(
            LogKind::Sys,
            format!("link {} closed", short_hash(&link_id)),
            now,
        ),
        Event::ResourceStarted { hash, size, .. } => state.log(
            LogKind::Sys,
            format!("resource {} started ({size} bytes)", short_hash(&hash)),
            now,
        ),
        Event::ResourceProgress { hash, fraction, .. } => state.log(
            LogKind::Sys,
            format!(
                "resource {} {:.0}% complete",
                short_hash(&hash),
                fraction * 100.0
            ),
            now,
        ),
        Event::ResourceComplete { hash, data, .. } => state.log(
            LogKind::Rx,
            format!(
                "resource {} received ({} bytes)",
                short_hash(&hash),
                data.len()
            ),
            now,
        ),
        Event::ResourceFailed { hash, .. } => {
            state.on_error(format!("resource {} failed", short_hash(&hash)), now)
        }
        Event::Error(error) => state.on_error(format!("{error:?}"), now),
    }
}

pub async fn run(options: Options) -> Result<(), Box<dyn Error>> {
    let mut config = load_config(options.config_path.as_deref())?;
    if let Some(identity_path) = options.identity_path {
        config.identity_path = identity_path;
    }
    let identity = save_or_create_identity(&config.identity_path)?;
    let identity_hash = identity.hash();
    let mut node = Node::with_clock(identity, SystemClock);
    if config.transport_enabled {
        node.enable_transport(true);
    }
    let aspects = config
        .aspects
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    node.register_single_destination(&config.app_name, &aspects);
    node.register_plain_destination(&config.app_name, &aspects);
    let interfaces = build_interfaces(&config).await?;
    if interfaces.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TUI configuration produced no peer-to-peer interfaces",
        )
        .into());
    }

    let (events_tx, mut events_rx) = mpsc::channel(EVENT_CAPACITY);
    let (driver, handle) = Driver::new_interfaces(node, interfaces, events_tx);
    let driver_task = tokio::spawn(driver.run());
    let app_data = config.app_data.into_bytes();
    handle
        .announce_all(&app_data)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "driver stopped at startup"))?;

    let ui_result = run_terminal(
        &handle,
        &mut events_rx,
        identity_hash,
        &app_data,
        config.announce_interval_secs,
    )
    .await;
    let _ = handle.shutdown().await;
    let driver_result = driver_task.await.map_err(io::Error::other)?;
    ui_result?;
    driver_result?;
    Ok(())
}

async fn run_terminal(
    handle: &DriverHandle,
    events_rx: &mut mpsc::Receiver<Event>,
    identity: [u8; 16],
    app_data: &[u8],
    announce_interval_secs: u64,
) -> io::Result<()> {
    let guard = TerminalGuard::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;
    let result = event_loop(
        &mut terminal,
        handle,
        events_rx,
        identity,
        app_data,
        announce_interval_secs,
    )
    .await;
    drop(terminal);
    drop(guard);
    result
}

async fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    handle: &DriverHandle,
    events_rx: &mut mpsc::Receiver<Event>,
    identity: [u8; 16],
    app_data: &[u8],
    announce_interval_secs: u64,
) -> io::Result<()> {
    let mut state = AppState::new(identity);
    state.log(LogKind::Sys, "native mesh node started", now_secs());
    let mut input = EventStream::new();
    let mut tick = tokio::time::interval(UI_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut announce = tokio::time::interval(Duration::from_secs(announce_interval_secs.max(1)));
    announce.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    announce.tick().await;
    terminal.draw(|frame| ui::draw(frame, &state))?;

    loop {
        tokio::select! {
            terminal_event = input.next() => {
                match terminal_event {
                    Some(Ok(TerminalEvent::Key(key))) => {
                        let action = key_to_action(key, &state);
                        if execute_action(handle, &mut state, action, app_data, now_secs()).await {
                            break;
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(error)) => return Err(error),
                    None => break,
                }
            }
            event = events_rx.recv() => {
                match event {
                    Some(event) => apply_event(&mut state, event, now_secs()),
                    None => {
                        state.on_error("driver event channel closed", now_secs());
                        break;
                    }
                }
            }
            _ = tick.tick() => {
                match handle.snapshot().await {
                    Ok(snapshot) => state.apply_snapshot(snapshot, now_secs()),
                    Err(_) => {
                        state.on_error("driver stopped", now_secs());
                        break;
                    }
                }
            }
            _ = announce.tick() => {
                if handle.announce_all(app_data).await.is_err() {
                    state.on_error("driver stopped before periodic announce", now_secs());
                    break;
                }
                state.log(LogKind::Sys, "periodic presence announced", now_secs());
            }
        }
        terminal.draw(|frame| ui::draw(frame, &state))?;
    }
    Ok(())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        if let Err(error) = execute!(stdout(), EnterAlternateScreen, EnableMouseCapture) {
            let _ = disable_raw_mode();
            return Err(error);
        }
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(stdout(), DisableMouseCapture, LeaveAlternateScreen);
        let _ = disable_raw_mode();
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use async_trait::async_trait;
    use reticulum_core::identity::Identity;
    use reticulum_tokio::interface::AsyncInterface;
    use tokio::time::timeout;

    use super::*;

    struct MemoryInterface {
        id: u16,
        incoming: mpsc::Receiver<Vec<u8>>,
        outgoing: mpsc::Sender<Vec<u8>>,
    }

    #[async_trait]
    impl AsyncInterface for MemoryInterface {
        fn id(&self) -> u16 {
            self.id
        }

        async fn recv_packet(&mut self) -> io::Result<Option<Vec<u8>>> {
            Ok(self.incoming.recv().await)
        }

        async fn send_packet(&mut self, raw: &[u8]) -> io::Result<()> {
            self.outgoing
                .send(raw.to_vec())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "peer stopped"))
        }
    }

    fn memory_pair() -> (Box<dyn AsyncInterface>, Box<dyn AsyncInterface>) {
        let (a_tx, a_rx) = mpsc::channel(64);
        let (b_tx, b_rx) = mpsc::channel(64);
        (
            Box::new(MemoryInterface {
                id: 0,
                incoming: a_rx,
                outgoing: b_tx,
            }),
            Box::new(MemoryInterface {
                id: 0,
                incoming: b_rx,
                outgoing: a_tx,
            }),
        )
    }

    fn test_node(seed: u8) -> (Node<SystemClock>, [u8; 16]) {
        let identity = Identity::from_private_bytes(&[seed; 32], &[seed + 1; 32]);
        let mut node = Node::with_clock(identity, SystemClock);
        let destination = node.register_single_destination("reticulum_tui", &["chat"]);
        node.register_plain_destination("reticulum_tui", &["chat"]);
        (node, destination)
    }

    #[test]
    fn maps_keys_to_typed_actions() {
        let mut state = AppState::new([0; 16]);
        state.on_announce([4; 16], 1, 10);
        state.input = "hello".to_owned();

        assert_eq!(
            key_to_action(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), &state),
            Action::Send {
                dest: [4; 16],
                text: "hello".to_owned()
            }
        );
        assert_eq!(
            key_to_action(
                KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
                &state
            ),
            Action::Quit
        );
        assert_eq!(
            key_to_action(
                KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE),
                &state
            ),
            Action::Input('x')
        );
    }

    #[tokio::test]
    async fn two_nodes_use_the_runtime_action_and_event_path() {
        let (interface_a, interface_b) = memory_pair();
        let (node_a, destination_a) = test_node(11);
        let (node_b, identity_b) = test_node(21);
        let (events_a_tx, mut events_a_rx) = mpsc::channel(64);
        let (events_b_tx, mut events_b_rx) = mpsc::channel(64);
        let (driver_a, handle_a) = Driver::new_interfaces(node_a, vec![interface_a], events_a_tx);
        let (driver_b, handle_b) = Driver::new_interfaces(node_b, vec![interface_b], events_b_tx);
        let task_a = tokio::spawn(driver_a.run());
        let task_b = tokio::spawn(driver_b.run());
        let mut state_a = AppState::new(destination_a);
        let mut state_b = AppState::new(identity_b);

        handle_a.announce_all(b"node-a").await.unwrap();
        let announce = timeout(Duration::from_secs(2), events_b_rx.recv())
            .await
            .unwrap()
            .unwrap();
        apply_event(&mut state_b, announce, 100);
        assert_eq!(state_b.selected_peer(), Some(destination_a));

        let quit = execute_action(
            &handle_b,
            &mut state_b,
            Action::Send {
                dest: destination_a,
                text: "decentralized hello".to_owned(),
            },
            b"node-b",
            101,
        )
        .await;
        assert!(!quit);
        let message = timeout(Duration::from_secs(2), events_a_rx.recv())
            .await
            .unwrap()
            .unwrap();
        apply_event(&mut state_a, message, 102);
        assert!(
            state_a.log.iter().any(
                |entry| entry.kind == LogKind::Rx && entry.text.contains("decentralized hello")
            )
        );

        handle_a.shutdown().await.unwrap();
        handle_b.shutdown().await.unwrap();
        task_a.await.unwrap().unwrap();
        task_b.await.unwrap().unwrap();
    }
}
