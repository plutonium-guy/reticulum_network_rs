use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
};

use crate::app::{AppState, LogKind, short_hash};

const ACCENT: Color = Color::Cyan;

pub fn draw(frame: &mut Frame<'_>, state: &AppState) {
    let regions = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(3),
        ])
        .split(frame.area());
    let content = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(regions[1]);

    frame.render_widget(status(state), regions[0]);
    frame.render_widget(roster(state), content[0]);
    frame.render_widget(log(state), content[1]);
    frame.render_widget(input(state), regions[2]);

    if state.show_help {
        render_help(frame);
    }
}

fn status(state: &AppState) -> Paragraph<'static> {
    let interfaces = if state.interfaces.is_empty() {
        "discovering".to_owned()
    } else {
        state
            .interfaces
            .iter()
            .map(|interface| {
                format!(
                    "#{} {} rx:{} tx:{}",
                    interface.id,
                    if interface.online {
                        "online"
                    } else {
                        "offline"
                    },
                    interface.rx_packets,
                    interface.tx_packets
                )
            })
            .collect::<Vec<_>>()
            .join(" · ")
    };
    Paragraph::new(Line::from(vec![
        Span::styled(
            "DECENTRALIZED · AutoInterface",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(
            "  identity {}  peers {}  {interfaces}",
            short_hash(&state.identity),
            state.roster.len()
        )),
    ]))
    .block(Block::default().borders(Borders::ALL).title(" Reticulum "))
}

fn roster(state: &AppState) -> List<'static> {
    let rows = state
        .roster
        .iter()
        .enumerate()
        .map(|(index, peer)| {
            let text = format!(
                "{}  hops:{} seen:{} last:{}s",
                hex::encode(peer.dest),
                peer.hops,
                peer.seen,
                peer.last_secs
            );
            let style = if index == state.selected {
                Style::default()
                    .fg(Color::Black)
                    .bg(ACCENT)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            ListItem::new(text).style(style)
        })
        .collect::<Vec<_>>();
    List::new(rows).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Mesh roster "),
    )
}

fn log(state: &AppState) -> Paragraph<'static> {
    let lines = state
        .log
        .iter()
        .rev()
        .take(500)
        .rev()
        .map(|entry| {
            Line::from(vec![
                Span::styled(
                    format!("[{:>6}] {:<9}", entry.at_secs, kind_label(entry.kind)),
                    Style::default().fg(kind_color(entry.kind)),
                ),
                Span::raw(entry.text.clone()),
            ])
        })
        .collect::<Vec<_>>();
    Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" Activity "))
        .wrap(Wrap { trim: false })
}

fn input(state: &AppState) -> Paragraph<'static> {
    let target = state
        .selected_peer()
        .map(|destination| short_hash(&destination))
        .unwrap_or_else(|| "no-peer".to_owned());
    Paragraph::new(format!("to {target}> {}", state.input))
        .style(Style::default().fg(Color::White))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(ACCENT))
                .title(" Message · Enter send · ? help · q quit "),
        )
}

fn kind_label(kind: LogKind) -> &'static str {
    match kind {
        LogKind::Sys => "system",
        LogKind::Tx => "sent",
        LogKind::Rx => "received",
        LogKind::Announce => "announce",
        LogKind::Delivered => "delivered",
        LogKind::Err => "error",
    }
}

fn kind_color(kind: LogKind) -> Color {
    match kind {
        LogKind::Sys => Color::Blue,
        LogKind::Tx => Color::Cyan,
        LogKind::Rx => Color::Green,
        LogKind::Announce => Color::Yellow,
        LogKind::Delivered => Color::Magenta,
        LogKind::Err => Color::Red,
    }
}

fn render_help(frame: &mut Frame<'_>) {
    let area = centered_rect(62, 60, frame.area());
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from("↑/↓ or Tab  select peer"),
            Line::from("Enter       send message"),
            Line::from("a           announce presence"),
            Line::from("?           close this help"),
            Line::from("q / Ctrl-C  quit"),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(ACCENT))
                .title(" Help "),
        ),
        area,
    );
}

fn centered_rect(width_percent: u16, height_percent: u16, area: Rect) -> Rect {
    let vertical = Layout::vertical([
        Constraint::Percentage((100 - height_percent) / 2),
        Constraint::Percentage(height_percent),
        Constraint::Percentage((100 - height_percent) / 2),
    ])
    .split(area);
    Layout::horizontal([
        Constraint::Percentage((100 - width_percent) / 2),
        Constraint::Percentage(width_percent),
        Constraint::Percentage((100 - width_percent) / 2),
    ])
    .split(vertical[1])[1]
}

#[cfg(test)]
mod tests {
    use ratatui::{Terminal, backend::TestBackend};

    use crate::app::{LogKind, Peer};

    use super::*;

    #[test]
    fn renders_peer_and_decentralized_status() {
        let mut state = AppState::new([7; 16]);
        state.roster.push(Peer {
            dest: [0xab; 16],
            hops: 1,
            seen: 3,
            last_secs: 42,
        });
        state.log(LogKind::Rx, "hello mesh", 43);
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|frame| draw(frame, &state)).unwrap();

        let rendered = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("abababababab"));
        assert!(rendered.contains("DECENTRALIZED · AutoInterface"));
    }
}
