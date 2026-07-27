use std::{cell::RefCell, rc::Rc};

use js_sys::{ArrayBuffer, Function, Uint8Array};
use reticulum_core::identity::Identity;
use reticulum_interface::hdlc::frame;
use reticulum_node::{Event, node::Node};
use wasm_bindgen::{JsCast, closure::Closure, prelude::*};
use web_sys::{BinaryType, Event as WebEvent, MessageEvent, WebSocket};

use crate::{HdlcStreamDecoder, WasmClock, WasmEntropy};

const INTERFACE_ID: u16 = 0;

struct BrowserState {
    node: Node<WasmClock>,
    entropy: WasmEntropy,
    socket: Option<WebSocket>,
    pending: Vec<Vec<u8>>,
    decoder: HdlcStreamDecoder,
    on_message: Option<Function>,
    on_delivered: Option<Function>,
}

impl BrowserState {
    fn drain_outbound(&mut self) -> Result<(), JsValue> {
        while let Some((_, packet)) = self.node.poll_outbound() {
            let framed = frame(&packet);
            match self.socket.as_ref() {
                Some(socket) if socket.ready_state() == WebSocket::OPEN => {
                    socket.send_with_u8_array(&framed)?;
                }
                Some(socket) if socket.ready_state() == WebSocket::CONNECTING => {
                    self.pending.push(framed);
                }
                Some(_) => return Err(JsValue::from_str("WebSocket is not open")),
                None => return Err(JsValue::from_str("WebSocket is not connected")),
            }
        }
        Ok(())
    }

    fn flush_pending(&mut self) -> Result<(), JsValue> {
        let Some(socket) = self.socket.as_ref() else {
            return Err(JsValue::from_str("WebSocket is not connected"));
        };
        for framed in self.pending.drain(..) {
            socket.send_with_u8_array(&framed)?;
        }
        Ok(())
    }

    fn callbacks(&self) -> (Option<Function>, Option<Function>) {
        (self.on_message.clone(), self.on_delivered.clone())
    }
}

/// Browser-facing Reticulum node using HDLC packets over a WebSocket bridge.
#[wasm_bindgen]
pub struct ReticulumNode {
    state: Rc<RefCell<BrowserState>>,
    on_open: Option<Closure<dyn FnMut(WebEvent)>>,
    on_message: Option<Closure<dyn FnMut(MessageEvent)>>,
    tick: Option<Closure<dyn FnMut()>>,
    interval_id: Option<i32>,
}

#[wasm_bindgen]
impl ReticulumNode {
    #[wasm_bindgen(constructor)]
    pub fn new(identity_hex: &str) -> Result<ReticulumNode, JsValue> {
        let identity = identity_from_hex(identity_hex)?;
        let mut node = Node::with_clock(identity, WasmClock);
        node.register_interface(INTERFACE_ID);
        Ok(Self {
            state: Rc::new(RefCell::new(BrowserState {
                node,
                entropy: WasmEntropy,
                socket: None,
                pending: Vec::new(),
                decoder: HdlcStreamDecoder::default(),
                on_message: None,
                on_delivered: None,
            })),
            on_open: None,
            on_message: None,
            tick: None,
            interval_id: None,
        })
    }

    pub fn register_single_destination(
        &self,
        app_name: &str,
        aspects: Vec<String>,
    ) -> Result<String, JsValue> {
        if aspects.is_empty() {
            return Err(JsValue::from_str("at least one aspect is required"));
        }
        let aspect_refs: Vec<_> = aspects.iter().map(String::as_str).collect();
        let hash = self
            .state
            .borrow_mut()
            .node
            .register_single_destination(app_name, &aspect_refs);
        Ok(hex::encode(hash))
    }

    pub fn connect_ws(&mut self, url: &str) -> Result<(), JsValue> {
        self.disconnect();
        let socket = WebSocket::new(url)?;
        socket.set_binary_type(BinaryType::Arraybuffer);
        self.state.borrow_mut().socket = Some(socket.clone());

        let open_state = Rc::clone(&self.state);
        let on_open = Closure::wrap(Box::new(move |_event: WebEvent| {
            let _ = open_state.borrow_mut().flush_pending();
        }) as Box<dyn FnMut(_)>);
        socket.set_onopen(Some(on_open.as_ref().unchecked_ref()));

        let message_state = Rc::clone(&self.state);
        let on_message = Closure::wrap(Box::new(move |event: MessageEvent| {
            let Ok(buffer) = event.data().dyn_into::<ArrayBuffer>() else {
                return;
            };
            let bytes = Uint8Array::new(&buffer).to_vec();
            let (events, callbacks) = {
                let mut state = message_state.borrow_mut();
                let packets = state.decoder.push(&bytes);
                let mut events = Vec::new();
                for packet in packets {
                    let mut entropy = state.entropy;
                    events.extend(state.node.handle_inbound_with_entropy(
                        &packet,
                        INTERFACE_ID,
                        &mut entropy,
                    ));
                    state.entropy = entropy;
                }
                let _ = state.drain_outbound();
                (events, state.callbacks())
            };
            dispatch(events, callbacks);
        }) as Box<dyn FnMut(_)>);
        socket.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

        let tick_state = Rc::clone(&self.state);
        let tick = Closure::wrap(Box::new(move || {
            let (events, callbacks) = {
                let mut state = tick_state.borrow_mut();
                let mut entropy = state.entropy;
                let events = state.node.tick_with_entropy(&mut entropy);
                state.entropy = entropy;
                let _ = state.drain_outbound();
                (events, state.callbacks())
            };
            dispatch(events, callbacks);
        }) as Box<dyn FnMut()>);
        let interval_id = web_sys::window()
            .ok_or_else(|| JsValue::from_str("window is unavailable"))?
            .set_interval_with_callback_and_timeout_and_arguments_0(
                tick.as_ref().unchecked_ref(),
                1_000,
            )?;

        self.on_open = Some(on_open);
        self.on_message = Some(on_message);
        self.tick = Some(tick);
        self.interval_id = Some(interval_id);
        Ok(())
    }

    pub fn announce(&self, app_data: Option<String>) -> Result<(), JsValue> {
        let mut state = self.state.borrow_mut();
        let destinations: Vec<_> = state.node.local_destinations().collect();
        for destination in destinations {
            let mut entropy = state.entropy;
            state.node.send_announce(
                &destination,
                app_data.as_deref().unwrap_or_default().as_bytes(),
                &mut entropy,
                INTERFACE_ID,
            );
            state.entropy = entropy;
        }
        state.drain_outbound()
    }

    pub fn send(&self, destination_hex: &str, text: &str) -> Result<(), JsValue> {
        let destination = hash16_from_hex(destination_hex)?;
        let mut state = self.state.borrow_mut();
        let mut entropy = state.entropy;
        state
            .node
            .send_message(&destination, text.as_bytes(), &mut entropy)
            .map_err(|error| JsValue::from_str(&format!("send failed: {error:?}")))?;
        state.entropy = entropy;
        state.drain_outbound()
    }

    #[wasm_bindgen(js_name = setOnMessage)]
    pub fn set_on_message(&self, callback: Function) {
        self.state.borrow_mut().on_message = Some(callback);
    }

    #[wasm_bindgen(js_name = setOnDelivered)]
    pub fn set_on_delivered(&self, callback: Function) {
        self.state.borrow_mut().on_delivered = Some(callback);
    }

    pub fn disconnect(&mut self) {
        if let Some(interval_id) = self.interval_id.take()
            && let Some(window) = web_sys::window()
        {
            window.clear_interval_with_handle(interval_id);
        }
        if let Some(socket) = self.state.borrow_mut().socket.take() {
            socket.set_onopen(None);
            socket.set_onmessage(None);
            let _ = socket.close();
        }
        self.on_open = None;
        self.on_message = None;
        self.tick = None;
        self.state.borrow_mut().pending.clear();
    }
}

impl Drop for ReticulumNode {
    fn drop(&mut self) {
        self.disconnect();
    }
}

fn dispatch(events: Vec<Event>, callbacks: (Option<Function>, Option<Function>)) {
    for event in events {
        match event {
            Event::Message {
                dest_hash,
                plaintext,
            } => {
                if let Some(callback) = callbacks.0.as_ref() {
                    let _ = callback.call2(
                        &JsValue::NULL,
                        &JsValue::from_str(&hex::encode(dest_hash)),
                        &JsValue::from_str(&String::from_utf8_lossy(&plaintext)),
                    );
                }
            }
            Event::Delivered { packet_hash } => {
                if let Some(callback) = callbacks.1.as_ref() {
                    let _ = callback.call1(
                        &JsValue::NULL,
                        &JsValue::from_str(&hex::encode(packet_hash)),
                    );
                }
            }
            _ => {}
        }
    }
}

fn identity_from_hex(encoded: &str) -> Result<Identity, JsValue> {
    let private = hex::decode(encoded)
        .map_err(|error| JsValue::from_str(&format!("invalid identity hex: {error}")))?;
    if private.len() != 64 {
        return Err(JsValue::from_str(
            "identity must contain exactly 64 private-key bytes",
        ));
    }
    let x25519 = private[..32]
        .try_into()
        .map_err(|_| JsValue::from_str("invalid X25519 key"))?;
    let ed25519 = private[32..]
        .try_into()
        .map_err(|_| JsValue::from_str("invalid Ed25519 key"))?;
    Ok(Identity::from_private_bytes(&x25519, &ed25519))
}

fn hash16_from_hex(encoded: &str) -> Result<[u8; 16], JsValue> {
    let decoded = hex::decode(encoded)
        .map_err(|error| JsValue::from_str(&format!("invalid destination hex: {error}")))?;
    decoded
        .try_into()
        .map_err(|_| JsValue::from_str("destination must contain exactly 16 bytes"))
}

#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn validates_identity_and_registers_destination() {
        let identity = format!("{}{}", "11".repeat(32), "22".repeat(32));
        let node = ReticulumNode::new(&identity).unwrap();
        let hash = node
            .register_single_destination("wasm_test", vec!["message".to_owned()])
            .unwrap();
        assert_eq!(hash.len(), 32);
        assert!(ReticulumNode::new("00").is_err());
    }
}
