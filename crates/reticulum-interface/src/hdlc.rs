use alloc::vec::Vec;

pub const FLAG: u8 = 0x7E;
pub const ESC: u8 = 0x7D;
pub const ESC_MASK: u8 = 0x20;

/// Wrap `data` in HDLC flags with byte-stuffing (RNS TCP/serial framing).
pub fn frame(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 2);
    out.push(FLAG);
    for &b in data {
        if b == FLAG || b == ESC {
            out.push(ESC);
            out.push(b ^ ESC_MASK);
        } else {
            out.push(b);
        }
    }
    out.push(FLAG);
    out
}

/// Decode a single well-formed frame (leading and trailing FLAG). Returns
/// `None` on malformed input rather than panicking.
pub fn deframe(framed: &[u8]) -> Option<Vec<u8>> {
    if framed.len() < 2 || framed[0] != FLAG || framed[framed.len() - 1] != FLAG {
        return None;
    }
    let body = &framed[1..framed.len() - 1];
    let mut out = Vec::with_capacity(body.len());
    let mut esc = false;
    for &b in body {
        if esc {
            out.push(b ^ ESC_MASK);
            esc = false;
        } else if b == ESC {
            esc = true;
        } else if b == FLAG {
            return None; // unescaped flag inside body = malformed
        } else {
            out.push(b);
        }
    }
    if esc {
        return None;
    } // dangling escape
    Some(out)
}
