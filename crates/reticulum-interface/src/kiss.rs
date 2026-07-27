use alloc::vec::Vec;

pub const FEND: u8 = 0xC0;
pub const FESC: u8 = 0xDB;
pub const TFEND: u8 = 0xDC;
pub const TFESC: u8 = 0xDD;
pub const CMD_DATA: u8 = 0x00;

/// Wrap a raw packet in a KISS data frame on port zero.
pub fn frame(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 3);
    out.push(FEND);
    out.push(CMD_DATA);
    for &byte in data {
        match byte {
            FEND => out.extend_from_slice(&[FESC, TFEND]),
            FESC => out.extend_from_slice(&[FESC, TFESC]),
            _ => out.push(byte),
        }
    }
    out.push(FEND);
    out
}

/// Decode one complete KISS data frame. Command frames, invalid escapes and
/// incomplete frames are rejected without panicking.
pub fn deframe(framed: &[u8]) -> Option<Vec<u8>> {
    if framed.len() < 3 || framed[0] != FEND || framed.last() != Some(&FEND) {
        return None;
    }
    if framed[1] & 0x0F != CMD_DATA {
        return None;
    }

    let mut out = Vec::with_capacity(framed.len() - 3);
    let mut escaped = false;
    for &byte in &framed[2..framed.len() - 1] {
        if escaped {
            out.push(match byte {
                TFEND => FEND,
                TFESC => FESC,
                _ => return None,
            });
            escaped = false;
        } else {
            match byte {
                FESC => escaped = true,
                FEND => return None,
                _ => out.push(byte),
            }
        }
    }
    (!escaped).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_reserved_bytes_and_strips_port_nibble() {
        let raw = [0x01, FEND, 0x02, FESC, 0x03];
        assert_eq!(
            frame(&raw),
            [
                FEND, CMD_DATA, 0x01, FESC, TFEND, 0x02, FESC, TFESC, 0x03, FEND
            ]
        );
        assert_eq!(deframe(&frame(&raw)).unwrap(), raw);

        let mut alternate_port = frame(&raw);
        alternate_port[1] = 0xA0;
        assert_eq!(deframe(&alternate_port).unwrap(), raw);
    }

    #[test]
    fn rejects_commands_and_malformed_escapes() {
        assert_eq!(deframe(&[FEND, 0x01, 0x10, FEND]), None);
        assert_eq!(deframe(&[FEND, CMD_DATA, FESC, 0x01, FEND]), None);
        assert_eq!(deframe(&[FEND, CMD_DATA, FESC, FEND]), None);
    }
}
