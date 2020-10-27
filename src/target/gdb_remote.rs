use std::io::{Read, Write};

pub struct GDBRemoteTarget<S: Read + Write> {
    stream: S,
    timeout: Option<std::time::Duration>,
}

impl GDBRemoteTarget<std::net::TcpStream> {
    pub fn connect_tcp<A: std::net::ToSocketAddrs>(
        addr: A,
        timeout: std::time::Duration,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let stream = std::net::TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        Ok(Self {
            stream,
            timeout: None,
        })
    }
}

#[derive(Debug, Clone)]
pub enum GDBRemoteTargetError {
    InvalidCharacterReceived(char),
    AckFailure(),
    InvalidNumOfCharsRead(),
}

impl std::fmt::Display for GDBRemoteTargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let string = match self {
            GDBRemoteTargetError::InvalidCharacterReceived(ch) => {
                format!("Invalid character received: {}", ch)
            }
            GDBRemoteTargetError::AckFailure() => {
                "Could not send data properly or ack was not received".to_string()
            }
            GDBRemoteTargetError::InvalidNumOfCharsRead() => {
                "Read invalid number of chars".to_string()
            }
        };
        write!(f, "{}", string)
    }
}

impl std::error::Error for GDBRemoteTargetError {}

impl<S: Read + Write> GDBRemoteTarget<S> {
    pub fn send(&mut self, mut package: PacketWriter) -> Result<(), Box<dyn std::error::Error>> {
        // FIXME: Move tries_left into struct
        let mut tries_left = 5;

        while tries_left > 0 {

            package.send(&mut self.stream)?;

            let mut buf = [0u8; 1];
            match self.stream.read(&mut buf) {
                Ok(1) => match buf[0] as char {
                    // Everything ok, received ack
                    '+' => {
                        return Ok(());
                    }
                    // Error occured during transmission, resending packet
                    '-' => {
                        package.send(&mut self.stream)?;
                    }
                    _ => {
                        return Err(Box::new(GDBRemoteTargetError::InvalidCharacterReceived(
                            buf[0] as char,
                        )));
                    }
                },
                // Received incorrect number of bytes
                Ok(_) => {
                    return Err(Box::new(GDBRemoteTargetError::InvalidNumOfCharsRead()));
                }
                Err(err) => {
                    if let std::io::ErrorKind::TimedOut = err.kind() {
                    } else {
                        return Err(Box::new(err));
                    }
                }
            }

            // Waiting before trying to read again
            if let Some(timeout) = self.timeout {
                std::thread::sleep(timeout);
            }
            tries_left -= 1;
        }

        // Tries run out
        Err(Box::new(GDBRemoteTargetError::AckFailure()))
    }
}

pub struct PacketWriter {
    buffer: [u8; 1024],
    pointer: usize,
    checksum: u8,
}

impl PacketWriter {
    pub fn new() -> Self {
        let mut buffer = [0u8; 1024];
        buffer[0] = '$' as u8;
        PacketWriter {
            buffer,
            pointer: 1,
            checksum: 0,
        }
    }

    fn write_raw(&mut self, byte: u8) {
        self.buffer[self.pointer] = byte;
        self.pointer += 1;
    }

    pub fn write_byte(mut self, byte: u8) -> Self {
        if byte == '$' as u8 || byte == '#' as u8 || byte == '}' as u8 {
            self.write_raw('}' as u8);
            self.write_raw(byte ^ 0x20);
            self.checksum = self.checksum.wrapping_add('}' as u8);
            self.checksum = self.checksum.wrapping_add(byte ^ 0x20);
        } else {
            self.write_raw(byte);
            self.checksum = self.checksum.wrapping_add(byte);
        }
        self
    }

    pub fn write_slice(self, data: &[u8]) -> Self {
        data.iter()
            .fold(self, |packet_writer, byte| packet_writer.write_byte(*byte))
    }

    pub fn write_str(self, s: &str) -> Self {
        self.write_slice(s.as_bytes())
    }

    fn add_checksum(&mut self) {
        self.write_raw('#' as u8);
        let checksum_str = format!("{:02x}", self.checksum);
        for ch in checksum_str.chars() {
            self.write_raw(ch as u8);
        };
    }

    pub fn send<W: std::io::Write>(
        &mut self,
        writer: &mut W,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.add_checksum();
        writer.write(&self.buffer[0..self.pointer])?;
        writer.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_packet_test() {
        let mut packet_writer = PacketWriter::new().write_str("OK");
        packet_writer.add_checksum();
        assert_eq!(
            "$OK#9a",
            std::str::from_utf8(&packet_writer.buffer[0..packet_writer.pointer]).unwrap()
        );

        let mut packet_writer = PacketWriter::new().write_str("}");
        packet_writer.add_checksum();
        assert_eq!(
            "$}]#da",
            std::str::from_utf8(&packet_writer.buffer[0..packet_writer.pointer]).unwrap()
        );
    }
}
