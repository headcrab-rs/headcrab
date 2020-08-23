use std::io::{Read, Write};

pub struct GDBRemoteTarget<S: Read + Write> {
    stream: S
}

impl GDBRemoteTarget<std::net::TcpStream> {
    pub fn connect_tcp<A: std::net::ToSocketAddrs>(addr: A) -> Result<Self, Box<dyn std::error::Error>> {
        let stream = std::net::TcpStream::connect(addr)?;
        Ok(Self { stream })
    }
}

impl<S: Read + Write> GDBRemoteTarget<S> {

    fn send_packet(&mut self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let mut buffer = [0u8; 1024];
        let len = encode_packet(data, &mut buffer);

        self.stream.write(&buffer[0..len])?;
        self.stream.flush()?;
        Ok(())
    }
}

fn encode_packet(data: &[u8], buffer: &mut [u8]) -> usize {

    // Special character
    buffer[0] = '$' as u8;
    let mut buffer_index = 1;

    // Escaping characters
    for val in data {
        if *val == '$' as u8 || *val == '#' as u8 || *val == '}' as u8 {
            buffer[buffer_index] = '}' as u8;
            buffer[buffer_index + 1] = val ^ 0x20;
            buffer_index += 2;
        }
        else {
            buffer[buffer_index] = *val;
            buffer_index += 1;
        }
    }

    // Special character
    buffer[buffer_index] = '#' as u8;
    buffer_index += 1;

    // Calculating checksum
    let remainder: u64 = data.iter().fold(0, |acc, x| {
        let res = acc + (*x as u64);
        res % 256
    });

    // Inserting checksum
    let checksum = format!("{:x}", remainder);
    for ch in checksum.chars(){
        buffer[buffer_index] = ch as u8;
        buffer_index += 1;
    }

    buffer_index
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_packet_test() {
        let expected = "$OK#9a";
        let mut buffer = [0u8; 6];
        let data = ['O' as u8, 'K' as u8];
        let len = encode_packet(&data, &mut buffer);
        assert_eq!(6, len);
        assert_eq!(expected, std::str::from_utf8(&buffer).unwrap());
    }

    #[test]
    fn encode_packet_escape_test() {
        let expected = "$}]#7d";
        let mut buffer = [0u8; 6];
        let data = ['}' as u8];
        let len = encode_packet(&data, &mut buffer);
        assert_eq!(6, len);
        assert_eq!(expected, std::str::from_utf8(&buffer).unwrap());
    }
}