use tokio::net::TcpListener;
use tokio::prelude::*;

fn u6_to_base64(b: u8) -> u8 {
    if b < 26 { b + 0x41 }
    else if b < 52 { (b - 26) + 0x61 }
    else if b < 62 { (b - 52) + 0x30 }
    else if b == 62 { 0x2B }
    else if b == 63 { 0x2F }
    else { 0xFF }  // should never happen
}

fn base64_to_u6(b: u8) -> u8 {
    if (b >= 0x41) && (b < 0x5B) { b - 0x41 }
    else if (b >= 0x61) && (b < 0x7B) { 26 + (b - 0x61) }
    else if (b >= 0x30) && (b < 0x3A) { 52 + (b - 0x30) }
    else if b == 0x2B { 62 }
    else if b == 0x2F { 63 }
    else if b == 0x3D { 0xFE }
    else { 0xFF }
}

fn base64_encode(buffer: &Vec<u8>) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();
    let chunks = buffer.len() / 3;
    for i in 0..chunks {
        let a = buffer[i * 3];
        let b = buffer[i * 3 + 1];
        let c = buffer[i * 3 + 2];
        result.push(u6_to_base64(a >> 2));
        result.push(u6_to_base64(((a & 0x03) << 4) | (b >> 4)));
        result.push(u6_to_base64(((b & 0x0F) << 2) | (c >> 6)));
        result.push(u6_to_base64(c & 0x3F));
    }
    match buffer.len() - (chunks * 3) {
        1 => {
            let a = buffer[chunks * 3];
            result.push(u6_to_base64(a >> 2));
            result.push(u6_to_base64((a & 0x03) << 4));
            result.push(0x3D);
            result.push(0x3D);
        },
        2 => {
            let a = buffer[chunks * 3];
            let b = buffer[chunks * 3 + 1];
            result.push(u6_to_base64(a >> 2));
            result.push(u6_to_base64((a & 0x03) << 4) | (b >> 4));
            result.push(u6_to_base64((b & 0x0F) << 2));
            result.push(0x3D);
        },
        _ => { },
    }
    result
}

fn base64_decode(buffer: &Vec<u8>) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();
    let chunks = (buffer.len() + 3) / 4;
    for i in 0..chunks {
        let a = base64_to_u6(buffer[i * 4]);
        if a > 63 {
            return result;
        }
        let b = base64_to_u6(buffer[i * 4 + 1]);
        if b > 63 {
            return result;
        }
        result.push((a << 2) | (b >> 4));
        let c = base64_to_u6(buffer[i * 4 + 2]);
        if c == 0xFF {
            return result;
        }
        let d = base64_to_u6(buffer[i * 4 + 3]);
        if d == 0xFF {
            return result;
        }
        if c != 0xFE {
            result.push((b << 4) | (c >> 2));
            if d != 0xFE {
                result.push((c << 6) | d);
            }
        }
    }
    result
}

fn sha1_encrypt(buffer: &Vec<u8>) -> Vec<u8> {
    let h0 = 0x67452301;
    let h1 = 0xEFCDAB89;
    let h2 = 0x98BADCFE;
    let h3 = 0x10325476;
    let h4 = 0xC3D2E1F0;
    let ml = buffer.len() * 8;
    
}

fn sha1_decrypt() {

}

#[tokio::main]
async fn main() -> Result<(),Box<dyn std::error::Error>> {
    let mut listener = TcpListener::bind("127.0.0.1:6502").await?;
    loop {
        let (mut socket,_) = listener.accept().await?;
        tokio::spawn(async move {
            let mut buf = [0; 32768];
            let n = match socket.read(&mut buf).await {
                Ok(n) if n == 0 => return,
                Ok(n) => n,
                Err(e) => {
                    eprintln!("failed to read from socket; err = {:?}",e);
                    return;
                }
            };
            let header = String::from_utf8(buf[0..n].to_vec()).unwrap();
            for line in header.split('\n') {
                let parts: Vec<&str> = line.trim().split(':').collect();
                if parts[0] == "Sec-WebSocket-Key" {
                    let input_key = parts[1].trim().as_bytes().to_vec();
                    let mut key = base64_decode(&input_key);
                    println!("websocket key: {:X?}",key);
                    
                    // to debug base64 encoding/decoding:
                    let verify_input_key = base64_encode(&key);
                    let input_key_string = String::from_utf8(input_key).unwrap();
                    let verify_input_key_string = String::from_utf8(verify_input_key).unwrap();
                    if input_key_string != verify_input_key_string {
                        println!("base64 verification failed!");
                        println!("input: \"{}\"",input_key_string);
                        println!("re-encoded: \"{}\"",verify_input_key_string);
                    }
                    key.push(0x25);
                    key.push(0x8E);
                    key.push(0xAF);
                    key.push(0xA5);
                    key.push(0xE9);
                    key.push(0x14);
                    key.push(0x47);
                    key.push(0xDA);
                    key.push(0x95);
                    key.push(0xCA);
                    key.push(0xC5);
                    key.push(0xAB);
                    key.push(0x0D);
                    key.push(0xC8);
                    key.push(0x5B);
                    key.push(0x11);
                    println!("key with UUID appended: {:X?}",key);
                    // TODO: apply SHA-1
                    // TODO: encode result with base64
                }
            }
            if let Err(e) = socket.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: HSmrc0sMlYUkAGmm50PpG2HaGWk=\r\nSec-WebSocket-Protocol: chat\r\n").await {
                eprintln!("failed to write header to socket; err = {:?}",e);
            }
            loop {
                //let n = match socket.read(&mut buf).await {
                //    Ok(n) if n == 0 => return,
                //    Ok(n) => n,
                //    Err(e) => {
                //        eprintln!("failed to read from socket; err = {:?}",e);
                //        return;
                //    }
                //};
                if let Err(e) = socket.write_all(&buf).await {
                    eprintln!("failed to write to socket; err = {:?}",e);
                    return;
                }
            }
        });
    }
}