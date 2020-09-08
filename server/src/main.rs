use std::str;
use tokio::net::TcpListener;
use tokio::prelude::*;

fn u6_to_base64(b: u8) -> u8 {
    const BASE64: [u8; 64] = [
        0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,
        0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F,0x50,
        0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,
        0x59,0x5A,0x61,0x62,0x63,0x64,0x65,0x66,
        0x67,0x68,0x69,0x6A,0x6B,0x6C,0x6D,0x6E,
        0x6F,0x70,0x71,0x72,0x73,0x74,0x75,0x76,
        0x77,0x78,0x79,0x7A,0x30,0x31,0x32,0x33,
        0x34,0x35,0x36,0x37,0x38,0x39,0x2B,0x2F,
    ];
    BASE64[b as usize]
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
            println!("base64: a = {:0X}, b = {:0X}",a,b);
            println!("base64: a >> 2 = {:0X}",a >> 2);
            println!("base64: ((a & 0x03) << 4) | (b >> 4) = {:0X}",((a & 0x03) << 4) | (b >> 4));
            println!("base64: (b & 0x0F) << 2 = {:0X}",(b & 0x0F) << 2);
            result.push(u6_to_base64(a >> 2));
            result.push(u6_to_base64(((a & 0x03) << 4) | (b >> 4)));
            result.push(u6_to_base64((b & 0x0F) << 2));
            result.push(0x3D);
            println!("encoded as {:0X} {:0X} {:0X} {:0X}",result[result.len() - 4],result[result.len() - 3],result[result.len() - 2],result[result.len() - 1]);
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

fn rol1(value: u32) -> u32 {
    (value << 1) | (value >> 31)
}

fn rol5(value: u32) -> u32 {
    (value << 5) | (value >> 27)
}

fn rol30(value: u32) -> u32 {
    (value << 30) | (value >> 2)
}

fn sha1_hash(buffer: &Vec<u8>) -> Vec<u8> {
    let mut message = buffer.clone();
    let ml = message.len() as u64;
    message.push(0x80);
    let mut padding = 64 - ((ml + 1) % 64);
    if padding < 8 { padding += 64; }
    for _i in 0..padding {
        message.push(0);
    }
    let ml2 = message.len() as u64;
    let ml = ml * 8;
    message[(ml2 - 8) as usize] = (ml >> 56) as u8;
    message[(ml2 - 7) as usize] = ((ml >> 48) & 0xFF) as u8;
    message[(ml2 - 6) as usize] = ((ml >> 40) & 0xFF) as u8;
    message[(ml2 - 5) as usize] = ((ml >> 32) & 0xFF) as u8;
    message[(ml2 - 4) as usize] = ((ml >> 24) & 0xFF) as u8;
    message[(ml2 - 3) as usize] = ((ml >> 16) & 0xFF) as u8;
    message[(ml2 - 2) as usize] = ((ml >> 8) & 0xFF) as u8;
    message[(ml2 - 1) as usize] = (ml & 0xFF) as u8;
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;
    for b in 0..ml2 / 64 {
        let mut block: Vec<u32> = Vec::new();
        for i in 0..16 {
            block.push(
                ((message[(b * 64 + i * 4) as usize] as u32) << 24) |
                ((message[(b * 64 + i * 4 + 1) as usize] as u32) << 16) |
                ((message[(b * 64 + i * 4 + 2) as usize] as u32) << 8) |
                (message[(b * 64 + i * 4 + 3) as usize] as u32)
            );
        }
        for i in 16..80 {
            block.push(
                rol1(block[i - 3] ^ block[i - 8] ^ block[i - 14] ^ block[i - 16])
            );
        }
        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;
        let mut f = 0u32;
        let mut k = 0u32;
        for i in 0..80 {
            if i < 20 {
                f = (b & c) | (!b & d);
                k = 0x5A827999;
            }
            else if i < 40 {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            }
            else if i < 60 {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            }
            else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            let temp = rol5(a) + f + e + k + block[i];
            e = d;
            d = c;
            c = rol30(b);
            b = a;
            a = temp;
        }
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }
    vec![
        (h0 >> 24) as u8,
        ((h0 >> 16) & 0xFF) as u8,
        ((h0 >> 8) & 0xFF) as u8,
        (h0 & 0xFF) as u8,
        (h1 >> 24) as u8,
        ((h1 >> 16) & 0xFF) as u8,
        ((h1 >> 8) & 0xFF) as u8,
        (h1 & 0xFF) as u8,
        (h2 >> 24) as u8,
        ((h2 >> 16) & 0xFF) as u8,
        ((h2 >> 8) & 0xFF) as u8,
        (h2 & 0xFF) as u8,
        (h3 >> 24) as u8,
        ((h3 >> 16) & 0xFF) as u8,
        ((h3 >> 8) & 0xFF) as u8,
        (h3 & 0xFF) as u8,
        (h4 >> 24) as u8,
        ((h4 >> 16) & 0xFF) as u8,
        ((h4 >> 8) & 0xFF) as u8,
        (h4 & 0xFF) as u8,
    ]
}

fn build_frame() -> Vec<u8> {
    let mut buffer: Vec<u8> = Vec::new();
    buffer.push(0x02);  // not FIN, RSV=0, opcode 2: binary
    buffer.push(0x7E);  // no mask, length = 16-bits
    buffer.push(0x80);  // length (32768)
    buffer.push(0x00);
    buffer.extend(vec![0xAA; 32768]);
    buffer
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
            let mut output_key_string = String::new();
            for line in header.split('\n') {
                let parts: Vec<&str> = line.trim().split(':').collect();
                if parts[0] == "Sec-WebSocket-Key" {
                    let mut key = parts[1].trim().as_bytes().to_vec();
                    key.extend("258EAFA5-E914-47DA-95CA-C5AB0DC85B11".as_bytes().to_vec());
                    let output_hash = sha1_hash(&key);
                    let output_key = base64_encode(&output_hash);
                    output_key_string = String::from_utf8(output_key).unwrap();
                }
            }
            let message = format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",output_key_string);
            if let Err(e) = socket.write_all(message.as_bytes()).await {
                eprintln!("failed to write header to socket; err = {:?}",e);
            }
            loop {
                println!("sending 32k");
                if let Err(e) = socket.write_all(&build_frame()).await {
                    eprintln!("failed to write to socket; err = {:?}",e);
                    return;
                }
            }
        });
    }
}