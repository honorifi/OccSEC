use super::*;
use sgx_tstd::net::TcpStream;
use client::hs::CertMG_tls_handshake;
use conn::msg_handle::PackHandle;
use comm::ecdsa::{EcdsaPublic, EcdsaPublicBytes};
use std::collections::HashMap;

lazy_static! {
    static ref KEY_LOCAL_CACHE: SgxMutex<HashMap<usize, EcdsaPublicBytes>> = 
        SgxMutex::new(HashMap::new());
}


const LENGH_WIDTH: usize = std::mem::size_of::<usize>();

pub fn msg_sender(repeat: usize) {
    let mut conn = TcpStream::connect("127.0.0.1:10011").unwrap();
    let packhandle = PackHandle::new(&conn);

    for i in 0..repeat {
        let mut send_buf = String::new();
        let len = std::io::stdin().read_line(&mut send_buf).unwrap();

        packhandle.send_msg(send_buf.as_bytes(), len);
    }
    let send_buf = "close".as_bytes();
    packhandle.send_msg(&send_buf, send_buf.len());
}

// fn send_msg(mut conn: &TcpStream, msg: &[u8], len: usize) {
//     let mut msg_send = Vec::from(len.to_be_bytes());
//     msg_send.append(&mut Vec::from(msg));
//     // println!("{:?}", msg_send);
//     conn.write(&msg_send).unwrap();
// }

pub fn safe_msg_sender(repeat: usize) {
    let mut conn = TcpStream::connect("127.0.0.1:10011").unwrap();
    let packhandle = PackHandle::new(&conn);
    let aes_cipher = CertMG_tls_handshake(&conn);

    for i in 0..repeat {
        let mut input_buf = String::new();
        let length = std::io::stdin().read_line(&mut input_buf).unwrap();
        let send_buf = aes_cipher.encrypt(input_buf.as_bytes());

        packhandle.send_msg(&send_buf, send_buf.len());
    }

    let send_buf = aes_cipher.encrypt("close".as_bytes());
    packhandle.send_msg(&send_buf, send_buf.len());
}

pub fn safe_msg_static_sender(repeat: usize) {
    let mut conn = TcpStream::connect("127.0.0.1:10011").unwrap();
    let packhandle = PackHandle::new(&conn);
    let aes_cipher = CertMG_tls_handshake(&conn);

    for i in 0..repeat {
        let msg = i.to_string();
        // println!("send: {}", msg);
        let send_buf = aes_cipher.encrypt(msg.as_bytes());
        packhandle.send_msg(&send_buf, send_buf.len());
    }
    
    let send_buf = aes_cipher.encrypt("close".as_bytes());
    packhandle.send_msg(&send_buf, send_buf.len());
}

pub fn safe_regist() {
    let mut conn = TcpStream::connect("127.0.0.1:10011").unwrap();
    let mut packhandle = PackHandle::new(&conn);
    let aes_cipher = CertMG_tls_handshake(&conn);

    let (priv_key, pub_key) = comm::ca_manager::generate_ec_key_pair();

    let req_type = aes_cipher.encrypt("regist".as_bytes());
    let pub_key_enc = aes_cipher.encrypt(&pub_key);
    packhandle.send_msg(&req_type, req_type.len());
    packhandle.send_msg(&pub_key_enc, pub_key_enc.len());

    let hash_key_enc = packhandle.recv_msg().unwrap();
    let hash_key_dec = aes_cipher.decrypt(&hash_key_enc);
    let hash_key = usize::from_be_bytes(hash_key_dec[..LENGH_WIDTH].try_into().unwrap());
    
    let close_req = aes_cipher.encrypt("close".as_bytes());
    packhandle.send_msg(&close_req, close_req.len());

    println!("hash_key: {}", hash_key);
}

pub fn safe_unregist(hash_key: usize) {
    let mut conn = TcpStream::connect("127.0.0.1:10011").unwrap();
    let mut packhandle = PackHandle::new(&conn);
    let aes_cipher = CertMG_tls_handshake(&conn);

    let req_type = aes_cipher.encrypt("unregist".as_bytes());
    let hash_key_enc = aes_cipher.encrypt(&hash_key.to_be_bytes());
    packhandle.send_msg(&req_type, req_type.len());
    packhandle.send_msg(&hash_key_enc, hash_key_enc.len());

    let close_req = aes_cipher.encrypt("close".as_bytes());
    packhandle.send_msg(&close_req, close_req.len());
}


pub fn generate_and_regist_pubkey() -> usize {
    println!("generate and regist my ECkey");

    comm::ca_manager::generate_ec_file("/host/myEC_key");
    let ec_handle = comm::ca_manager::get_ec_fromfile("/host/myEC_key");
    let pub_key = ec_handle.to_pub_handle().to_be_bytes();

    let mut conn = TcpStream::connect("127.0.0.1:10011").unwrap();
    let mut packhandle = PackHandle::new(&conn);
    let aes_cipher = CertMG_tls_handshake(&conn);

    let req_type = aes_cipher.encrypt("regist".as_bytes());
    let pub_key_enc = aes_cipher.encrypt(&pub_key);
    packhandle.send_msg(&req_type, req_type.len());
    packhandle.send_msg(&pub_key_enc, pub_key_enc.len());

    let hash_tag_enc = packhandle.recv_msg().unwrap();
    let hash_tag_dec = aes_cipher.decrypt(&hash_tag_enc);
    let hash_tag = usize::from_be_bytes(hash_tag_dec[..LENGH_WIDTH].try_into().unwrap());
    
    let close_req = aes_cipher.encrypt("close".as_bytes());
    packhandle.send_msg(&close_req, close_req.len());

    println!("hash_key: {}", hash_tag);

    let hash_tag_file = comm::FileWriter::create("/host/hash_tag").unwrap();
    hash_tag_file.write(&hash_tag.to_be_bytes());

    hash_tag
}

pub fn request_peer_pubkey(ec_hash_tag: usize) -> EcdsaPublic {
    let mut klc = KEY_LOCAL_CACHE.lock().unwrap();
    match klc.get(&ec_hash_tag) {
        Some(pubkey_bytes) => {
            println!("found peer EC_pubkey in KLC");
            let handle = pubkey_bytes.to_pub_handle();
            return handle;
        }
        None => println!("request peer EC_pubkey from CertMG"),
    };

    let mut conn = TcpStream::connect("127.0.0.1:10011").unwrap();
    let mut packhandle = PackHandle::new(&conn);
    let aes_cipher = CertMG_tls_handshake(&conn);

    let req_type = aes_cipher.encrypt("req_pubkey".as_bytes());
    let hash_tag = aes_cipher.encrypt(&ec_hash_tag.to_be_bytes());
    packhandle.send_msg(&req_type, req_type.len());
    packhandle.send_msg(&hash_tag, hash_tag.len());

    let pubkey_bytes_enc = packhandle.recv_msg().unwrap();
    let pubkey_bytes_dec = aes_cipher.decrypt(&pubkey_bytes_enc);
    if pubkey_bytes_dec.len() == 0 {
        panic!("hash_tag:{} with no pubkey found in CertMG", ec_hash_tag);
    }
    let ret = EcdsaPublic::from_be_bytes(&pubkey_bytes_dec);
    klc.insert(ec_hash_tag, EcdsaPublicBytes::from_pub_handle(&ret));
    
    let close_req = aes_cipher.encrypt("close".as_bytes());
    packhandle.send_msg(&close_req, close_req.len());

    ret
}