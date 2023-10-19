use super::*;
use client::msg::read_usize_be;
use conn::msg_handle::PackHandle;
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::io::{Read, Write};
use comm::aes_comm::Aes128CtrCipher;
use comm::{aes_comm, rand_gen};
use std::sync::{Arc, Mutex};
use cert_cont::CertContain;

const LENGH_WIDTH: usize = std::mem::size_of::<usize>();

macro_rules! echo_buf {
    ($buf: ident, $length: ident) => {
        for i in 0..$length {
            print!("{:X}", $buf[i] as u8);
        }
        println!("");
    };
    ($buf: expr, $length: ident) => {
        for i in 0..$length {
            print!("{:X}", $buf[i] as u8);
        }
        println!("");
    };
}

pub struct CertMG{
    listener: TcpListener,
    container: Arc<Mutex<CertContain> >,
    shared_aes: Arc<Vec<u8> >,
}

impl CertMG{
    pub fn new(ip_port: &str) -> Self {
        let listener = TcpListener::bind(ip_port).unwrap();
        Self {
            listener,
            container: Arc::new(Mutex::new(CertContain::new())),
            shared_aes: Arc::new(rand_gen::Generator::gen_biguint(256).to_bytes_be()),
        }
    }

    pub fn start(&self) {
        println!("server listening ...");
        for stream in self.listener.incoming() {
            println!("got one connection");
            thread::spawn(move || {
                conn_handle(stream.unwrap());
            });
        }
    }
 
    pub fn safe_start(&self) {
        println!("server listening ...");
        for stream in self.listener.incoming() {
            println!("got one connection");
            let child_arc = self.container.clone();
            let child_aes = self.shared_aes.clone();
            thread::spawn(move || {
                let mut service = init_service(stream.unwrap(), child_arc, child_aes);
                service.safe_conn_handle();
                // conn_handle(stream.unwrap());
            });
        }
    }

}


fn conn_handle(mut conn_stream: TcpStream) {
    let mut packhandle = PackHandle::new(&conn_stream);

    loop{
        let buf = packhandle.recv_msg().unwrap();
        let client_str = std::str::from_utf8(&buf).unwrap();
        println!("{}", client_str);

        if client_str == "close" {
            println!("connection from:{} shutdown", conn_stream.peer_addr().unwrap());
            break;
        }
    }
}

fn init_service(mut conn_stream: TcpStream, container: Arc<Mutex<CertContain> >, shared_aes: Arc<Vec<u8> >) -> CertService {
    let mut packhandle = PackHandle::new(&conn_stream);

    let mut ret = CertService {
        aes_cipher: Aes128CtrCipher::empty_new(),
        conn: conn_stream,
        packhandle,
        container,
        shared_aes,
    };
    ret.server_tls_handshake().unwrap();
    ret
}

struct CertService {
    aes_cipher: Aes128CtrCipher,
    conn: TcpStream,
    packhandle: PackHandle,
    container: Arc<Mutex<CertContain> >,
    shared_aes: Arc<Vec<u8> >,
}

impl CertService {
    fn parse_one_dec_msg(&mut self) -> Result<Vec<u8>, &'static str> {
        if self.aes_cipher.key_valid() != true {
            return Err("error: got one msg, but secure channel not yet established");
        }
        let msg = self.packhandle.recv_msg().unwrap();
        let dec_msg = self.aes_cipher.decrypt(&msg);
        Ok(dec_msg)
    }

    fn server_tls_handshake(&mut self) -> Result<(), &'static str> {
        let mut client_hello = [0u8; 512];
        let msg_len = self.conn.read(&mut client_hello).unwrap();
    
        match msg_len {
            0 => {
                Err("err from server handshake: recieve 0 bytes from client")
            },
            _ => {
                let mut server_hs = server::hs::ServerHs::new();
    
                let client_hello = &client_hello[0..msg_len];
                // println!("recv msg_len: {}", msg_len);
                server_hs.recv_clienthello_and_decrypt(client_hello);
    
                let server_hello = server_hs.reply_to_client();
                self.conn.write(&server_hello);
    
                let server_nego_key = server_hs.get_nego_key();
    
                // println!("nego_key: {}", server_nego_key);
                self.aes_cipher.set_key(&server_nego_key.to_bytes_be()).unwrap();

                Ok(())
            },
        }
    }

    fn safe_conn_handle(&mut self) {
        let mut flag = true;
        while flag {
            let request = self.parse_one_dec_msg().unwrap();
            let client_str = std::str::from_utf8(&request).unwrap();

            match client_str {
                "close" => {
                    println!("connection from:{} shutdown", self.conn.peer_addr().unwrap());
                    flag = false;
                    break;
                },

                "regist" => {
                    self.regist_handle();
                },

                "unregist" => {
                    self.unregist_handle();
                },

                "req_pubkey" => {
                    self.req_pubkey_handle();
                },

                "req_shared_aes" => {
                    self.req_shared_aes_handle();
                }

                _ => {
                    println!("got one unrecognized msg:\n{}", client_str);
                },
            }
        }
    }

    fn regist_handle(&mut self) {
        let pub_key = self.parse_one_dec_msg().unwrap();
        let len = pub_key.len();

        let mut container = self.container.lock().unwrap();
        let hash_key = container.regist(&pub_key);

        println!("recv one register request, distribute hash_tag: {} to pub_key:", hash_key);
        echo_buf!(&pub_key, len);

        let ret_msg = hash_key.to_be_bytes().to_vec();
        let enc_ret_msg = self.aes_cipher.encrypt(&ret_msg);
        self.packhandle.send_msg(&enc_ret_msg, enc_ret_msg.len());
    }

    fn unregist_handle(&mut self) {
        let hash_key_bytes = self.parse_one_dec_msg().unwrap();
        let hash_key = usize::from_be_bytes(hash_key_bytes[..LENGH_WIDTH].try_into().unwrap());
        println!("recv one unregist request, got hash_tag:{}", hash_key);

        let mut container = self.container.lock().unwrap();
        container.unregist(hash_key);
    }

    pub fn req_pubkey_handle(&mut self) {
        let hash_key_bytes: Vec<u8> = self.parse_one_dec_msg().unwrap();
        let hash_key = usize::from_be_bytes(hash_key_bytes[..LENGH_WIDTH].try_into().unwrap());
        println!("req pub key from:{}; with hash_tag:{}",self.conn.peer_addr().unwrap(), hash_key);

        let container = self.container.lock().unwrap();
        let pubkey = match container.req_val(hash_key) {
            Ok(val) => val,
            Err(err) => "None".as_bytes().to_vec(),
        };

        let enc_ret_msg = self.aes_cipher.encrypt(&pubkey);
        self.packhandle.send_msg(&enc_ret_msg, enc_ret_msg.len());
    } 

    fn req_shared_aes_handle(&mut self) {
        println!("req shared_aes from: {}", self.conn.peer_addr().unwrap());
        let len = self.shared_aes.len();
        echo_buf!(&self.shared_aes, len);
        let enc_ret_msg = self.aes_cipher.encrypt(&self.shared_aes);
        self.packhandle.send_msg(&enc_ret_msg, enc_ret_msg.len());
    }

}