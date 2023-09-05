//this file is edit by kxc
use super::*;
use std::any::Any;
use fs::{FsView, FileMode, AccessMode, CreationFlags, StatusFlags, INodeFile, AsINodeFile};
use self::local_proxy::{EncryptLocalProxy, RunningELP, EncryptMsg};
use tls::comm::aes_comm::Aes128CtrCipher;
use std::sync::{SgxMutex as Mutex, SgxMutexGuard as MutexGuard, SgxRwLock as RwLock};
const LENGH_WIDTH: usize = std::mem::size_of::<usize>();


macro_rules! try_libc {
    ($ret: expr) => {{
        let ret = unsafe { $ret };
        if ret < 0 {
            let errno = unsafe { libc::errno() };
            return_errno!(Errno::from(errno as u32), "libc error");
        }
        ret
    }};
}

macro_rules! echo_buf {
    ($buf: ident) => {
        let length = EncryptMsg::msg_len($buf);
        for i in 0..length {
            print!("{:X}", $buf[i] as u8);
        }
        println!("");
    };
    ($buf: expr) => {
        let length = EncryptMsg::msg_len({$buf});
        for i in 0..length {
            print!("{:X}", $buf[i] as u8);
        }
        println!("");
    };
}

#[derive(Debug)]
enum NfvSocketState {
    NEW,            // could not send anything
    BARE,           // UDP socket, allow plaintext msg
    CONNECTED,      // could only use sendto to send plaintext msg to other socket except peer
    CHELLOSEND,    // already send client hello
    HANDSHAKED,     // could send encrypted msg to peer
}

#[derive(Debug)]
pub struct NfvSocket {
    // pub nfv_fd: Arc<dyn File>,
    pub host_sc: HostSocket,                // host socket
    pub hs_sock: Option<HostSocket>,                // handshake socket
    pub aes_cipher: RwLock<Aes128CtrCipher>,
    pub pub_key_hash_tag: usize,            // 0 means did not registed yet.
    sock_state: RwLock<NfvSocketState>,
    aes_msg_buf: RwLock<Vec<u8>>,           // aes padding require whole msg recv, but the app may tunic the msg, this buff is used to cache the remain data
    //pub key: Some(BigUint),
    //pub elp_service: RunningELP,
}

impl NfvSocket {
    pub fn new(
        domain: AddressFamily,
        socket_type: SocketType,
        file_flags: FileFlags,
        protocol: i32,
    ) -> Result<Self> {
        // let path = "/host/Nfv_pipe";
        // let flags =
        // AccessMode::O_RDWR as u32 | (CreationFlags::O_CREAT | CreationFlags::O_TRUNC).bits();// | StatusFlags::O_APPEND.bits();
        // let current = current!();
        // let host_fs = current.fs().read().unwrap();
        // let fd = match host_fs.open_file(path, flags, FileMode::all()) {
        //     Ok(fd) => {println!("open File success {:?}", fd); fd},
        //     Err(error) => panic!("open File failed {:?}", error),
        // };
        let pub_key_hash_tag = tls::comm::ca_manager::get_echash_fromfile("/host/hash_tag");

        let host_sc = HostSocket::new(domain, socket_type, file_flags, protocol)?;
        let mut raw_aes_cipher = Aes128CtrCipher::empty_new();
        let aes_cipher =  RwLock::new(raw_aes_cipher);
        println!("socket_type: {:?}", socket_type);
        
        let sock_state = RwLock::new(match socket_type {
            SocketType::STREAM => NfvSocketState::NEW,
            _ => NfvSocketState::BARE,
        });
        let hs_sock = match socket_type {
            SocketType::STREAM => {
                match pub_key_hash_tag {
                    0 => None,
                    _ => Some(HostSocket::new(domain, socket_type, file_flags, protocol)?),
                }
            },
            _ => None,
        };
        //let elp_service = EncryptLocalProxy::new(fd.clone()).start();

        Ok(Self {
            // nfv_fd: fd, 
            host_sc,
            hs_socket,
            aes_cipher,
            pub_key_hash_tag,
            sock_state,
            aes_msg_buf: RwLock::new(Vec::new()),
            //elp_service,
        })
    }

    fn from_host_sc(host_sc: HostSocket) -> NfvSocket {
        // let path = "/host/Nfv_pipe";
        // let flags =
        // AccessMode::O_RDWR as u32 | (CreationFlags::O_CREAT | CreationFlags::O_TRUNC).bits();// | StatusFlags::O_APPEND.bits();
        // let current = current!();
        // let host_fs = current.fs().read().unwrap();
        // let fd = match host_fs.open_file(path, flags, FileMode::all()) {
        //     Ok(fd) => {println!("open File success {:?}", fd); fd},
        //     Err(error) => panic!("open File failed {:?}", error),
        // };
        //let elp_service = EncryptLocalProxy::new(fd.clone()).start();
        let pub_key_hash_tag = tls::comm::ca_manager::get_echash_fromfile("/host/hash_tag");

        let mut raw_aes_cipher = Aes128CtrCipher::empty_new();
        let aes_cipher = RwLock::new(raw_aes_cipher);

        Self {
            // nfv_fd: fd, 
            host_sc,
            hs_sock: None,
            aes_cipher,
            pub_key_hash_tag,
            // server_tls_handshake is blocked, if it fail, then fail all the time
            sock_state: RwLock::new(NfvSocketState::BARE),
            aes_msg_buf: RwLock::new(Vec::new()),
            // elp_service,
        }
    }

    fn from_hsc_cipher(host_sc: HostSocket, cipher:Aes128CtrCipher) -> NfvSocket {
        let pub_key_hash_tag = tls::comm::ca_manager::get_echash_fromfile("/host/hash_tag");

        Self {
            host_sc,
            hs_sock: None,      // already got aes_cipher, no need to use hs_sock
            aes_cipher: RwLock::new(cipher),
            pub_key_hash_tag, 
            sock_state: RwLock::new(NfvSocketState::HANDSHAKED),
            aes_msg_buf: RwLock::new(Vec::new()),
        }
    }

    pub fn bind(&self, addr: &SockAddr) -> Result<()> {
        self.host_sc.bind(addr)
    }

    pub fn listen(&self, backlog: i32) -> Result<()> {
        self.host_sc.listen(backlog)
    }

    pub fn accept(&self, flags: FileFlags) -> Result<(NfvSocket, Option<SockAddr>)> {
        if self.pub_key_hash_tag == 0 {
            return self.host_sc.accept(flags);
        }

        let (host_sc, addr_option) = match self.host_sc.accept(flags) {
            Ok(ret) => ret,
            Err(err) => {
                println!("accept Err: {:?}", err);
                return Err(err);
            },
        };
        let (host_sc, addr_option) = match self.hs_sock.unwrap().accept(flags) {
            Ok(ret) => ret,
            Err(err) => {
                println!("accept Err: {:?}", err);
                return Err(err);
            },
        };

        // kssp mode off
        if self.pub_key_hash_tag == 0 {
            return Ok((NfvSocket::from_host_sc(host_sc), addr_option));
        }

        // println!("accept server_tls_handshake");
        match self.server_tls_handshake(&host_sc) {
            Ok(cipher) => {
                Ok((NfvSocket::from_hsc_cipher(host_sc, cipher), addr_option))
            },
            Err(err) => {
                println!("\x1b[33m[Warning:handshake faild] {}\x1b[0m", err);
                Ok((NfvSocket::from_host_sc(host_sc), addr_option))
            },
        }
    }

    fn server_tls_handshake(&self, host_sc: &HostSocket) -> Result<Aes128CtrCipher> {
        let sflag = SendFlags::MSG_NOSIGNAL;
        let mut server_hs = server::hs::ServerHsRmAt::new();

        if let Err(err) = server_hs.recv_clienthello_and_parse(&host_sc) {
            println!("clienthello parse fail");
            // std::thread::park_timeout(std::time::Duration::from_secs(0));
            return Err(err);
        }

        let server_hello = server_hs.reply_to_client();

        if let Err(err) = host_sc.sendto(&server_hello, sflag, &None) {
            println!("server handshake send fail: {:?}", err);
            // std::thread::park_timeout(std::time::Duration::from_secs(0));
            return Err(err);
        }
        
        let server_nego_key = server_hs.get_nego_key();

        // println!("nego_key: {}", server_nego_key);

        println!("\x1b[32mhandshake success\x1b[0m");
        Ok(Aes128CtrCipher::new(&server_nego_key.to_bytes_be()).unwrap())
    }

    pub fn connect(&self, addr: &Option<SockAddr>) -> Result<()> {
        if self.pub_key_hash_tag == 0{
            return self.host_sc.connect(addr);
        }
        
        let ret = self.host_sc.connect(addr);

        let sock_state = self.sock_state.read().unwrap();
        if *sock_state != NfvSocketState::BARE {
            drop(sock_state);
            if let Err(err) = self.hs_sock.unwrap().connect(addr) {
                println!("connect Err: {:?}", err);
                let mut sock_state = self.sock_state.write().unwrap();
                *sock_state = NfvSocketState::CONNECTED;
                return Err(err);
            }
            self.client_tls_handshake();
        }

        ret    
    }

    fn client_tls_handshake(&self) -> Result<()> {
        let mut client_hs = client::hs::ClientHsRmAt::new();
        let sflag = SendFlags::from_bits(0).unwrap();
        let client_hello = client_hs.start_handshake();

        if let Err(err) = self.hs_sock.unwrap().sendto(&client_hello, sflag, &None) {
            println!("client handshake send fail: {:?}", err);
            // std::thread::park_timeout(std::time::Duration::from_secs(0));
            return Err(err);
        }
        // println!("client hello send");
        let mut sock_state = self.sock_state.write().unwrap();
        *sock_state = NfvSocketState::CHELLOSEND;

        if let Err(err) = client_hs.recv_serverhello_and_parse(&self.hs_sock.unwrap()) {
            // if err.errno() == EINVAL {
            //     *sock_state = NfvSocketState::BARE;
            // }
            // println!("serverhello parse fail");
            return Err(err);
        }

        let client_nego_key = client_hs.get_nego_key();
        self.aes_cipher.write().unwrap().set_key(&client_nego_key.to_bytes_be());
        *sock_state = NfvSocketState::HANDSHAKED;
        println!("\x1b[32mhandshake success\x1b[0m");

        Ok(())
    }

    fn recv_server_hello_again(&self) -> Result<()> {
        let mut client_hs = client::hs::ClientHsRmAt::new();
        if let Err(err) = client_hs.recv_serverhello_and_parse(&self.hs_sock.unwrap()) {
            println!("recv serverhello fail agian, set the socket to BARE");
            *self.sock_state.write().unwrap() = NfvSocketState::BARE;
            // println!("got write lock");
            return Err(errno!(EINVAL, "handshake failed"));
            // std::thread::park_timeout(std::time::Duration::from_millis(1));
        }

        let client_nego_key = client_hs.get_nego_key();
        self.aes_cipher.write().unwrap().set_key(&client_nego_key.to_bytes_be());
        *self.sock_state.write().unwrap() = NfvSocketState::HANDSHAKED;
        println!("\x1b[32mhandshake success\x1b[0m");
        
        Ok(())
    }

    pub fn check_handshake_before_comm(&self) -> Result<()> {
        let sock_state = self.sock_state.read().unwrap();
        match *sock_state {
            NfvSocketState::CONNECTED => {
                drop(sock_state);
                // non-block connect where client_tls_handshake not happened
                if let Err(err) = self.client_tls_handshake() {
                    self.recv_server_hello_again()
                }else {
                    Ok(())
                }
            },
            NfvSocketState::CHELLOSEND => {
                drop(sock_state);
                // already send clienthello during connect
                self.recv_server_hello_again()
            },
            NfvSocketState::HANDSHAKED => {
                Ok(())
            },
            _ => Err(errno!(EINVAL, "bare socket")),
        }
    }

    pub fn sendto(
        &self,
        buf: &[u8],
        flags: SendFlags,
        addr_option: &Option<SockAddr>,
    ) -> Result<usize> {
        // kssp mode on
        if self.pub_key_hash_tag != 0 {
            // there's already a connection
            println!("call sendto");
            if let None = addr_option {
                if let Err(err) = self.check_handshake_before_comm() {
                    return self.host_sc.sendto(buf, flags, &None);
                }
                let msg_len = buf.len();
                let enc_msg = self.aes_cipher.read().unwrap().encrypt_mark_len(buf, msg_len);
                // println!("sendto: {}", base64::encode(&enc_msg));
                match self.host_sc.sendto(&enc_msg, flags, &None) {
                    Ok(x) => Ok(msg_len),
                    Err(err) => Err(err),
                }
            }
            // UDP sendto
            else {
                println!("\x1b[33m[Warning:] plaintext UDP sendto {:?}\x1b[0m", addr_option.unwrap());
                self.host_sc.sendto(buf, flags, addr_option)
            }
        }
        // kssp mode off
        else {
            self.host_sc.sendto(buf, flags, addr_option)
        }
    }

    // recv a whole encrypted msg to aes_msg_buf
    pub fn recv_msg_to_amb(&self, flags: RecvFlags, expect_volumn: usize) -> Result<usize> {
        let mut amb = self.aes_msg_buf.write().unwrap();
        if amb.len() >= expect_volumn {
            return Err(errno!(ENOMEM, "already enough data in amb"));
        }

        let mut len_buf = [0u8; LENGH_WIDTH];
        let peek_flag = match amb.len() {
            // if there's no data in amb, the flag should adapt to app-flags
            0 => (flags | RecvFlags::MSG_PEEK),
            // if there's already data in amb, recvbuf may empty, add DONWAIT to avoid block
            _ => (flags | RecvFlags::MSG_PEEK | RecvFlags::MSG_DONTWAIT),
        };
        match self.host_sc.recvfrom(&mut len_buf, peek_flag) {
            Ok((x, addr_option)) => {
                // plaintext UDP msg
                if let Some(addr) = addr_option {
                    return Err(errno!(ENOKEY, "plaintext UDP msg"));
                }
            },
            Err(err) => {
                return Err(err);
            },
        };

        // println!("peek len buf: {}", base64::encode(len_buf));
        let rflag = RecvFlags::MSG_WAITALL;
        self.host_sc.recvfrom(&mut len_buf, rflag);
        let msg_len = usize::from_be_bytes(len_buf);
        // println!("parse len: {}", msg_len);
        if msg_len == 0 {
            // peer close the socket
            return Ok(0);
        }
        let mut data_buf = vec![0u8; msg_len];
        // println!("len buf: {}", base64::encode(len_buf));
        self.host_sc.recvfrom(&mut data_buf, rflag);
        // println!("recvfrom: {}", base64::encode(&data_buf));
        let mut dec_msg = self.aes_cipher.read().unwrap().decrypt(&mut data_buf);
        dec_msg.resize(msg_len, 0u8);
        amb.append(&mut dec_msg);

        Ok(msg_len)
    }

    pub fn fetch_msg_from_amb(&self, des: &mut [u8], flags: RecvFlags) -> Result<usize> {
        let expect_volumn = des.len();
        while match self.recv_msg_to_amb(flags, expect_volumn) {
            Ok(x) => {
                match x {
                    // peer close the socket
                    0 => false,
                    _ => true,
                }
            },
            Err(err) => {
                if self.aes_msg_buf.read().unwrap().len() == 0 {
                    return Err(err);
                }
                false
            }
        }{;}

        let mut amb = self.aes_msg_buf.write().unwrap();
        let amb_len = amb.len();
        if amb_len <= expect_volumn {
            for i in 0..amb_len{
                des[i] = amb[i];
            }
            amb.resize(0, 0u8);
            Ok(amb_len)
        }
        else{
            for i in 0..expect_volumn{
                des[i] = amb[i];
            }
            *amb = amb[expect_volumn..amb_len].to_vec();
            Ok(expect_volumn)
        }
    }

    pub fn recvfrom(&self, buf: &mut [u8], flags: RecvFlags) -> Result<(usize, Option<SockAddr>)> {
        // kssp mode on
        if self.pub_key_hash_tag != 0 {
            println!("call recvfrom");
            if let Err(err) = self.check_handshake_before_comm() {
                return self.host_sc.recvfrom(buf, flags);
            }

            if let Err(err) = self.recv_msg_to_amb(flags, buf.len()) {
                if err.errno() == ENOKEY{
                    println!("\x1b[33m[Warning:] plaintext UDP recvfrom[0m");
                    return self.host_sc.recvfrom(buf, flags);
                }
            }
            match self.fetch_msg_from_amb(buf, flags) {
                Ok(len) => Ok((len, None)),
                Err(err) => Err(err),
            }
            // let mut enc_msg = vec![0u8; buf.len()];
            // let ret = self.host_sc.recvfrom(&mut enc_msg, flags);

            // match ret {
            //     Ok((msg_len, addr_option)) => {
            //         // there's already a connection
            //         if let None = addr_option {
            //             let aes_cipher = self.aes_cipher.read().unwrap();
            //             let enc_msg = aes_cipher.decrypt_to(buf, &enc_msg[..msg_len]);
            //             drop(aes_cipher);
            //         }
            //         // UDP recvfrom
            //         // one can only know whether it is a TCP/UDP after parsing the result of the hostsocket.recvfrom()
            //         // but the data can not be writen into buf directly, in case that aes_cipher is not ready.
            //         // As a backward, when it is UDP, the data need to be transfered from enc_msg to buf
            //         else {
            //             println!("\x1b[33m[Warning:] plaintext UDP recvfrom {:?}\x1b[0m", addr_option.unwrap());
            //             for i in 0..msg_len {
            //                 buf[i] = enc_msg[i];
            //             }
            //         }
            //         ret
            //     },
            //     Err(err) => Err(err),
            // }
        }
        // kssp mode off
        else{
            self.host_sc.recvfrom(buf, flags)
        }
    }

    pub fn raw_host_fd(&self) -> FileDesc {
        self.host_sc.raw_host_fd()
    }

    pub fn shutdown(&self, how: HowToShut) -> Result<()> {
        // println!("call nfv shutdown");
        //self.elp_service.stop();
        self.host_sc.shutdown(how)
    }
}

pub trait NfvSocketType {
    fn as_host_socket(&self) -> Result<&NfvSocket>;
}

use backtrace::Backtrace;
impl NfvSocketType for FileRef {
    fn as_host_socket(&self) -> Result<&NfvSocket> {
        self.as_any()
            .downcast_ref::<NfvSocket>()
            .ok_or_else(|| errno!(EBADF, "not a host socket"))
    }
}