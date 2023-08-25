//this file is edit by kxc
use super::*;
use std::any::Any;
use fs::{FsView, FileMode, AccessMode, CreationFlags, StatusFlags, INodeFile, AsINodeFile};
use self::local_proxy::{EncryptLocalProxy, RunningELP, EncryptMsg};
use tls::comm::aes_comm::Aes128CtrCipher;
use std::sync::{SgxMutex as Mutex, SgxMutexGuard as MutexGuard};

// please modify these two variable simutaneously for accurate err msg display
const MAX_RETRY: usize = 10;
const HANDSHAKE_FAIL_ERR: &str = "handshake failed after 10 times retry";
// please modify these two variable simutaneously

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
pub struct NfvSocket {
    // pub nfv_fd: Arc<dyn File>,
    pub host_sc: HostSocket,
    pub aes_cipher: SgxMutex<Aes128CtrCipher>,
    pub pub_key_hash_tag: usize,       // 0 means did not registed yet.
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

        let hs = HostSocket::new(domain, socket_type, file_flags, protocol)?;
        let mut raw_aes_cipher = Aes128CtrCipher::empty_new();
        let aes_cipher =  SgxMutex::new(raw_aes_cipher);
        //let elp_service = EncryptLocalProxy::new(fd.clone()).start();

        Ok(Self {
            // nfv_fd: fd, 
            host_sc: hs,
            aes_cipher,
            pub_key_hash_tag,
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
        let aes_cipher = SgxMutex::new(raw_aes_cipher);

        Self {
            // nfv_fd: fd, 
            host_sc,
            aes_cipher,
            pub_key_hash_tag,
            //elp_service,
        }
    }

    fn from_hsc_cipher(host_sc: HostSocket, cipher:Aes128CtrCipher) -> NfvSocket {
        let pub_key_hash_tag = tls::comm::ca_manager::get_echash_fromfile("/host/hash_tag");

        Self {
            host_sc,
            aes_cipher: SgxMutex::new(cipher),
            pub_key_hash_tag, 
        }
    }

    pub fn bind(&self, addr: &SockAddr) -> Result<()> {
        self.host_sc.bind(addr)
    }

    pub fn listen(&self, backlog: i32) -> Result<()> {
        self.host_sc.listen(backlog)
    }

    pub fn accept(&self, flags: FileFlags) -> Result<(NfvSocket, Option<SockAddr>)> {
        let (host_sc, addr_option) = self.host_sc.accept(flags).unwrap();
        // {
        //     Ok((host_sc, addr_option)) => {
        //         Ok((NfvSocket::from_host_sc(host_sc), addr_option))
        //     },
        //     Err(error) => panic!("socket accept failed {:?}", &error),
        // };

        if self.pub_key_hash_tag == 0 {
            return Ok((NfvSocket::from_host_sc(host_sc), addr_option));
        }

        match self.server_tls_handshake(&host_sc) {
            Ok(cipher) => {
                Ok((NfvSocket::from_hsc_cipher(host_sc, cipher), addr_option))
            },
            Err(err) => {
                println!("\x1b[33m[Warning:] {}\x1b[0m", err);
                Ok((NfvSocket::from_host_sc(host_sc), addr_option))
            },
        }
    }

    fn server_tls_handshake(&self, host_sc: &HostSocket) -> Result<Aes128CtrCipher> {
        let mut retry = 0;

        let rflag = RecvFlags::from_bits(0).unwrap();
        let mut client_hello = [0u8; 512];

        let mut msg_len = 0;
        while retry < MAX_RETRY {
            match host_sc.recvfrom(&mut client_hello, rflag) {
                Ok((x, y)) => {msg_len = x; break;},
                _ => 0,
            };
            retry += 1;
        }

        if msg_len != 0 {
            // println!("server_recv_msg_len: {}", msg_len);

            let sflag = SendFlags::from_bits(0).unwrap();
            let mut server_hs = server::hs::ServerHsRmAt::new();

            let client_hello = &client_hello[0..msg_len];
            // println!("recv msg_len: {}", msg_len);
            server_hs.recv_clienthello_and_decrypt(client_hello);

            let server_hello = server_hs.reply_to_client();

            retry = 0;
            while retry < MAX_RETRY {
                if let Ok(len) = host_sc.send(&server_hello, sflag) {
                    let server_nego_key = server_hs.get_nego_key();

                    // println!("nego_key: {}", server_nego_key);

                    println!("\x1b[32mhandshake success\x1b[0m");
                    return Ok(Aes128CtrCipher::new(&server_nego_key.to_bytes_be()).unwrap());
                }
                retry += 1;
            }
        }

        Err(errno!(EINVAL, HANDSHAKE_FAIL_ERR))
    }

    pub fn connect(&self, addr: &Option<SockAddr>) -> Result<()> {
        // tls::test_client::safe_regist();
        let ret = self.host_sc.connect(addr);

        if self.pub_key_hash_tag != 0{
            self.client_tls_handshake();
        }

        ret
    }

    fn client_tls_handshake(&self) -> Result<()> {
        let mut retry = 0;

        let sflag = SendFlags::from_bits(0).unwrap();
        let rflag = RecvFlags::from_bits(0).unwrap();
        let mut client_hs = client::hs::ClientHsRmAt::new();
    
        let client_hello = client_hs.start_handshake();
        while retry < MAX_RETRY {
            if let Ok(msg_len) = self.host_sc.sendto(&client_hello, sflag, &None) {
                break;
            }
            retry += 1;
        }
        // println!("send {} bytes", msg_len);
    
        let mut server_hello = [0u8; 512];

        retry = 0;
        let mut msg_len = 0;
        while retry < MAX_RETRY {
            match self.host_sc.recvfrom(&mut server_hello, rflag) {
                Ok((x, y)) => {msg_len = x; break;},
                _ => 0,
            };
            retry += 1;
        }

        if msg_len != 0 {
            let server_hello = &server_hello[0..msg_len];
            // println!("recv msg_len: {}", msg_len);
            client_hs.recv_serverhello_and_decrypt(server_hello);
        
            let client_nego_key = client_hs.get_nego_key();
            
            // println!("nego_key: {}", client_nego_key);

            self.aes_cipher.lock().unwrap().set_key(&client_nego_key.to_bytes_be());
            println!("\x1b[32mhandshake success\x1b[0m");
            return Ok(());
        }

        Err(errno!(EINVAL, HANDSHAKE_FAIL_ERR))
    }

    pub fn sendto(
        &self,
        buf: &[u8],
        flags: SendFlags,
        addr_option: &Option<SockAddr>,
    ) -> Result<usize> {
        // let aes_cipher = self.aes_cipher.lock().unwrap();

        // // aes_cipher.show_key();

        // if aes_cipher.key_valid() {
        //     let enc_msg = aes_cipher.encrypt(buf);
        //     // print!("origin: ");
        //     // echo_buf!(buf);
        //     // print!("sendto: ");
        //     // echo_buf!(&enc_msg);
        //     self.host_sc.sendto(&enc_msg, flags, addr_option)
        // }
        // else {
        //     self.host_sc.sendto(buf, flags, addr_option)
        // }

        self.host_sc.sendto(buf, flags, addr_option)
    }

    pub fn recvfrom(&self, buf: &mut [u8], flags: RecvFlags) -> Result<(usize, Option<SockAddr>)> {
        // let aes_cipher = self.aes_cipher.lock().unwrap();

        // // aes_cipher.show_key();

        // if aes_cipher.key_valid() {
        //     let mut rec_buf = vec![0u8; buf.len()];
        //     let (len, addr_option) = match self.host_sc.recvfrom(&mut rec_buf, flags) {
        //         Ok(ret) => ret,
        //         Err(err) => {
        //             return Err(err);
        //             (0, None)
        //         }
        //     };

        //     let dec_msg = aes_cipher.decrypt_to(buf, &rec_buf[0..len]);
        //     // print!("recvfr: ");
        //     // echo_buf!(&rec_buf);
        //     // print!("decmsg: ");
        //     // echo_buf!(&buf[0..len]);
        //     Ok((len, addr_option))
        // }
        // else {
        //     self.host_sc.recvfrom(buf, flags)
        // }

        self.host_sc.recvfrom(buf, flags)
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