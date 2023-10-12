pub mod client;
pub mod server;
pub mod comm;

use client::cypher::ClientCypher;
use comm::{ca_manager, aes_comm, rand_gen, rc4_comm};
use server::cypher::ServerCypher;
// use openssl::symm;

pub fn test_dh_handshake() {
    let mut alice = ClientCypher::new();
    let dh_pub_para = alice.get_dh_pub_para();
    let mut bob = ServerCypher::new(dh_pub_para);

    let a_key = alice.get_dh_pub_key();
    let b_key = bob.get_dh_pub_key();

    println!("pub_key_A: {}", a_key);
    println!("pub_key_B: {}", b_key);

    alice.calc_symmetric_key(b_key);
    bob.calc_symmetric_key(a_key);

    let sym_key_a = alice.get_dh_symmetric_key().unwrap();
    let sym_key_b = bob.get_dh_symmetric_key().unwrap();

    println!("sym_key_A: {}", sym_key_a);
    println!("sym_key_B: {}", sym_key_b);
    assert_eq!(sym_key_a, sym_key_b);
}

pub fn test_dh_rsa_handshake() {
    // ca_manager::generate_rsa_group_file();

    let mut client_hs = client::hs::ClientHs::new();
    let mut server_hs = server::hs::ServerHs::new();

    let client_hello = client_hs.start_handshake();
    server_hs.recv_clienthello_and_decrypt(&client_hello);

    let server_hello = server_hs.reply_to_client();
    client_hs.recv_serverhello_and_decrypt(&server_hello);

    let client_nego_key = client_hs.get_nego_key();
    let server_nego_key = server_hs.get_nego_key();

    println!("client_nego_key:\n{}", client_nego_key);
    println!("server_nego_key:\n{}", server_nego_key);
}

// pub fn test_symm_encrypt(){
//     let raw_data = b"hello, this is a aes256 encrypted communication test";

//     let cipher = symm::Cipher::aes_128_cbc();
//     let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
//     let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";
    
//     let enc_cipher = symm::Cipher::aes_128_cbc();
//     let enc_text = symm::encrypt(
//         enc_cipher,
//         key,
//         Some(iv),
//         raw_data
//     ).unwrap();
    
//     let ciphertext = symm::decrypt(
//         cipher,
//         key,
//         Some(iv),
//         &enc_text
//     ).unwrap();

//     assert_eq!(
//         raw_data,
//         &ciphertext[..]);
// }

pub fn test_handshake_and_aes256_comm() {
    let mut client_hs = client::hs::ClientHs::new();
    let mut server_hs = server::hs::ServerHs::new();

    let client_hello = client_hs.start_handshake();
    println!("client_hello_len: {}", client_hello.len());
    server_hs.recv_clienthello_and_decrypt(&client_hello);

    let server_hello = server_hs.reply_to_client();
    println!("server_hello_len: {}", server_hello.len());
    client_hs.recv_serverhello_and_decrypt(&server_hello);

    let client_nego_key = client_hs.get_nego_key().to_bytes_be();
    let server_nego_key = server_hs.get_nego_key().to_bytes_be();

    let msg = b"hello, this is a aes256 encrypted communication test";

    // let enc_key = &client_nego_key[0..32];
    // let enc_iv = &client_nego_key[32..48];
    // let enc_cipher = symm::Cipher::aes_256_ctr();
    // let ciphertext = symm::encrypt(
    //     enc_cipher,
    //     enc_key,
    //     Some(enc_iv),
    //     msg
    // ).unwrap();
    
    // let dec_key = &server_nego_key[0..32];
    // let dec_iv = &server_nego_key[32..48];
    // let dec_cipher = symm::Cipher::aes_256_ctr();
    // let dec_text = symm::decrypt(
    //     dec_cipher,
    //     dec_key,
    //     Some(dec_iv),
    //     &ciphertext
    // ).unwrap();

    let enc_cipher = aes_comm::Aes128ctrcipher::new(&client_nego_key).unwrap();
    let enc_text = enc_cipher.encrypt(msg);

    let dec_cipher = aes_comm::Aes128ctrcipher::new(&server_nego_key).unwrap();
    let dec_text = dec_cipher.decrypt(&enc_text);

    println!("{}", std::str::from_utf8(&dec_text).unwrap());
}

pub fn test_mutbuf_ptr() {
    let mut buf1 = vec![0; 10];
    let mut buf2 = vec![1,2,3,4,5];

    let mut raw_ptr = &mut buf1;
    let mut ptr1 = &mut raw_ptr[1..3];

    for i in 0..2 {
        ptr1[i] = buf2[i];
    }
    for i in 0..10 {
        print!("{} ", buf1[i]);
    }
    println!("");
}

pub fn test_combine_aes_decrypt() {
    let init_bytes = rand_gen::Generator::gen_biguint(256);
    let aes_cipher = aes_comm::Aes128ctrcipher::new(&init_bytes.to_bytes_be()).unwrap();
    let mut msg1 = "123".as_bytes().to_vec();
    msg1.resize(16, 0u8);
    let mut msg2 = "abcde".as_bytes().to_vec();
    msg2.resize(16, 0u8);
    let mut msg3 = "o".as_bytes().to_vec();
    msg3.resize(16, 0u8);

    let mut enc_msg1 = aes_cipher.encrypt(&msg1);
    let mut enc_msg2 = aes_cipher.encrypt(&msg2);
    let mut enc_msg3 = aes_cipher.encrypt(&msg3);

    let combine_msg = {
        msg1.append(&mut msg2);
        msg1.append(&mut msg3);
        msg1
    };

    let combine_enc_msg = {
        enc_msg1.append(&mut enc_msg2);
        enc_msg1.append(&mut enc_msg3);
        enc_msg1
    };

    let dec_combine_enc_msg = aes_cipher.decrypt(&combine_enc_msg);

    println!("combine_msg: {:?}", combine_msg);
    println!("dec_combine_enc_msg: {:?}", dec_combine_enc_msg);
}

pub fn test_split_off() {
    let mut buf = vec![1,2,3];
    let buf_ref = &buf;
    let new_buf = &buf_ref[3..];
    println!("split_buf_len: {}", new_buf.len());
}

pub fn test_rc4_encrypt() {
    let init_bytes = rand_gen::Generator::gen_biguint(2048);
    let mut rc4_cipher1 = rc4_comm::RC4Cipher::new(&init_bytes.to_bytes_be());
    let mut rc4_cipher2 = rc4_comm::RC4Cipher::new(&init_bytes.to_bytes_be());

    let msg = "hello this is a test".as_bytes().to_vec();
    let msg2 = "hello this is a test".as_bytes().to_vec();
    let msg3 = "hello this is a test".as_bytes().to_vec();

    let enc_msg = rc4_cipher1.encrypt(&msg);
    let enc_msg2 = rc4_cipher1.encrypt(&msg2);
    let enc_msg3 = rc4_cipher1.encrypt(&msg3);

    let dec_msg = rc4_cipher2.decrypt(&enc_msg);
    let dec_msg = std::str::from_utf8(&dec_msg).unwrap();
    let dec_msg2 = rc4_cipher2.decrypt(&enc_msg2);
    let dec_msg2 = std::str::from_utf8(&dec_msg2).unwrap();
    let dec_msg3 = rc4_cipher2.decrypt(&enc_msg3);
    let dec_msg3 = std::str::from_utf8(&dec_msg3).unwrap();

    println!("dec: {}", dec_msg);
    println!("dec: {}", dec_msg2);
    println!("dec: {}", dec_msg3);
}

fn main() {
    //test_dh_handshake();
    //test_dh_rsa_handshake();
    //test_symm_encrypt();

    //comm::ca_manager::generate_ec_group_file();
    //comm::ca_manager::test_ecdsa_sign_veri();
    
    // test_handshake_and_aes256_comm();

    //aes_comm::test_aes_comm();

    // test_combine_aes_decrypt();
    // test_split_off();
    // test_mutbuf_ptr();
    test_rc4_encrypt();
}