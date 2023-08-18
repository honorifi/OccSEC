mod stls;
use stls::*;

fn main() {
    // comm::ca_manager::generate_ec_group_file();

    let args: Vec<String> = std::env::args().collect();
    let opt = args[1].parse::<usize>().unwrap();

    match opt {
        0 => {  //run server, without encryption
            let service = server::conn_handle::CertMG::new("127.0.0.1:10011");
            service.start();
        }

        1 => {  //run server, with encryption
            let service = server::conn_handle::CertMG::new("127.0.0.1:10011");
            service.safe_start();
        }

        2 => {  //run test client, without encryption
            let repeat = args[2].parse::<usize>().unwrap();
            test_client::msg_sender(repeat);
        }

        3 => {  //run test client, with encryption
            let repeat = args[2].parse::<usize>().unwrap();
            test_client::safe_msg_sender(repeat);
        }

        4 => {  //run test client, auto msg, with encryption
            let repeat = args[2].parse::<usize>().unwrap();
            test_client::safe_msg_static_sender(repeat);
        }

        5 => {  //run test client, register an pub key with encryption
            test_client::safe_regist();
        }

        6 => {  //run test client, unregist an pub key with encryption
            let hash_key = args[2].parse::<usize>().unwrap();
            test_client::safe_unregist(hash_key);
        }

        7 => {  //run test_generate_ecdsa_string_and_parse
            comm::ca_manager::test_generate_ecdsa_string_and_parse();
        }

        8 => {  // generate new ec_key group
            comm::ca_manager::generate_ec_group_file();
        }

        9 => {
            comm::ca_manager::show_client_regist_priv_key();
        }

        _ => {
            println!("unrecognized instruction");
        }
    }
}
