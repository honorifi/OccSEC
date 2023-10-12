use super::*;

#[derive(Debug)]
pub struct RC4Cipher {
    seed: [u8; 256],
    pre_seed: [u8; 256],
    ptr_i: usize,
    ptr_j: usize,
    pre_i: usize,
    pre_j: usize,
    key_valid: bool,
}

impl RC4Cipher {
    pub fn new(init_bytes: &[u8]) -> Self{
        let init_bytes_len = init_bytes.len();

        let mut seed = [0u8; 256];
        let mut tmp = [0u8; 256];
        for i in 0..256 {
            seed[i] = i as u8;
            tmp[i] = init_bytes[i%init_bytes_len];
        }

        let mut j: usize = 0;
        for i in 0..256 {
            j = (j+seed[i] as usize+tmp[i] as usize) % 256;
            let mid = seed[i];
            seed[i] = seed[j];
            seed[j] = mid;
        }

        let pre_seed = seed.clone();
        
        Self{
            seed,
            pre_seed,
            ptr_i: 0,
            ptr_j: 0,
            pre_i: 0,
            pre_j: 0,
            key_valid: true,
        }
    }

    pub fn empty_new() -> Self {
        Self{
            seed: [0u8; 256],
            pre_seed: [0u8; 256],
            ptr_i: 0,
            ptr_j: 0,
            pre_i: 0,
            pre_j: 0,
            key_valid: false,
        }
    }

    pub fn set_key(&mut self, init_bytes: &[u8]) {
        let init_bytes_len = init_bytes.len();

        let mut seed = [0u8; 256];
        let mut tmp = [0u8; 256];
        for i in 0..256 {
            seed[i] = i as u8;
            tmp[i] = init_bytes[i%init_bytes_len];
        }

        let mut j: usize = 0;
        for i in 0..256 {
            j = (j+seed[i] as usize+tmp[i] as usize) % 256;
            let mid = seed[i];
            seed[i] = seed[j];
            seed[j] = mid;
        }

        self.seed = seed.clone();
        self.pre_seed = seed;
        self.ptr_i = 0;
        self.ptr_j = 0;
        self.pre_i = 0;
        self.pre_j = 0;
        self.key_valid = true;
    }

    pub fn key_valid(&self) -> bool {
        self.key_valid
    }

    pub fn encrypt(&mut self, buf: &[u8]) -> Vec<u8> {
        // backup, look back when send fail
        self.pre_seed = self.seed.clone();
        self.pre_i = self.ptr_i;
        self.pre_j = self.ptr_j;

        let mut i: usize = self.ptr_i;
        let mut j: usize = self.ptr_j;

        let len = buf.len();
        let mut ret = vec![0u8; len];
        for iter in 0..len {
            i = (i+1) % 256;
            let mid = self.seed[i];
            let t = (mid as usize+self.seed[j] as usize) % 256;
            j = (j+mid as usize) % 256;
            self.seed[i] = self.seed[j];
            self.seed[j] = mid;

            ret[iter] = buf[iter] ^ self.seed[t];
        }
        self.ptr_i = i;
        self.ptr_j = j;

        ret
    }

    pub fn decrypt(&mut self, buf: &[u8]) -> Vec<u8> {
        let mut i: usize = self.ptr_i;
        let mut j: usize = self.ptr_j;

        let len = buf.len();
        let mut ret = vec![0u8; len];
        for iter in 0..len {
            i = (i+1) % 256;
            let mid = self.seed[i];
            let t = (mid as usize+self.seed[j] as usize) % 256;
            j = (j+mid as usize) % 256;
            self.seed[i] = self.seed[j];
            self.seed[j] = mid;

            ret[iter] = buf[iter] ^ self.seed[t];
        }
        self.ptr_i = i;
        self.ptr_j = j;

        ret
    }

    pub fn decrypt_to(&mut self, des: &mut [u8], buf: &[u8]) {
        let mut i: usize = self.ptr_i;
        let mut j: usize = self.ptr_j;

        let len = buf.len();
        for iter in 0..len {
            i = (i+1) % 256;
            let mid = self.seed[i];
            let t = (mid as usize+self.seed[j] as usize) % 256;
            j = (j+mid as usize) % 256;
            self.seed[i] = self.seed[j];
            self.seed[j] = mid;

            des[iter] = buf[iter] ^ self.seed[t];
        }
        self.ptr_i = i;
        self.ptr_j = j;
    }

    pub fn look_back(&mut self) {
        self.seed = self.pre_seed;
        self.ptr_i = self.pre_i;
        self.ptr_j = self.pre_j;
    }
}