
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use std::fs;
use mlua::{Error as LuaError}; 
use config::get_or_create_sub_module;
use mlua::Lua;
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;


#[derive(Clone, Debug)]
pub struct AesParams {
    pub key: AesKey,
    pub iv: [u8; 16],
}


#[derive(Clone, Debug)]
pub enum AesKey {
    Aes128([u8; 16]),
    Aes256([u8; 32]),
}

impl AesKey {
    // Associated function to create AesKey from raw bytes 
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        match bytes.len() {
            16 => {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(bytes);
                Ok(AesKey::Aes128(arr))
            }
            32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(bytes);
                Ok(AesKey::Aes256(arr))
            }
            _ => Err("Key length must be 16 or 32 bytes"),
        }
    }
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let bytes = fs::read(path)?;
        AesKey::from_bytes(&bytes).map_err(|e| e.into())
    }
}

fn aes_encrypt_cbc(plaintext: &str,  params: AesParams)->  Result<Vec<u8>, &'static str> {
    let plaintext_bytes = plaintext.as_bytes();
    // Buffer must be big enough for padded plaintext.
    // For PKCS7 padding, max size = plaintext length + block size
    let block_size = 16;
    let mut buf = vec![0u8; plaintext.len() + block_size];

    // Copy plaintext to buffer
    buf[..plaintext.len()].copy_from_slice(plaintext_bytes);

    // handle 128 and 256 keys with the given IV
    match params.key {
        AesKey::Aes128(k) => {
        let cipher = Aes128CbcEnc::new((&k).into(), (&params.iv).into());
           match cipher.encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext_bytes.len()) {
           Ok(ct) => Ok(ct.to_vec()),
           Err(_) => Err("Encryption failed or padding error"),
         }
        
        }
        AesKey::Aes256(k) => {
        let cipher = Aes256CbcEnc::new((&k).into(), (&params.iv).into());
           match cipher.encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext_bytes.len()) {
           Ok(ct) => Ok(ct.to_vec()),
           Err(_) => Err("Encryption failed or padding error"),
        }
    }
   }
}

fn aes_decrypt_cbc(ciphertext: &[u8], params: AesParams) -> Result<Vec<u8>, &'static str> {
    let mut buf = ciphertext.to_vec();

    match params.key {
        AesKey::Aes128(k) => {
            let cipher = Aes128CbcDec::new((&k).into(), (&params.iv).into());
            cipher.decrypt_padded_mut::<Pkcs7>(&mut buf)
                .map(|pt| pt.to_vec())
                .map_err(|_| "Decryption failed for AES-128")
        }
        AesKey::Aes256(k) => {
            let cipher = Aes256CbcDec::new((&k).into(), (&params.iv).into());
            cipher.decrypt_padded_mut::<Pkcs7>(&mut buf)
                .map(|pt| pt.to_vec())
                .map_err(|_| "Decryption failed for AES-256")
        }
    }
}

pub fn register(lua: &Lua) -> anyhow::Result<()> {
    let crypto = get_or_create_sub_module(lua, "crypto")?;
       crypto.set(
            "aes_encrypt_cbc",
            lua.create_function(|_, (value, enc_key,  iv_param): (String, String,  [u8; 16])| {
            // TODO: aes_key should come either from bytes or from file depending of user. Use keysource later
            // TODO: if len is not 16 bytes just erorr our friendly
               let aes_key = AesKey::from_bytes(enc_key.as_bytes())
                               .map_err(|e| LuaError::external(e.to_string()))?;
                 let  p = AesParams { key: aes_key, iv: iv_param};
                 let result = aes_encrypt_cbc(&value, p)
                     .map_err(|e| LuaError::external(e.to_string()))?;
             Ok(result)
             })?,
    )?;
       crypto.set(
        "aes_decrypt_cbc",
        lua.create_function(|_, (value, enc_key,  iv_param): (String, String,  [u8; 16])| {
            // TODO: aes_key should come either from bytes or from file depending of user. Use keysource later
            // TODO: if len is not 16 bytes just erorr our friendly
               let aes_key = AesKey::from_bytes(enc_key.as_bytes())
                               .map_err(|e| LuaError::external(e.to_string()))?;
                 let  p = AesParams { key: aes_key, iv: iv_param};
                 let result = aes_decrypt_cbc(&value.as_bytes(), p)
                     .map_err(|e| LuaError::external(e.to_string()))?;
             Ok(result)
             })?,
    )?;
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_aes128() {
        let key = AesKey::Aes128([0x11; 16]);
        let iv = [0x22; 16];
        let params = AesParams { key: key.clone(), iv };

        let plaintext = "This is a test message for AES-128";
        let ciphertext = aes_encrypt_cbc(plaintext, params.clone())
            .expect("Encryption failed");
        let decrypted = aes_decrypt_cbc(&ciphertext, params)
            .expect("Decryption failed");

        assert_eq!(decrypted, plaintext.as_bytes());
    }

    #[test]
    fn test_encrypt_decrypt_aes256() {
        let key = AesKey::Aes256([0x33; 32]);
        let iv = [0x44; 16];
        let params = AesParams { key: key.clone(), iv };

        let plaintext = "This is a test message for AES-256 encryption";
        let ciphertext = aes_encrypt_cbc(plaintext, params.clone())
            .expect("Encryption failed");
        let decrypted = aes_decrypt_cbc(&ciphertext, params)
            .expect("Decryption failed");

        assert_eq!(decrypted, plaintext.as_bytes());
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let correct_key = AesKey::Aes128([0x11; 16]);
        let wrong_key = AesKey::Aes128([0x22; 16]);
        let iv = [0x22; 16];
        let correct_params = AesParams { key: correct_key.clone(), iv };
        let wrong_params = AesParams { key: wrong_key, iv };

        let plaintext = "This message won't decrypt correctly with the wrong key";
        let ciphertext = aes_encrypt_cbc(plaintext, correct_params.clone())
            .expect("Encryption failed");

        let result = aes_decrypt_cbc(&ciphertext, wrong_params);
        assert!(result.is_err());
    }
}