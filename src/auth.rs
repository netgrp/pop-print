use std::{
    num::ParseIntError,
    time::{Duration, UNIX_EPOCH},
};

use aws_lc_rs::{
    cipher::{
        AES_256, Algorithm, DecryptingKey, DecryptionContext, EncryptingKey, EncryptionContext,
        UnboundCipherKey,
    },
    digest::{SHA1_FOR_LEGACY_USE_ONLY, digest},
    iv::{FixedLength, IV_LEN_128_BIT},
};
use reqwest::{Client, Method, Url};
use serde::Deserialize;
use thiserror::Error;

const ALGORITHM: &Algorithm = &AES_256;
const LOGIN_TIME: Duration = Duration::from_secs(10 * 60);

pub struct KNetApiCreds {
    pub api_base_url: Url,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Error)]
pub enum LoginError {
    #[error("error doing http request: {0}")]
    HttpRequestError(#[from] reqwest::Error),
    #[error("wrong username or password")]
    InvalidCredentials,
}

#[derive(Deserialize)]
struct UserLookupResult {
    count: usize,
    //next: Option<String>,
    //previous: Option<String>,
    results: Box<[UserLookupEntry]>,
}

#[derive(Deserialize)]
struct UserLookupEntry {
    //url: String,
    //dorm: String,
    //username: String,
    password: String,
    //vlan: String,
}

async fn check_knet_user_creds(
    knet_api_creds: &KNetApiCreds,
    username: &str,
    password: &str,
) -> Result<(), LoginError> {
    let mut url = knet_api_creds
        .api_base_url
        .join("network/user/")
        .expect("user lookup url should be joinable");
    url.query_pairs_mut()
        .append_pair("username", username)
        .finish();
    let client = Client::new();
    let resp = client
        .request(Method::GET, url)
        .basic_auth(&knet_api_creds.username, Some(&knet_api_creds.password))
        .send()
        .await?
        .error_for_status()?;
    let results: UserLookupResult = resp.json().await?;
    if results.count == 1 {
        let password_hash_str = &results.results[0].password;
        let [hash_algorithm, salt, expected]: [&str; 3] = password_hash_str
            .split('$')
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        assert_eq!(hash_algorithm, "sha1");
        let hashed = digest(
            &SHA1_FOR_LEGACY_USE_ONLY,
            format!("{salt}{password}").as_bytes(),
        );
        if hashed.as_ref() != decode_hex(expected).unwrap() {
            Err(LoginError::InvalidCredentials)
        } else {
            Ok(())
        }
    } else {
        Err(LoginError::InvalidCredentials)
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

pub struct Authentication {
    knet_api_creds: KNetApiCreds,
    encrypting_key: EncryptingKey,
    decrypting_key: DecryptingKey,
    initialization_vector: [u8; IV_LEN_128_BIT],
}

#[derive(Debug, Error)]
pub enum KeyConstructionErr {
    #[error("key length does match AES256 key length")]
    InvalidKeyLength,
    #[error("could not construct AES encrypting key")]
    EncryptingKeyError,
    #[error("could not construct AES decrypting key")]
    DecryptingKeyError,
}

impl Authentication {
    pub fn new(
        knet_api_creds: KNetApiCreds,
        key: &[u8],
        initialization_vector: [u8; IV_LEN_128_BIT],
    ) -> Result<Self, KeyConstructionErr> {
        use KeyConstructionErr::*;

        let unbound = UnboundCipherKey::new(ALGORITHM, key).map_err(|_| InvalidKeyLength)?;
        let encrypting_key = EncryptingKey::ctr(unbound).map_err(|_| EncryptingKeyError)?;

        let unbound = UnboundCipherKey::new(ALGORITHM, key).map_err(|_| InvalidKeyLength)?;
        let decrypting_key = DecryptingKey::ctr(unbound).map_err(|_| DecryptingKeyError)?;

        Ok(Authentication {
            knet_api_creds,
            encrypting_key,
            decrypting_key,
            initialization_vector,
        })
    }

    fn decryption_context(&self) -> DecryptionContext {
        DecryptionContext::Iv128(FixedLength::from(self.initialization_vector))
    }

    fn encryption_context(&self) -> EncryptionContext {
        EncryptionContext::Iv128(FixedLength::from(self.initialization_vector))
    }

    pub fn check_login(&self, cookie: &str) -> bool {
        let Ok(mut cookie_contents) = u64::from_str_radix(cookie, 16).map(|w| w.to_le_bytes())
        else {
            return false;
        };
        match self
            .decrypting_key
            .decrypt(&mut cookie_contents, self.decryption_context())
        {
            Ok(_) => {
                let cookie_time =
                    UNIX_EPOCH + Duration::from_secs_f64(f64::from_le_bytes(cookie_contents));
                matches!(cookie_time.elapsed(), Ok(dur) if dur < LOGIN_TIME)
            }
            Err(_) => false,
        }
    }

    pub async fn login(&self, username: &str, password: &str) -> Result<String, LoginError> {
        check_knet_user_creds(&self.knet_api_creds, username, password).await?;
        let time = UNIX_EPOCH
            .elapsed()
            .expect("time should be after epoch")
            .as_secs_f64();
        let mut in_out = time.to_bits().to_le_bytes();
        self.encrypting_key
            .less_safe_encrypt(&mut in_out, self.encryption_context())
            .unwrap();
        Ok(format!("{:x}", u64::from_le_bytes(in_out)))
    }
}
