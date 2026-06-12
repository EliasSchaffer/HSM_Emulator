
use serde::{Deserialize, Serialize};

fn main() {}

#[derive(Serialize, Deserialize, Debug)]
pub enum HsmRequest {
    OpenSession,
    Sign { session_id: u64, data: Vec<u8> },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum HsmResponse {
    SessionOpened { session_id: u64 },
    SignResult { signature: Vec<u8> },
    Error(String),
}

async fn health_check() -> &'static str {
    "OK"
}

// async fn create_signature(
//     Json(CreateSignatureRequest { file_hash, private_key_token }): Json<CreateSignatureRequest>,
// ) -> Result<String, String> {
//
//     println!("Received request with file_hash: {:?}", file_hash);
//     println!("Received request with private_key_token: {:?}", private_key_token);
//     println!("Getting private key from HSM...");
//     let key_pair = KeyPair::from_pem("-----BEGIN PRIVATE KEY-----
// MC4CAQAwBQYDK2VwBCIEINTp9M7v7K62bUvpx6Hh7vKclBv7v0jXlNmZ4X9v7v9A
// -----END PRIVATE KEY-----")
//         .map_err(|e| format!("Error loading the key {}", e))?;
//
//     println!("Signing file...");
//     let signature_bytes = key_pair.sign(file_hash.as_slice())
//         .map_err(|e| format!("Error while signing {}", e))?;
//
//     println!("Signature created successfully!");
//     let signature_hex = hex::encode(signature_bytes);
//
//     println!("Signature hex: {}", signature_hex);
//     Ok(signature_hex)
// }

