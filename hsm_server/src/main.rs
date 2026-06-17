use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use bincode;
use rcgen::{KeyPair, SigningKey};

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

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

fn handle_client(mut stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    println!("Driver Connection established!");

    loop {
        let mut len_bytes = [0u8; 4];
        if stream.read_exact(&mut len_bytes).is_err() {
            break;
        }
        let req_len = u32::from_be_bytes(len_bytes) as usize;

        let mut req_bytes = vec![0u8; req_len];
        stream.read_exact(&mut req_bytes)?;

        let request: HsmRequest = bincode::deserialize(&req_bytes)?;
        println!("Request from Client: {:?}", request);

        let response = match request {
            HsmRequest::OpenSession => {
                let new_id = SESSION_COUNTER.fetch_add(1, Ordering::SeqCst);
                HsmResponse::SessionOpened { session_id: new_id }
            }
            HsmRequest::Sign { session_id, data } => {
                println!("Signing Data for Session {}", session_id);

                //TODO Load key from HSM
                let pem_string = "-----BEGIN PRIVATE KEY-----\n\
                      MC4CAQAwBQYDK2VwBCIEINTp9M7v7K62bUvpx6Hh7vKclBv7v0jXlNmZ4X9v7v9A\n\
                      -----END PRIVATE KEY-----";

                let key_pair = rcgen::KeyPair::from_pem(pem_string).unwrap();
                let signature_bytes = key_pair.sign(&data).unwrap();

                // Hier wird die Response nur für den Match-Block zurückgegeben,
                // NICHT für die ganze Funktion!
                HsmResponse::SignResult { signature: signature_bytes }
            }
            HsmRequest::OpenSession => {
                HsmResponse::SessionOpened { session_id: 1 }
            }
        };


        let encoded_res = bincode::serialize(&response)?;
        let res_len = encoded_res.len() as u32;
        stream.write_all(&res_len.to_be_bytes())?;
        stream.write_all(&encoded_res)?;
        stream.flush()?;
    }

println!("Driver Connection closed.");
Ok(())
}

fn main() {
    let listener = TcpListener::bind("127.0.0.1:8888").unwrap();
    println!("HSM Emulator Server running on 127.0.0.1:8888");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(e) = handle_client(stream) {
                    eprintln!("Error on Client: {}", e);
                }
            }
            Err(e) => eprintln!("Connection Error: {}", e),
        }
    }
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

