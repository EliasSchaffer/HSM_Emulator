use std::collections::HashSet;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use std::error::Error;
use bincode;
use rcgen::{KeyPair, SigningKey};
use sqlx::{sqlite::SqlitePoolOptions, Row, SqlitePool};
use ring::pbkdf2;
use std::num::NonZeroU32;
use ring::aead::{Aad, Nonce, NonceSequence, SealingKey, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use ring::aead::{self, BoundKey, OpeningKey};

#[derive(Serialize, Deserialize, Debug)]
pub enum HsmRequest {
    OpenSession,
    CloseSession { session_id: u64 },
    Sign { session_id: u64, key_id: String, data: Vec<u8> },
    GenerateKey { key_id: String, key_type: String },
    Error(String),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum HsmResponse {
    SessionOpened { session_id: u64 },
    SessionClosed,
    SignResult { signature: Vec<u8> },
    KeyGenerated,
    Error(String),
}

struct MasterKey {
    bytes: [u8; 32],
}

struct SimpleNonceSequence {
    nonce: [u8; 12],
}

impl NonceSequence for SimpleNonceSequence {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        Ok(Nonce::assume_unique_for_key(self.nonce))
    }
}



static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);
static ACTIVE_SESSIONS: LazyLock<Mutex<HashSet<u64>>> = LazyLock::new(|| Mutex::new(HashSet::new()));
async fn handle_client(mut stream: TcpStream, d_pool: SqlitePool, master_key: [u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
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
                ACTIVE_SESSIONS.lock().unwrap().insert(new_id);
                HsmResponse::SessionOpened { session_id: new_id }
            }
            HsmRequest::CloseSession { session_id } => {
                let existed = ACTIVE_SESSIONS.lock().unwrap().remove(&session_id);
                if existed {
                    HsmResponse::SessionClosed
                } else {
                    HsmResponse::Error("Session not found!".to_string())
                }
            }
            HsmRequest::Sign { session_id, key_id, data } => {
                println!("Signing Data for Session {}", session_id);

                let encrypted_blob = load_key_from_db(&d_pool, &key_id).await?;

                if encrypted_blob.is_none() {
                    HsmResponse::Error("Key not found!".to_string())
                } else {
                    let decrypted_key = decrypt_blob(&master_key, &encrypted_blob.unwrap()).unwrap();
                    println!("Decrypted Data: {:?}", decrypted_key);

                    let key_pair: KeyPair = (&decrypted_key[..]).try_into().unwrap();
                    let mut signature_bytes = key_pair.sign(&data);
                    HsmResponse::SignResult { signature: signature_bytes.unwrap() }
                }
            }
            HsmRequest::GenerateKey { key_id, key_type } => {
                match generate_key(&master_key, key_id, key_type, &d_pool).await {
                    Ok(_) => HsmResponse::KeyGenerated,
                    Err(e) => HsmResponse::Error(e.to_string()),
                }
            }
            HsmRequest::Error(e) => HsmResponse::Error(format!("Echo Error: {}", e)),
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
    println!("=== HSM Emulator ===");
    println!("Starting HSM Emulator Server...");
    println!("Please enter the master password to initialize the HSM emulator:");
    std::io::Write::flush(&mut std::io::stdout()).unwrap();

    let password = rpassword::read_password().unwrap();

    if password.trim().is_empty() {
        eprintln!("Password cannot be empty!");
        std::process::exit(1);
    }

    let master_key = derive_master_key(&password);
    println!("✔ Master Key Successfully derived!");

    let rt = tokio::runtime::Runtime::new().unwrap();
    let db_pool = rt.block_on(setup_database()).unwrap();

    let listener = TcpListener::bind("127.0.0.1:8888").unwrap();
    // Hol dir ein Handle auf die bereits erstellte Tokio-Runtime
    let handle = rt.handle();

    println!("HSM Emulator Server running on 127.0.0.1:8888");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let pool_cloned = db_pool.clone();
                let key_copy = master_key; // Kopiert das Array [u8; 32] für diesen Client

                // Spawne den asynchronen Task auf der Runtime
                handle.spawn(async move {
                    if let Err(e) = handle_client(stream, pool_cloned, key_copy).await {
                        eprintln!("Error on Client: {}", e);
                    }
                });
            }
            Err(e) => eprintln!("Connection Error: {}", e),
        }
    }
}

fn derive_master_key(password: &str) -> [u8; 32] {
    let mut master_key = [0u8; 32];

    let salt = b"HSM_EMULATOR_STABLE_SALT_12345";
    let iterations = NonZeroU32::new(100_000).unwrap();

    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        password.as_bytes(),
        &mut master_key,
    );
    master_key
}

async fn setup_database() -> Result<SqlitePool, Box<dyn Error>> {
    let connection_string = "sqlite://emulator.db";

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(connection_string)
        .await?;

    sqlx::query(
        r#"
            CREATE TABLE IF NOT EXISTS hsm_keys (
            key_id TEXT PRIMARY KEY,
            key_type TEXT NOT NULL,
            encrypted_blob BLOB NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        "#
    )
    .execute(&pool)
    .await?;

    println!("Database initialized");
    Ok(pool)
}

async fn save_key_to_db(pool: &SqlitePool, key_id: &str, key_type: &str, encrypted_blob: &[u8]) -> Result<(), Box<dyn Error>> {
    sqlx::query("INSERT INTO hsm_keys (key_id, key_type, encrypted_blob) VALUES (?, ?, ?)")
        .bind(key_id)
        .bind(key_type)
        .bind(encrypted_blob)
        .execute(pool)
        .await?;

    Ok(())
}

async fn load_key_from_db(pool: &SqlitePool, key_id: &str) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    let row = sqlx::query(
        "SELECT encrypted_blob FROM hsm_keys WHERE key_id = ?"
    )
        .bind(key_id)
        .fetch_optional(pool)
        .await?;

    match row {
        Some(r) => {
            let blob: Vec<u8> = r.get("encrypted_blob");
            Ok(Some(blob))
        }
        None => {
            Ok(None)
        }
    }
}

pub fn encrypt_blob(master_key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let rand = SystemRandom::new();

    let mut nonce_bytes = [0u8; 12];
    rand.fill(&mut nonce_bytes)
        .map_err(|_| "Fehler beim Generieren der Nonce")?;

    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, master_key)
        .map_err(|_| "Ungültiger Master-Schlüssel für AES-GCM")?;

    let nonce_sequence = SimpleNonceSequence { nonce: nonce_bytes };
    let mut sealing_key = SealingKey::new(unbound_key, nonce_sequence);

    let mut in_out = plaintext.to_vec();

    sealing_key.seal_in_place_append_tag(Aad::empty(), &mut in_out)
        .map_err(|_| "Verschlüsselung fehlgeschlagen")?;

    let mut encrypted_packet = nonce_bytes.to_vec();
    encrypted_packet.extend_from_slice(&in_out);
    Ok(encrypted_packet)
}

pub fn decrypt_blob(master_key: &[u8; 32], encrypted_packet: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if encrypted_packet.len() < 12 {
        return Err("Packet too short".into());
    }

    let (nonce_bytes, ciphertext) = encrypted_packet.split_at(12);
    let mut in_out = ciphertext.to_vec();

    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, master_key)
        .map_err(|_| "Invalid Master Key for AES-GCM")?;

    let mut fixed_nonce = [0u8; 12];
    fixed_nonce.copy_from_slice(nonce_bytes);

    let nonce_sequence = SimpleNonceSequence { nonce: fixed_nonce };
    let mut opening_key = OpeningKey::new(unbound_key, nonce_sequence);

    let decrypted_data = opening_key.open_in_place(Aad::empty(), &mut in_out)
        .map_err(|_| "Decryption failed")?;

    Ok(decrypted_data.to_vec())
}

pub async fn generate_key(master_key: &[u8; 32], key_id: String, key_type: String, d_pool: &SqlitePool) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key_bytes = match key_type.as_str() {
        "Ed25519" => {
            let alg = &rcgen::PKCS_ED25519;
            let key_pair = KeyPair::generate_for(alg).unwrap();
            key_pair.serialize_der()
        },
        "RSA-2048" => {
            let alg = &rcgen::PKCS_RSA_SHA256;
            let key_pair = KeyPair::generate_for(alg).unwrap();
            key_pair.serialize_der()
        }
        "ECDSA" => {
            let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
            let key_pair = KeyPair::generate_for(alg).unwrap();
            key_pair.serialize_der()
        },
        "AES-GCM" => {
            let rand = ring::rand::SystemRandom::new();
            let mut key_bytes = vec![0u8; 32]; // 32 Bytes = AES-256
            rand.fill(&mut key_bytes)
                .map_err(|_| "Fehler beim Generieren der AES-GCM Bytes")?;

            key_bytes
        },
        "AES-CBC" => {
            let rand = ring::rand::SystemRandom::new();
            let mut key_bytes = vec![0u8; 32]; // 32 Bytes = AES-256
            rand.fill(&mut key_bytes)
                .map_err(|_| "Fehler beim Generieren der AES-CBC Bytes")?;

            key_bytes
        }
        _ => {
            return Err("Invalid Key Type".into());
        }
    };

    let encrypted_blob = encrypt_blob(master_key, &key_bytes)?;

    save_key_to_db(d_pool, &key_id, &key_type, &encrypted_blob).await?;
    Ok(encrypted_blob)
}




