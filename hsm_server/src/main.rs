use std::collections::HashSet;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use std::error::Error;
use bincode;
use rcgen::{KeyPair, SigningKey};
use sqlx::{sqlite::SqlitePoolOptions, Row, SqlitePool};
use ring::pbkdf2;
use std::num::NonZeroU32;

#[derive(Serialize, Deserialize, Debug)]
pub enum HsmRequest {
    OpenSession,
    CloseSession { session_id: u64 },
    Sign { session_id: u64, data: Vec<u8> },
    Error(String),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum HsmResponse {
    SessionOpened { session_id: u64 },
    SessionClosed,
    SignResult { signature: Vec<u8> },
    Error(String),
}

struct MasterKey {
    bytes: [u8; 32],
}



static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);
static ACTIVE_SESSIONS: LazyLock<Mutex<HashSet<u64>>> = LazyLock::new(|| Mutex::new(HashSet::new()));
fn handle_client(mut stream: TcpStream, d_pool: SqlitePool) -> Result<(), Box<dyn std::error::Error>> {
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
                }else {
                    HsmResponse::Error("Session not found!".to_string())
                }
            }
            HsmRequest::Sign { session_id, data } => {
                println!("Signing Data for Session {}", session_id);

                //TODO Load key from HSM
                let pem_string = "-----BEGIN PRIVATE KEY-----\n\
                      MC4CAQAwBQYDK2VwBCIEINTp9M7v7K62bUvpx6Hh7vKclBv7v0jXlNmZ4X9v7v9A\n\
                      -----END PRIVATE KEY-----";

                let key_pair = rcgen::KeyPair::from_pem(pem_string).unwrap();
                let signature_bytes = key_pair.sign(&data).unwrap();

                HsmResponse::SignResult { signature: signature_bytes }
            }

            //TODO implement
            HsmRequest::Error(_) => todo!()
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
    println!("HSM Emulator Server running on 127.0.0.1:8888");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let pool_cloned = db_pool.clone();
                if let Err(e) = handle_client(stream, pool_cloned) {
                    eprintln!("Error on Client: {}", e);
                }
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


