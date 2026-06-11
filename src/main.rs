use axum::{
    routing::{get, post},
    Json, Router,
};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/health", get(health_check));

    let addr = SocketAddr::from(([127,0,0,1], 3000));
    println!("Server running at {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health_check() -> &'static str {
    "OK"
}
