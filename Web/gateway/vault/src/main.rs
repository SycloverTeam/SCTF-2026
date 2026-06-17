use vault::{build_app, AppState};

#[tokio::main]
async fn main() {
    let state = AppState::seeded();
    let app = build_app(state);

    let addr = "127.0.0.1:3005";
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    println!("Server launched at http://{addr}");

    axum::serve(listener, app).await.unwrap();
}
