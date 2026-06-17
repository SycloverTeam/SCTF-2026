use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::time::Instant;

use hyper::Request;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use tokio::net::TcpListener;
use tower::ServiceExt;
use tracing::{debug, error, info, warn};

use crate::Error;
use crate::config::Config;
use crate::gateway::{GatewayService, ResponseBody, build_service, error_response};

pub async fn run(config: Config) -> Result<(), Error> {
    let listener = TcpListener::bind(config.server.listen).await?;
    run_with_listener(listener, config, shutdown_signal()).await
}

pub async fn run_with_listener<S>(
    listener: TcpListener,
    config: Config,
    shutdown: S,
) -> Result<(), Error>
where
    S: Future<Output = ()>,
{
    let service = build_service(&config)?;
    let local_addr = listener.local_addr()?;
    info!(%local_addr, "gateway listening");

    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => {
                info!("gateway shutdown requested");
                return Ok(());
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, remote_addr)) => {
                        stream.set_nodelay(true)?;
                        spawn_connection(stream, remote_addr, service.clone());
                    }
                    Err(error) => {
                        warn!(%error, "failed to accept connection");
                    }
                }
            }
        }
    }
}

fn spawn_connection(
    stream: tokio::net::TcpStream,
    remote_addr: SocketAddr,
    service: GatewayService,
) {
    tokio::spawn(async move {
        let io = TokioIo::new(stream);
        let hyper_service = service_fn(move |request| {
            let service = service.clone();
            async move { serve_request(service, remote_addr, request).await }
        });

        let builder = AutoBuilder::new(TokioExecutor::new());
        if let Err(error) = builder
            .serve_connection_with_upgrades(io, hyper_service)
            .await
        {
            debug!(%remote_addr, %error, "connection closed with error");
        }
    });
}

async fn serve_request(
    service: GatewayService,
    remote_addr: SocketAddr,
    request: Request<Incoming>,
) -> Result<http::Response<ResponseBody>, Infallible> {
    let start = Instant::now();
    let method = request.method().clone();
    let uri = request.uri().clone();

    let response = match service.oneshot(request).await {
        Ok(response) => response,
        Err(error) if error.is::<tower::timeout::error::Elapsed>() => {
            error!(%remote_addr, %method, %uri, %error, "request timed out");
            error_response(http::StatusCode::GATEWAY_TIMEOUT, "gateway timeout\n")
        }
        Err(error) => {
            error!(%remote_addr, %method, %uri, %error, "request failed");
            error_response(http::StatusCode::BAD_GATEWAY, "bad gateway\n")
        }
    };

    info!(
        %remote_addr,
        %method,
        %uri,
        status = response.status().as_u16(),
        elapsed_ms = start.elapsed().as_millis(),
        "request completed"
    );

    Ok(response)
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        warn!(%error, "failed to install Ctrl-C handler");
    }
}
