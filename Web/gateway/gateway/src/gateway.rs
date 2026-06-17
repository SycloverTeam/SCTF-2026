use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use http::header::{
    CONNECTION, HOST, HeaderMap, HeaderName, HeaderValue, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION,
    TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use http::{Method, Request, Response, StatusCode, Uri};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use tower::limit::ConcurrencyLimitLayer;
use tower::timeout::TimeoutLayer;
use tower::util::BoxCloneService;
use tower::{ServiceBuilder, ServiceExt, service_fn};
use tracing::debug;

use crate::Error;
use crate::config::Config;
use crate::error::BoxedError;
use crate::router::{MatchedBackend, RouteTable};
use crate::selector::{SelectorEngine, trace_json};
use crate::upstream::Endpoint;

pub type ResponseBody = UnsyncBoxBody<Bytes, BoxedError>;
pub type GatewayService = BoxCloneService<Request<Incoming>, Response<ResponseBody>, BoxedError>;

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
pub struct Gateway {
    routes: RouteTable,
    client: Client<HttpsConnector<HttpConnector>, Incoming>,
    selector: SelectorEngine,
}

impl Gateway {
    pub fn new(config: &Config) -> Result<Self, Error> {
        let routes = RouteTable::from_config(config)?;
        let https = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(https);
        let selector = SelectorEngine::new(
            config.selector.snapshot_url.clone(),
            config.selector.refresh_interval,
        );

        Ok(Self {
            routes,
            client,
            selector,
        })
    }

    pub async fn handle(
        &self,
        request: Request<Incoming>,
    ) -> Result<Response<ResponseBody>, BoxedError> {
        if is_health_check(&request) {
            return Ok(text_response(StatusCode::OK, "ok\n"));
        }

        if is_route_audit(&request) {
            return self.route_audit(request).await;
        }

        let host = request
            .headers()
            .get(HOST)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let path = request.uri().path().to_string();
        let method = request.method().clone();
        let request_id = request_id(&request);

        let Some(matched) = self.routes.match_route(&method, host.as_deref(), &path) else {
            let mut response = text_response(StatusCode::NOT_FOUND, "route not found\n");
            insert_request_id(response.headers_mut(), &request_id)?;
            return Ok(response);
        };

        match matched.backend {
            MatchedBackend::Proxy(upstream) => {
                debug!(route = %matched.name, "proxying request");
                self.proxy(request, &upstream, &request_id).await
            }
            MatchedBackend::Static {
                path_prefix,
                service,
            } => {
                debug!(route = %matched.name, "serving static request");
                serve_static(request, path_prefix.as_ref(), service, &request_id).await
            }
        }
    }

    async fn proxy(
        &self,
        request: Request<Incoming>,
        upstream: &Endpoint,
        request_id: &str,
    ) -> Result<Response<ResponseBody>, BoxedError> {
        let mut upstream_request = rewrite_request(request, upstream)?;
        strip_hop_by_hop_headers(upstream_request.headers_mut());
        insert_request_id(upstream_request.headers_mut(), request_id)?;

        let mut response = self
            .client
            .request(upstream_request)
            .await?
            .map(boxed_incoming);
        strip_hop_by_hop_headers(response.headers_mut());
        insert_request_id(response.headers_mut(), request_id)?;

        Ok(response)
    }

    async fn route_audit(
        &self,
        request: Request<Incoming>,
    ) -> Result<Response<ResponseBody>, BoxedError> {
        let request_id = request_id(&request);
        let Some(selector) = request.headers().get("x-route-selector") else {
            let mut response = text_response(StatusCode::BAD_REQUEST, "missing x-route-selector\n");
            insert_request_id(response.headers_mut(), &request_id)?;
            return Ok(response);
        };

        let trace = self.selector.defer_trace(selector.as_bytes());
        request.into_body().collect().await?;

        let trace = trace.finish();
        let mut response = bytes_response(StatusCode::OK, trace_json(&trace));
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        insert_request_id(response.headers_mut(), &request_id)?;
        Ok(response)
    }
}

pub fn build_service(config: &Config) -> Result<GatewayService, Error> {
    let gateway = Gateway::new(config)?;
    let timeout = config.server.request_timeout;
    let max_concurrency = config.server.max_concurrency;

    Ok(ServiceBuilder::new()
        .layer(TimeoutLayer::new(timeout))
        .layer(ConcurrencyLimitLayer::new(max_concurrency))
        .service(service_fn(move |request| {
            let gateway = gateway.clone();
            async move { gateway.handle(request).await }
        }))
        .boxed_clone())
}

pub fn text_response(status: StatusCode, body: &'static str) -> Response<ResponseBody> {
    let mut response = Response::new(boxed_full(Bytes::from_static(body.as_bytes())));
    *response.status_mut() = status;
    response
}

pub fn error_response(status: StatusCode, body: &'static str) -> Response<ResponseBody> {
    text_response(status, body)
}

fn bytes_response(status: StatusCode, body: Bytes) -> Response<ResponseBody> {
    let mut response = Response::new(boxed_full(body));
    *response.status_mut() = status;
    response
}

fn is_health_check(request: &Request<Incoming>) -> bool {
    request.method() == Method::GET && request.uri().path() == "/healthz"
}

fn is_route_audit(request: &Request<Incoming>) -> bool {
    request.method() == Method::POST && request.uri().path() == "/__route/audit"
}

fn rewrite_request(
    request: Request<Incoming>,
    endpoint: &Endpoint,
) -> Result<Request<Incoming>, BoxedError> {
    let (mut parts, body) = request.into_parts();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    parts.uri = Uri::builder()
        .scheme(endpoint.scheme.clone())
        .authority(endpoint.authority.clone())
        .path_and_query(path_and_query)
        .build()?;
    parts
        .headers
        .insert(HOST, HeaderValue::from_str(endpoint.authority.as_str())?);
    Ok(Request::from_parts(parts, body))
}

async fn serve_static(
    request: Request<Incoming>,
    path_prefix: &str,
    service: tower_http::services::ServeDir,
    request_id: &str,
) -> Result<Response<ResponseBody>, BoxedError> {
    let request = rewrite_static_request(request, path_prefix)?;
    let mut response = service
        .oneshot(request)
        .await
        .map_err(|never| match never {})?
        .map(|body| {
            body.map_err(|err| -> BoxedError { Box::new(err) })
                .boxed_unsync()
        });
    insert_request_id(response.headers_mut(), request_id)?;
    Ok(response)
}

fn rewrite_static_request(
    request: Request<Incoming>,
    path_prefix: &str,
) -> Result<Request<Incoming>, BoxedError> {
    let (mut parts, body) = request.into_parts();
    let static_path = static_path(parts.uri.path(), path_prefix);
    let path_and_query = match parts.uri.query() {
        Some(query) => format!("{static_path}?{query}"),
        None => static_path,
    };
    parts.uri = Uri::builder().path_and_query(path_and_query).build()?;
    Ok(Request::from_parts(parts, body))
}

fn static_path(path: &str, path_prefix: &str) -> String {
    if path_prefix == "/" {
        return path.to_string();
    }

    let suffix = path.strip_prefix(path_prefix).unwrap_or(path);
    if suffix.is_empty() {
        "/".to_string()
    } else if suffix.starts_with('/') {
        suffix.to_string()
    } else {
        format!("/{suffix}")
    }
}

fn request_id(request: &Request<Incoming>) -> String {
    request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| {
            let id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
            format!("gw-{id}")
        })
}

fn insert_request_id(headers: &mut HeaderMap, request_id: &str) -> Result<(), BoxedError> {
    headers.insert("x-request-id", HeaderValue::from_str(request_id)?);
    Ok(())
}

fn boxed_full(bytes: Bytes) -> ResponseBody {
    Full::new(bytes)
        .map_err(|never| -> BoxedError { match never {} })
        .boxed_unsync()
}

fn boxed_incoming(body: Incoming) -> ResponseBody {
    body.map_err(|err| -> BoxedError { Box::new(err) })
        .boxed_unsync()
}

pub fn strip_hop_by_hop_headers(headers: &mut HeaderMap) {
    let connection_headers = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|value| HeaderName::from_bytes(value.trim().as_bytes()).ok())
        .collect::<Vec<_>>();

    for name in connection_headers {
        headers.remove(name);
    }

    for name in [CONNECTION.as_str(), "keep-alive"] {
        headers.remove(name);
    }

    for name in [
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
    ] {
        headers.remove(name);
    }
}
