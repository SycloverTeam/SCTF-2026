use std::sync::Arc;

use http::Method;
use tower_http::services::ServeDir;

use crate::Error;
use crate::config::{Config, RouteConfig, RouteKind};
use crate::upstream::{Endpoint, UpstreamCluster};

#[derive(Debug, Clone)]
pub struct RouteTable {
    routes: Arc<Vec<Route>>,
}

#[derive(Debug)]
struct Route {
    name: Arc<str>,
    host: Option<String>,
    path_prefix: String,
    methods: Vec<Method>,
    backend: RouteBackend,
}

#[derive(Debug, Clone)]
pub struct MatchedRoute {
    pub name: Arc<str>,
    pub backend: MatchedBackend,
}

#[derive(Debug)]
enum RouteBackend {
    Proxy(Arc<UpstreamCluster>),
    Static(ServeDir),
}

#[derive(Debug, Clone)]
pub enum MatchedBackend {
    Proxy(Endpoint),
    Static {
        path_prefix: Arc<str>,
        service: ServeDir,
    },
}

impl RouteTable {
    pub fn from_config(config: &Config) -> Result<Self, Error> {
        let mut routes = config
            .routes
            .iter()
            .map(Route::try_from_config)
            .collect::<Result<Vec<_>, _>>()?;

        routes.sort_by(|left, right| right.path_prefix.len().cmp(&left.path_prefix.len()));

        Ok(Self {
            routes: Arc::new(routes),
        })
    }

    pub fn match_route(
        &self,
        method: &Method,
        host: Option<&str>,
        path: &str,
    ) -> Option<MatchedRoute> {
        self.routes
            .iter()
            .find(|route| route.matches(method, host, path))
            .map(|route| MatchedRoute {
                name: route.name.clone(),
                backend: route.matched_backend(),
            })
    }
}

impl Route {
    fn try_from_config(config: &RouteConfig) -> Result<Self, Error> {
        if !config.path_prefix.starts_with('/') {
            return Err(Error::Config(format!(
                "route {} path_prefix must start with /",
                config.name
            )));
        }

        let backend = match config.kind {
            RouteKind::Proxy => RouteBackend::Proxy(UpstreamCluster::new(&config.upstreams)?),
            RouteKind::Static => {
                if !config.upstreams.is_empty() {
                    return Err(Error::Config(format!(
                        "static route {} must not define upstreams",
                        config.name
                    )));
                }

                let root = config.root.as_ref().ok_or_else(|| {
                    Error::Config(format!("static route {} must define root", config.name))
                })?;

                RouteBackend::Static(ServeDir::new(root))
            }
        };

        Ok(Self {
            name: Arc::from(config.name.as_str()),
            host: config.host.as_deref().map(normalize_host),
            path_prefix: config.path_prefix.clone(),
            methods: config.methods.clone(),
            backend,
        })
    }

    fn matches(&self, method: &Method, host: Option<&str>, path: &str) -> bool {
        self.matches_method(method) && self.matches_host(host) && self.matches_path(path)
    }

    fn matches_method(&self, method: &Method) -> bool {
        self.methods.is_empty() || self.methods.iter().any(|candidate| candidate == method)
    }

    fn matches_host(&self, host: Option<&str>) -> bool {
        let Some(expected) = &self.host else {
            return true;
        };

        host.map(normalize_host).as_deref() == Some(expected.as_str())
    }

    fn matches_path(&self, path: &str) -> bool {
        if self.path_prefix == "/" {
            return path.starts_with('/');
        }

        path == self.path_prefix
            || path
                .strip_prefix(self.path_prefix.as_str())
                .is_some_and(|suffix| suffix.starts_with('/'))
    }

    fn matched_backend(&self) -> MatchedBackend {
        match &self.backend {
            RouteBackend::Proxy(upstream) => MatchedBackend::Proxy(upstream.select()),
            RouteBackend::Static(service) => MatchedBackend::Static {
                path_prefix: Arc::from(self.path_prefix.as_str()),
                service: service.clone(),
            },
        }
    }
}

fn normalize_host(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use super::*;
    use crate::config::{SelectorConfig, ServerConfig};

    fn config_with_routes(routes: Vec<RouteConfig>) -> Config {
        Config {
            server: ServerConfig {
                listen: SocketAddr::from(([127, 0, 0, 1], 0)),
                request_timeout: Duration::from_secs(1),
                max_concurrency: 16,
            },
            selector: SelectorConfig::default(),
            routes,
        }
    }

    #[test]
    fn prefers_longest_path_prefix() {
        let routes = vec![
            route("short", "/api", "http://127.0.0.1:3001"),
            route("long", "/api/users", "http://127.0.0.1:3002"),
        ];
        let table = RouteTable::from_config(&config_with_routes(routes)).unwrap();

        let matched = table
            .match_route(&Method::GET, Some("example.com"), "/api/users/42")
            .unwrap();

        assert_eq!(matched.name.as_ref(), "long");
        let MatchedBackend::Proxy(upstream) = matched.backend else {
            panic!("expected proxy route");
        };
        assert_eq!(upstream.authority.as_str(), "127.0.0.1:3002");
    }

    #[test]
    fn path_prefix_requires_segment_boundary() {
        let table = RouteTable::from_config(&config_with_routes(vec![route(
            "api",
            "/api",
            "http://127.0.0.1:3001",
        )]))
        .unwrap();

        assert!(
            table
                .match_route(&Method::GET, None, "/api/users")
                .is_some()
        );
        assert!(table.match_route(&Method::GET, None, "/apix").is_none());
    }

    fn route(name: &str, path_prefix: &str, upstream: &str) -> RouteConfig {
        RouteConfig {
            name: name.to_string(),
            kind: RouteKind::Proxy,
            host: None,
            path_prefix: path_prefix.to_string(),
            methods: vec![Method::GET],
            upstreams: vec![upstream.to_string()],
            root: None,
        }
    }
}
