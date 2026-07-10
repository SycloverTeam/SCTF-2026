use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use http::Uri;
use http::uri::{Authority, Scheme};

use crate::Error;

#[derive(Debug)]
pub struct UpstreamCluster {
    endpoints: Vec<Endpoint>,
    next: AtomicUsize,
}

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub scheme: Scheme,
    pub authority: Authority,
}

impl UpstreamCluster {
    pub fn new(values: &[String]) -> Result<Arc<Self>, Error> {
        if values.is_empty() {
            return Err(Error::Config(
                "route must define at least one upstream".to_string(),
            ));
        }

        let endpoints = values
            .iter()
            .map(|value| Endpoint::parse(value))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Arc::new(Self {
            endpoints,
            next: AtomicUsize::new(0),
        }))
    }

    pub fn select(&self) -> Endpoint {
        let index = self.next.fetch_add(1, Ordering::Relaxed) % self.endpoints.len();
        self.endpoints[index].clone()
    }
}

impl Endpoint {
    fn parse(value: &str) -> Result<Self, Error> {
        let uri = value
            .parse::<Uri>()
            .map_err(|err| Error::Config(format!("invalid upstream URI {value}: {err}")))?;
        let scheme = uri
            .scheme()
            .cloned()
            .ok_or_else(|| Error::Config(format!("upstream URI {value} must include scheme")))?;
        let authority = uri
            .authority()
            .cloned()
            .ok_or_else(|| Error::Config(format!("upstream URI {value} must include authority")))?;

        match scheme.as_str() {
            "http" | "https" => Ok(Self { scheme, authority }),
            other => Err(Error::Config(format!(
                "unsupported upstream scheme {other}; expected http or https"
            ))),
        }
    }
}
