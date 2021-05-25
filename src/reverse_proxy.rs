use hyper::{Client, Request, Body, Response, HeaderMap, Uri};
use hyper::client::HttpConnector;
use hyper::http::HeaderValue;
use hyper::http::StatusCode;
use crate::waf_error::WafError;
use crate::waf::WebApplicationFirewall;
use std::net::SocketAddr;

pub(crate) struct ReverseProxy {
    pub(crate) scheme: String,
    pub(crate) authority: String,
    pub(crate) client: Client<HttpConnector>,
    pub(crate) web_application_firewall: WebApplicationFirewall,
}

impl ReverseProxy {
    pub async fn handle_request(&self,
                                remote_addr: SocketAddr,
                                mut request: Request<Body>)
                                -> Result<Response<Body>, WafError>
    {
        request.extensions_mut().insert(remote_addr);
        // Rewrite the request to pass it forward to upstream servers
        *request.headers_mut() = self.whitelist_headers(&request);
        *request.uri_mut() = self.rewrite_uri(&request);

        log::debug!("Request == {:?} from {:?}", request, remote_addr);
        let inspected_request_result = self.web_application_firewall
            .inspect_request(request)
            .await
            .and_then(|normalized_req| {
                log::debug!("Normalized request {:?}", normalized_req);
                Ok(normalized_req)
            });

        if inspected_request_result.is_err() {
            let blocked_response = Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("Shoo! Go away!"))
                .unwrap();
            return Ok(blocked_response);
        }

        let received_response_result = match inspected_request_result {
            Ok(normalized_request) => self.client.request(normalized_request)
                .await
                .map_err(|error| WafError::new("Unreachable origin")),
            Err(error) => Err(error),
        };

        return received_response_result
            .and_then(|response| {
                log::debug!("Received response == {:?}", response);
                Ok(response)
            })
            .and_then(|mut response| self.web_application_firewall.inspect_response(response));
    }

    fn rewrite_uri(&self, request: &Request<Body>) -> Uri {
        // Change the request's URI
        let mut uri_builder = hyper::Uri::builder()
            .scheme(&*self.scheme)
            .authority(&*self.authority);
        // Copy path and query params
        if let Some(path_and_query) = request.uri().path_and_query() {
            uri_builder = uri_builder.path_and_query(path_and_query.clone());
        }
        return uri_builder.build().unwrap();
    }

    fn whitelist_headers(&self, request: &Request<Body>) -> HeaderMap<HeaderValue> {
        // Remove headers not whitelisted
        const ALLOWED_HEADERS: [&str; 7] = [
            // "host",
            "content-type",
            "accept",
            "user-agent",
            "dnt",
            "x-forwarded-for",
            "x-real-ip",
            "cookie",
        ];

        let mut filtered_headers = HeaderMap::new();
        for (header_name, header_value) in request.headers() {
            if ALLOWED_HEADERS.contains(&header_name.as_str()) {
                filtered_headers.insert(header_name, header_value.clone());
            }
        }

        // todo: add x-forwarded-for and x-real-ip logic
        let user_ip = request.extensions().get::<SocketAddr>().unwrap().ip();
        filtered_headers.insert("x-forwarded-for", (user_ip.to_string() + ", 127.0.0.1").parse().unwrap());
        filtered_headers.insert("x-real-ip", user_ip.to_string().parse().unwrap());
        return filtered_headers;
    }
}