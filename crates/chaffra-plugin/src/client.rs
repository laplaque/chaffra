//! gRPC client for the AnalysisModule service.
//!
//! Implements unary RPCs using raw HTTP/2 via tonic's transport channel
//! and prost for serialization. This avoids tonic-build codegen entirely.

use crate::proto::{
    AnalysisRequest, AnalysisResponse, DescribeRequest, ExplainRequest, ExplainResponse,
    FixRequest, FixResponse, ModuleInfoProto,
};
use prost::Message;
use tonic::transport::Channel;

/// gRPC client for the chaffra `AnalysisModule` service.
#[derive(Debug, Clone)]
pub struct AnalysisModuleClient {
    channel: Channel,
}

impl AnalysisModuleClient {
    /// Wrap an existing tonic channel.
    pub fn new(channel: Channel) -> Self {
        Self { channel }
    }

    /// Connect to a remote endpoint.
    ///
    /// Returns an error if the endpoint is not a valid URI or the connection fails.
    pub async fn connect(endpoint: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let channel = Channel::from_shared(endpoint.to_owned())
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("invalid endpoint URI '{endpoint}': {e}").into()
            })?
            .connect()
            .await?;
        Ok(Self::new(channel))
    }

    /// Perform a unary gRPC call: encode the request with prost, send via
    /// HTTP/2, and decode the response.
    async fn unary_call<Req, Resp>(
        &mut self,
        path: &str,
        request: Req,
    ) -> Result<Resp, tonic::Status>
    where
        Req: Message,
        Resp: Message + Default,
    {
        use http_body_util::BodyExt;
        use tower::Service;
        use tower::ServiceExt;

        // Encode the request body with gRPC framing (5-byte header: compressed flag + length).
        let mut buf = Vec::new();
        request
            .encode(&mut buf)
            .map_err(|e| tonic::Status::internal(format!("encode error: {e}")))?;
        let mut framed = Vec::with_capacity(5 + buf.len());
        framed.push(0u8); // not compressed
        framed.extend_from_slice(&(buf.len() as u32).to_be_bytes());
        framed.extend_from_slice(&buf);

        let http_request = http::Request::builder()
            .method(http::Method::POST)
            .uri(path)
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(tonic::body::Body::new(http_body_util::Full::new(
                bytes::Bytes::from(framed),
            )))
            .map_err(|e| tonic::Status::internal(format!("request build error: {e}")))?;

        let response = self
            .channel
            .ready()
            .await
            .map_err(|e| tonic::Status::unavailable(format!("service not ready: {e}")))?
            .call(http_request)
            .await
            .map_err(|e| tonic::Status::internal(format!("transport error: {e}")))?;

        // Check gRPC status from trailers/headers.
        if let Some(status) = response.headers().get("grpc-status") {
            let code = status.to_str().unwrap_or("0").parse::<i32>().unwrap_or(0);
            if code != 0 {
                let message = response
                    .headers()
                    .get("grpc-message")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("unknown error")
                    .to_owned();
                return Err(tonic::Status::new(tonic::Code::from_i32(code), message));
            }
        }

        // Collect the response body.
        let body_bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|e| tonic::Status::internal(format!("body read error: {e}")))?
            .to_bytes();

        // Strip gRPC framing (5 bytes) and decode.
        if body_bytes.len() < 5 {
            return Err(tonic::Status::internal("response too short for gRPC frame"));
        }
        let payload = &body_bytes[5..];
        Resp::decode(payload).map_err(|e| tonic::Status::internal(format!("decode error: {e}")))
    }

    /// Call the `Describe` RPC.
    pub async fn describe(
        &mut self,
        request: DescribeRequest,
    ) -> Result<ModuleInfoProto, tonic::Status> {
        self.unary_call("/chaffra.module.v1.AnalysisModule/Describe", request)
            .await
    }

    /// Call the `Analyze` RPC.
    pub async fn analyze(
        &mut self,
        request: AnalysisRequest,
    ) -> Result<AnalysisResponse, tonic::Status> {
        self.unary_call("/chaffra.module.v1.AnalysisModule/Analyze", request)
            .await
    }

    /// Call the `Explain` RPC.
    pub async fn explain(
        &mut self,
        request: ExplainRequest,
    ) -> Result<ExplainResponse, tonic::Status> {
        self.unary_call("/chaffra.module.v1.AnalysisModule/Explain", request)
            .await
    }

    /// Call the `Fix` RPC.
    pub async fn fix(&mut self, request: FixRequest) -> Result<FixResponse, tonic::Status> {
        self.unary_call("/chaffra.module.v1.AnalysisModule/Fix", request)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_new() {
        // Verify the client can be constructed (channel creation is lazy).
        // We can't fully test without a running server.
        // This test validates the type construction compiles.
        let _client_type_check: fn(Channel) -> AnalysisModuleClient = AnalysisModuleClient::new;
    }
}
