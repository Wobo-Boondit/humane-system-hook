use std::sync::Arc;

use reqwest::Client as HttpClient;
use rig::providers;
use tracing::info;

use crate::config::ResolvedConfig;
use crate::llm::backend::LlmBackend;
use crate::llm::memory::MemoryService;
use crate::llm::request_log::LlmRequestLogger;
use crate::llm::rig_backend::RigBackend;

pub struct GeminiProvider;

impl GeminiProvider {
    pub async fn build(
        config: &ResolvedConfig,
        http_client: HttpClient,
        request_logger: LlmRequestLogger,
        memory: Option<MemoryService>,
    ) -> Result<Arc<dyn LlmBackend>, Box<dyn std::error::Error + Send + Sync>> {
        let llm_config = &config.config.llm;
        let api_key = llm_config.resolve_api_key().ok_or(
            "Gemini api_key not set; configure GEMINI_API_KEY in the environment or .env, or set llm.api_key in config.toml",
        )?;
        let client = providers::gemini::Client::builder()
            .api_key(&api_key)
            .http_client(http_client.clone())
            .build()?;

        let client = client.interactions_api();

        info!("Gemini agent ready (model={})", llm_config.model);
        let gemini_google_search = llm_config.web_search;

        RigBackend::from_client(
            "Gemini",
            client,
            request_logger,
            config,
            http_client,
            memory,
            move |builder| {
                let additional_params = if gemini_google_search {
                    info!("Gemini Google Search grounding enabled");
                    serde_json::json!({
                        "tools": [{ "type": "google_search" }],
                    })
                } else {
                    serde_json::json!({})
                };

                builder.additional_params(additional_params)
            },
        )
        .await
    }
}
