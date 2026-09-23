use std::time::Instant;

use std::sync::Arc;

use base64::Engine as _;
use reqwest::Client as HttpClient;
use rig::agent::{Agent, AgentBuilder, AgentHook, CompletionResponseEvent, HookContext, ObservationAction};
use rig::client::{AgentClientExt, CompletionClient};
use rig::completion::message::{AssistantContent, ImageMediaType, Message, UserContent};
use rig::completion::{Prompt, PromptError};
use rig::tool::Tool;
use tracing::{error, warn};

use crate::config::ResolvedConfig;
use crate::llm::ChatResult;

use super::backend::{LlmBackend, LlmFuture};
use super::error::{friendly_error_message, strip_query_strings};
use super::memory::MemoryService;
use super::prompt::PromptBuilder;
use super::request::LlmChatRequest;
use super::request_log::LlmRequestLogger;
use super::tools::registry::LlmToolContext;
use super::tools::understand_scene::UnderstandSceneTool;

/// Marker for a termination due to device vision request
const DEFERRED_VISION_SENTINEL: &str = "__HUMANE_DEFERRED_VISION__";

/// Rig hook to prevent execution of the `understand_scene` tool. The returned termination value
/// is used to trigger a DeferredVision response to the client
#[derive(Clone)]
struct DeferredVisionHook;

impl AgentHook for DeferredVisionHook {
    async fn on_completion_response(
        &self,
        _ctx: &HookContext,
        event: CompletionResponseEvent<'_>,
    ) -> ObservationAction {
        let selected_vision = event.content.iter().any(|content| {
            matches!(
                content,
                AssistantContent::ToolCall(call)
                    if call.function.name == UnderstandSceneTool::NAME
            )
        });

        if selected_vision {
            ObservationAction::stop(DEFERRED_VISION_SENTINEL.to_string())
        } else {
            ObservationAction::continue_run()
        }
    }
}

/// Shared LLM backend for providers
pub struct RigBackend {
    provider_label: &'static str,
    agent: Agent,
    request_logger: LlmRequestLogger,
    max_tool_turns: usize,
    tool_concurrency: usize,
}

impl RigBackend {
    pub async fn from_client<C, F>(
        provider_label: &'static str,
        client: C,
        request_logger: LlmRequestLogger,
        config: &ResolvedConfig,
        http_client: HttpClient,
        memory: Option<MemoryService>,
        customize_builder: F,
    ) -> Result<Arc<dyn LlmBackend>, Box<dyn std::error::Error + Send + Sync>>
    where
        C: CompletionClient,
        <C as CompletionClient>::CompletionModel: 'static,
        F: FnOnce(AgentBuilder) -> AgentBuilder,
    {
        let llm_config = &config.config.llm;
        let builder = customize_builder(
            client
                .agent(&llm_config.model)
                .max_tokens(llm_config.max_output_tokens),
        );

        let tool_resources = if llm_config.tools.enabled {
            let tool_context = LlmToolContext::new(http_client, config, memory);
            tool_context
                .build_tool_resources(llm_config)
                .await
                .map_err(|err| -> Box<dyn std::error::Error + Send + Sync> {
                    std::io::Error::new(std::io::ErrorKind::Other, err).into()
                })?
        } else {
            None
        };

        let agent = match tool_resources {
            Some(resources) => resources.apply(builder).build(),
            None => builder.build(),
        };

        Ok(Arc::new(Self {
            provider_label,
            agent,
            request_logger,
            max_tool_turns: llm_config.tools.max_tool_turns,
            tool_concurrency: llm_config.tools.tool_concurrency,
        }))
    }
}

impl LlmBackend for RigBackend
{
    fn chat<'a>(&'a self, request: LlmChatRequest) -> LlmFuture<'a> {
        Box::pin(async move {
            let utterance = request.utterance.clone();
            let run_id = request.template_context.run_id.clone();
            let history = PromptBuilder::build_chat_history(&request);
            let started = Instant::now();

            let content = if let Some(image_bytes) = &request.image {
                vec![
                    UserContent::text(utterance.clone()),
                    UserContent::image_base64(
                        &base64::engine::general_purpose::STANDARD.encode(image_bytes),
                        Some(ImageMediaType::JPEG),
                        None,
                    ),
                ]
            } else {
                vec![UserContent::text(utterance.clone())]
            };

            let user_message = Message::User { content };

            let mut retried = false;
            let raw_result = loop {
                let result = self
                    .agent
                    .prompt(user_message.clone())
                    .history(history.clone())
                    .max_turns(self.max_tool_turns)
                    .tool_concurrency(self.tool_concurrency.max(1))
                    .add_hook(DeferredVisionHook)
                    .await;

                match result {
                    Err(ref e) if !retried && is_retryable_send_error(e) => {
                        retried = true;
                        warn!(
                            provider = self.provider_label,
                            error = %strip_query_strings(&e.to_string()),
                            "LLM request failed before reaching the server; retrying once"
                        );
                    }
                    other => break other,
                }
            };
            let latency_ms = started.elapsed().as_millis();

            let result = match raw_result {
                Ok(text) => Ok(ChatResult::Text(text)),
                Err(PromptError::PromptCancelled { reason, .. })
                    if reason == DEFERRED_VISION_SENTINEL =>
                {
                    Ok(ChatResult::DeferredVision)
                }
                Err(e) => {
                    error!(provider = self.provider_label, error = %strip_query_strings(&e.to_string()), "LLM chat failed");
                    Err(friendly_error_message(&e))
                }
            };

            self.request_logger
                .log_chat(
                    self.provider_label,
                    &run_id,
                    &history,
                    &utterance,
                    match &result {
                        Ok(ChatResult::Text(text)) => Some(text.as_str()),
                        Ok(ChatResult::DeferredVision) => None,
                        Err(_) => None,
                    },
                    result.clone().err().as_deref(),
                    latency_ms,
                )
                .await;

            result
        })
    }
}

/// Check for a transport level error, denoting the request never reached the provider and may be retried
fn is_retryable_send_error(error: &PromptError) -> bool {
    if !matches!(error, PromptError::CompletionError(_)) {
        return false;
    }

    let mut source = std::error::Error::source(error);
    while let Some(inner) = source {
        if let Some(e) = inner.downcast_ref::<reqwest::Error>() {
            return (e.is_connect() || e.is_request()) && !e.is_timeout();
        }

        source = inner.source();
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use rig::completion::CompletionError;

    /// Wrap a reqwest error the way rig's transport does, so the test
    /// exercises the same source() chain `is_retryable_send_error` walks.
    fn prompt_error_from(reqwest_err: reqwest::Error) -> PromptError {
        PromptError::CompletionError(CompletionError::HttpError(
            rig::http_client::Error::Instance(Box::new(reqwest_err)),
        ))
    }

    #[tokio::test]
    async fn retries_connect_class_errors() {
        // Nothing listens on this loopback port, so send() fails at connect.
        let reqwest_err = reqwest::Client::new()
            .get("http://127.0.0.1:1/")
            .send()
            .await
            .expect_err("connect to a closed port must fail");
        assert!(is_retryable_send_error(&prompt_error_from(reqwest_err)));
    }

    #[test]
    fn does_not_retry_response_class_errors() {
        let status = PromptError::CompletionError(CompletionError::HttpError(
            rig::http_client::Error::InvalidStatusCodeWithMessage(
                http::StatusCode::TOO_MANY_REQUESTS,
                "rate limited".to_string(),
            ),
        ));
        assert!(!is_retryable_send_error(&status));

        let provider =
            PromptError::CompletionError(CompletionError::ProviderError("500".to_string()));
        assert!(!is_retryable_send_error(&provider));
    }

    #[test]
    fn does_not_retry_cancellation() {
        let cancelled = PromptError::PromptCancelled {
            chat_history: Vec::new(),
            reason: DEFERRED_VISION_SENTINEL.to_string(),
        };
        assert!(!is_retryable_send_error(&cancelled));
    }
}
