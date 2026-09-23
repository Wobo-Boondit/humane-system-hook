use std::convert::Infallible;

use rig::tool::{Tool, ToolContext, ToolEmbedding};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::llm::memory::{MemorySearchResult, MemoryService};

#[derive(Clone)]
pub struct SearchMemoryTool {
    memory: MemoryService,
}

impl SearchMemoryTool {
    pub fn new(memory: MemoryService) -> Self {
        Self { memory }
    }
}

#[derive(Debug, Deserialize)]
pub struct SearchMemoryArgs {
    pub query: String,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct SearchMemoryOutput {
    pub memories: Vec<MemorySearchResult>,
}

impl Tool for SearchMemoryTool {
    const NAME: &'static str = "search_memory";

    type Error = super::MemoryToolError;
    type Args = SearchMemoryArgs;
    type Output = SearchMemoryOutput;

    fn description(&self) -> String {
        "Search long-term assistant memory for preferences, facts, project context, instructions, relationships, or prior saved information relevant to the user request.".to_string()
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Semantic search query for long-term memory."
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 20,
                    "description": "Maximum memories to return. Defaults to 5."
                }
            },
            "required": ["query"]
        })
    }

    async fn call(&self, _context: &mut ToolContext, args: Self::Args) -> Result<Self::Output, Self::Error> {
        let memories = self
            .memory
            .search(args.query, args.limit.unwrap_or(5))
            .await?;

        Ok(SearchMemoryOutput { memories })
    }
}

impl ToolEmbedding for SearchMemoryTool {
    type InitError = Infallible;
    type Context = ();
    type State = MemoryService;

    fn embedding_docs(&self) -> Vec<String> {
        vec!["Search recall find retrieve long term assistant memory saved preferences facts project instructions relationship context what do I know remember about".to_string()]
    }

    fn context(&self) -> Self::Context {
        ()
    }

    fn init(state: Self::State, _context: Self::Context) -> Result<Self, Self::InitError> {
        Ok(Self::new(state))
    }
}
