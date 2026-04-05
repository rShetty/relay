"""
AI Provider Connector for MCP Gateway

Provides tools for OpenAI and Anthropic APIs:
- Chat completions
- Embeddings
- Image generation (OpenAI)
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

import httpx

from .github import BaseConnector, ConnectorConfig, ToolDefinition, ResourceDefinition, PromptDefinition

logger = logging.getLogger(__name__)


class OpenAIConnector(BaseConnector):
    """
    OpenAI API connector.
    
    Provides access to GPT models, embeddings, and image generation.
    """
    
    name = "openai"
    display_name = "OpenAI"
    description = "OpenAI API for GPT models, embeddings, and images"
    
    TOOL_MAPPING = {
        "chat_completion": {
            "name": "openai_chat_completion",
            "description": "Generate a chat completion using GPT models",
            "parameters": {
                "type": "object",
                "properties": {
                    "messages": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "role": {"type": "string", "enum": ["system", "user", "assistant"]},
                                "content": {"type": "string"},
                            },
                        },
                        "description": "Conversation messages",
                    },
                    "model": {"type": "string", "default": "gpt-4o", "description": "Model to use (gpt-4o, gpt-4o-mini, gpt-4-turbo, gpt-3.5-turbo)"},
                    "temperature": {"type": "number", "default": 0.7, "minimum": 0, "maximum": 2},
                    "max_tokens": {"type": "integer", "default": 4096},
                    "top_p": {"type": "number", "default": 1},
                    "stop": {"type": "array", "items": {"type": "string"}},
                    "presence_penalty": {"type": "number", "default": 0},
                    "frequency_penalty": {"type": "number", "default": 0},
                    "response_format": {"type": "object", "description": "Force JSON output with {type: 'json_object'}"},
                },
                "required": ["messages"],
            },
            "handler": "_chat_completion",
        },
        "create_embedding": {
            "name": "openai_create_embedding",
            "description": "Generate embeddings for text",
            "parameters": {
                "type": "object",
                "properties": {
                    "input": {"type": "string", "description": "Text to embed"},
                    "model": {"type": "string", "default": "text-embedding-3-small"},
                    "dimensions": {"type": "integer", "description": "Output dimensions (for text-embedding-3 models)"},
                },
                "required": ["input"],
            },
            "handler": "_create_embedding",
        },
        "generate_image": {
            "name": "openai_generate_image",
            "description": "Generate an image using DALL-E",
            "parameters": {
                "type": "object",
                "properties": {
                    "prompt": {"type": "string", "description": "Image description"},
                    "model": {"type": "string", "default": "dall-e-3", "enum": ["dall-e-3", "dall-e-2"]},
                    "size": {"type": "string", "default": "1024x1024", "enum": ["256x256", "512x512", "1024x1024", "1792x1024", "1024x1792"]},
                    "quality": {"type": "string", "default": "standard", "enum": ["standard", "hd"]},
                    "style": {"type": "string", "default": "vivid", "enum": ["vivid", "natural"]},
                    "n": {"type": "integer", "default": 1, "description": "Number of images to generate"},
                },
                "required": ["prompt"],
            },
            "handler": "_generate_image",
        },
        "list_models": {
            "name": "openai_list_models",
            "description": "List available models",
            "parameters": {"type": "object", "properties": {}},
            "handler": "_list_models",
        },
    }
    
    RESOURCE_MAPPING = {
        "models": {
            "uri": "openai://models",
            "name": "Models",
            "description": "List available OpenAI models",
            "handler": "_list_models_resource",
        },
    }
    
    PROMPT_MAPPING = {
        "chat": {
            "name": "Chat Completion",
            "description": "Template for chat completion",
            "arguments": [
                {"name": "message", "description": "User message"},
                {"name": "model", "description": "Model to use"},
            ],
            "template": """Send the following message to the user:

{message}

Use openai_chat_completion with model: {model}""",
        },
    }
    
    def __init__(self, config: ConnectorConfig):
        super().__init__(config)
        self.base_url = config.base_url or "https://api.openai.com/v1"
    
    def set_token(self, token: str) -> None:
        """Set the API token for this connector."""
        self.config.api_key = token
    
    def _get_headers(self) -> Dict[str, str]:
        """Get headers for OpenAI API requests."""
        return {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }
    
    def get_tools(self) -> List[ToolDefinition]:
        """Return OpenAI tools dynamically from TOOL_MAPPING."""
        tools = []
        for tool_key, tool_def in self.TOOL_MAPPING.items():
            handler = getattr(self, tool_def["handler"], None)
            if handler:
                tools.append(ToolDefinition(
                    name=tool_def["name"],
                    description=tool_def["description"],
                    parameters=tool_def["parameters"],
                    handler=handler,
                ))
        return tools
    
    async def get_tools_async(self) -> List[ToolDefinition]:
        """Return OpenAI tools (sync version for compatibility)."""
        return self.get_tools()
    
    def get_resources(self) -> List[ResourceDefinition]:
        """Return OpenAI resources from RESOURCE_MAPPING."""
        resources = []
        for res_key, res_def in self.RESOURCE_MAPPING.items():
            handler = getattr(self, res_def["handler"], None)
            if handler:
                resources.append(ResourceDefinition(
                    uri=res_def["uri"],
                    name=res_def["name"],
                    description=res_def["description"],
                    read_handler=handler,
                ))
        return resources
    
    def get_prompts(self) -> List[PromptDefinition]:
        """Return OpenAI prompts from PROMPT_MAPPING."""
        prompts = []
        for prompt_key, prompt_def in self.PROMPT_MAPPING.items():
            prompts.append(PromptDefinition(
                name=prompt_def["name"],
                description=prompt_def["description"],
                arguments=prompt_def.get("arguments", []),
                template=prompt_def.get("template", ""),
            ))
        return prompts
    
    async def read_resource(self, uri: str) -> Optional[Dict[str, Any]]:
        """Read an OpenAI resource by URI."""
        resources = self.get_resources()
        for resource in resources:
            if resource.uri == uri and resource.read_handler:
                try:
                    result = await resource.read_handler()
                    return result
                except Exception as e:
                    return {"error": str(e)}
        return None
    
    # call_tool is inherited from BaseConnector
    
    async def health_check(self) -> Tuple[bool, str]:
        """Check OpenAI API accessibility."""
        try:
            client = await self.get_client()
            response = await client.get(
                f"{self.base_url}/models",
                headers=self._get_headers(),
            )
            if response.status_code == 200:
                return True, "OpenAI API accessible"
            return False, f"OpenAI API returned status {response.status_code}"
        except Exception as e:
            return False, f"OpenAI API check failed: {e}"
    
    # --- Tool Implementations ---
    
    async def _chat_completion(
        self,
        messages: List[Dict[str, str]],
        model: str = "gpt-4o",
        temperature: float = 0.7,
        max_tokens: int = 4096,
        top_p: float = 1.0,
        stop: Optional[List[str]] = None,
        presence_penalty: float = 0,
        frequency_penalty: float = 0,
        response_format: Optional[Dict] = None,
    ) -> Dict:
        """Generate a chat completion."""
        client = await self.get_client()
        
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "top_p": top_p,
            "presence_penalty": presence_penalty,
            "frequency_penalty": frequency_penalty,
        }
        if stop:
            payload["stop"] = stop
        if response_format:
            payload["response_format"] = response_format
        
        response = await self._retry_request(
            lambda: client.post(
                f"{self.base_url}/chat/completions",
                json=payload,
                headers=self._get_headers(),
            )
        )
        response.raise_for_status()
        data = response.json()
        
        choice = data.get("choices", [{}])[0]
        return {
            "content": choice.get("message", {}).get("content"),
            "role": choice.get("message", {}).get("role"),
            "finish_reason": choice.get("finish_reason"),
            "model": data.get("model"),
            "usage": data.get("usage"),
        }
    
    async def _create_embedding(
        self,
        input: str,
        model: str = "text-embedding-3-small",
        dimensions: Optional[int] = None,
    ) -> Dict:
        """Create an embedding."""
        client = await self.get_client()
        
        payload = {"input": input, "model": model}
        if dimensions:
            payload["dimensions"] = dimensions
        
        response = await self._retry_request(
            lambda: client.post(
                f"{self.base_url}/embeddings",
                json=payload,
                headers=self._get_headers(),
            )
        )
        response.raise_for_status()
        data = response.json()
        
        embedding = data.get("data", [{}])[0]
        return {
            "embedding": embedding.get("embedding"),
            "index": embedding.get("index"),
            "model": data.get("model"),
            "usage": data.get("usage"),
        }
    
    async def _generate_image(
        self,
        prompt: str,
        model: str = "dall-e-3",
        size: str = "1024x1024",
        quality: str = "standard",
        style: str = "vivid",
        n: int = 1,
    ) -> Dict:
        """Generate an image."""
        client = await self.get_client()
        
        payload = {
            "prompt": prompt,
            "model": model,
            "size": size,
            "quality": quality,
            "n": n,
        }
        if model == "dall-e-3":
            payload["style"] = style
        
        response = await self._retry_request(
            lambda: client.post(
                f"{self.base_url}/images/generations",
                json=payload,
                headers=self._get_headers(),
            )
        )
        response.raise_for_status()
        data = response.json()
        
        return {
            "images": [
                {
                    "url": img.get("url"),
                    "revised_prompt": img.get("revised_prompt"),
                }
                for img in data.get("data", [])
            ],
            "created": data.get("created"),
        }
    
    async def _list_models(self) -> Dict:
        """List available models."""
        client = await self.get_client()
        
        response = await client.get(
            f"{self.base_url}/models",
            headers=self._get_headers(),
        )
        response.raise_for_status()
        data = response.json()
        
        # Filter to relevant models
        relevant_prefixes = ("gpt-", "text-embedding", "dall-e", "whisper", "tts")
        
        return {
            "models": [
                {
                    "id": m.get("id"),
                    "owned_by": m.get("owned_by"),
                    "created": m.get("created"),
                }
                for m in data.get("data", [])
                if any(m.get("id", "").startswith(p) for p in relevant_prefixes)
            ]
        }
    
    # --- Resource Handlers ---
    
    async def _list_models_resource(self) -> Dict[str, Any]:
        """List models (for resource)."""
        return await self._list_models()


class AnthropicConnector(BaseConnector):
    """
    Anthropic API connector.
    
    Provides access to Claude models for chat completions.
    """
    
    name = "anthropic"
    display_name = "Anthropic"
    description = "Anthropic Claude API for AI completions"
    
    TOOL_MAPPING = {
        "chat_completion": {
            "name": "anthropic_chat_completion",
            "description": "Generate a chat completion using Claude models",
            "parameters": {
                "type": "object",
                "properties": {
                    "messages": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "role": {"type": "string", "enum": ["user", "assistant"]},
                                "content": {"type": "string"},
                            },
                        },
                        "description": "Conversation messages (no system message here)",
                    },
                    "system": {"type": "string", "description": "System prompt"},
                    "model": {"type": "string", "default": "claude-sonnet-4-20250514",
                              "description": "Model: claude-opus-4, claude-sonnet-4, claude-haiku-3.5"},
                    "max_tokens": {"type": "integer", "default": 4096},
                    "temperature": {"type": "number", "default": 0.7},
                    "top_p": {"type": "number"},
                    "top_k": {"type": "integer"},
                    "stop_sequences": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["messages"],
            },
            "handler": "_chat_completion",
        },
        "count_tokens": {
            "name": "anthropic_count_tokens",
            "description": "Count tokens for a prompt",
            "parameters": {
                "type": "object",
                "properties": {
                    "messages": {"type": "array", "description": "Messages to count"},
                    "system": {"type": "string", "description": "System prompt"},
                    "model": {"type": "string", "default": "claude-sonnet-4-20250514"},
                },
                "required": ["messages"],
            },
            "handler": "_count_tokens",
        },
    }
    
    RESOURCE_MAPPING = {
        "models": {
            "uri": "anthropic://models",
            "name": "Models",
            "description": "List available Anthropic models",
            "handler": "_list_models_resource",
        },
    }
    
    PROMPT_MAPPING = {
        "chat": {
            "name": "Chat Completion",
            "description": "Template for Claude chat completion",
            "arguments": [
                {"name": "message", "description": "User message"},
                {"name": "model", "description": "Model to use"},
            ],
            "template": """Send the following message to the user using Claude:

{message}

Use anthropic_chat_completion with model: {model}""",
        },
    }
    
    def __init__(self, config: ConnectorConfig):
        super().__init__(config)
        self.base_url = config.base_url or "https://api.anthropic.com/v1"
    
    def set_token(self, token: str) -> None:
        """Set the API token for this connector."""
        self.config.api_key = token
    
    def _get_headers(self) -> Dict[str, str]:
        """Get headers for Anthropic API requests."""
        return {
            "x-api-key": self.config.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
    
    def get_tools(self) -> List[ToolDefinition]:
        """Return Anthropic tools dynamically from TOOL_MAPPING."""
        tools = []
        for tool_key, tool_def in self.TOOL_MAPPING.items():
            handler = getattr(self, tool_def["handler"], None)
            if handler:
                tools.append(ToolDefinition(
                    name=tool_def["name"],
                    description=tool_def["description"],
                    parameters=tool_def["parameters"],
                    handler=handler,
                ))
        return tools
    
    async def get_tools_async(self) -> List[ToolDefinition]:
        """Return Anthropic tools (sync version for compatibility)."""
        return self.get_tools()
    
    def get_resources(self) -> List[ResourceDefinition]:
        """Return Anthropic resources from RESOURCE_MAPPING."""
        resources = []
        for res_key, res_def in self.RESOURCE_MAPPING.items():
            handler = getattr(self, res_def["handler"], None)
            if handler:
                resources.append(ResourceDefinition(
                    uri=res_def["uri"],
                    name=res_def["name"],
                    description=res_def["description"],
                    read_handler=handler,
                ))
        return resources
    
    def get_prompts(self) -> List[PromptDefinition]:
        """Return Anthropic prompts from PROMPT_MAPPING."""
        prompts = []
        for prompt_key, prompt_def in self.PROMPT_MAPPING.items():
            prompts.append(PromptDefinition(
                name=prompt_def["name"],
                description=prompt_def["description"],
                arguments=prompt_def.get("arguments", []),
                template=prompt_def.get("template", ""),
            ))
        return prompts
    
    async def read_resource(self, uri: str) -> Optional[Dict[str, Any]]:
        """Read an Anthropic resource by URI."""
        resources = self.get_resources()
        for resource in resources:
            if resource.uri == uri and resource.read_handler:
                try:
                    result = await resource.read_handler()
                    return result
                except Exception as e:
                    return {"error": str(e)}
        return None
    
    async def health_check(self) -> Tuple[bool, str]:
        """Check Anthropic API accessibility."""
        # Anthropic doesn't have a health endpoint, so we do a minimal request
        try:
            await self._count_tokens([{"role": "user", "content": "test"}])
            return True, "Anthropic API accessible"
        except Exception as e:
            return False, f"Anthropic API check failed: {e}"
    
    # --- Tool Implementations ---
    
    async def _chat_completion(
        self,
        messages: List[Dict[str, str]],
        system: Optional[str] = None,
        model: str = "claude-sonnet-4-20250514",
        max_tokens: int = 4096,
        temperature: float = 0.7,
        top_p: Optional[float] = None,
        top_k: Optional[int] = None,
        stop_sequences: Optional[List[str]] = None,
    ) -> Dict:
        """Generate a chat completion."""
        client = await self.get_client()
        
        payload = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if system:
            payload["system"] = system
        if top_p is not None:
            payload["top_p"] = top_p
        if top_k is not None:
            payload["top_k"] = top_k
        if stop_sequences:
            payload["stop_sequences"] = stop_sequences
        
        response = await self._retry_request(
            lambda: client.post(
                f"{self.base_url}/messages",
                json=payload,
                headers=self._get_headers(),
            )
        )
        response.raise_for_status()
        data = response.json()
        
        # Extract text content
        content_blocks = data.get("content", [])
        text_content = ""
        for block in content_blocks:
            if block.get("type") == "text":
                text_content += block.get("text", "")
        
        return {
            "content": text_content,
            "role": data.get("role"),
            "model": data.get("model"),
            "stop_reason": data.get("stop_reason"),
            "usage": data.get("usage"),
        }
    
    async def _count_tokens(
        self,
        messages: List[Dict[str, str]],
        system: Optional[str] = None,
        model: str = "claude-sonnet-4-20250514",
    ) -> Dict:
        """Count tokens for a prompt."""
        client = await self.get_client()
        
        payload = {"model": model, "messages": messages}
        if system:
            payload["system"] = system
        
        response = await client.post(
            f"{self.base_url}/messages/count_tokens",
            json=payload,
            headers=self._get_headers(),
        )
        response.raise_for_status()
        data = response.json()
        
        return {
            "input_tokens": data.get("input_tokens"),
        }
    
    # --- Resource Handlers ---
    
    async def _list_models_resource(self) -> Dict[str, Any]:
        """List models (for resource). Anthropic doesn't have a models endpoint, so return known models."""
        return {
            "models": [
                {"id": "claude-opus-4-20250514", "name": "Claude Opus 4"},
                {"id": "claude-sonnet-4-20250514", "name": "Claude Sonnet 4"},
                {"id": "claude-haiku-3-20240307", "name": "Claude Haiku 3"},
                {"id": "claude-3-opus-20240229", "name": "Claude 3 Opus"},
                {"id": "claude-3-sonnet-20240229", "name": "Claude 3 Sonnet"},
                {"id": "claude-3-haiku-20240307", "name": "Claude 3 Haiku"},
            ],
        }
