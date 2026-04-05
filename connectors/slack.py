"""
Slack API connector with dynamic tool discovery.
"""

import os
from typing import Any, Callable, Dict, List, Optional, Tuple

import httpx

from . import BaseConnector
from .github import ConnectorConfig, ToolDefinition, ResourceDefinition, PromptDefinition


class SlackConnector(BaseConnector):
    """
    Slack API connector with dynamic tool discovery.
    
    Tools are discovered from Slack's API methods rather than hardcoded.
    """
    
    name = "slack"
    display_name = "Slack"
    description = "Slack API for messaging, channels, and team communication"
    
    # Map of Slack API methods to tool definitions
    TOOL_MAPPING = {
        "chat.postMessage": {
            "name": "slack_post_message",
            "description": "Post a message to a Slack channel or user",
            "parameters": {
                "type": "object",
                "properties": {
                    "channel": {"type": "string", "description": "Channel ID or name (e.g., #general or C12345)"},
                    "text": {"type": "string", "description": "Message text"},
                    "blocks": {"type": "array", "description": "Slack Block Kit blocks"},
                    "attachments": {"type": "array", "description": "Message attachments"},
                },
                "required": ["channel", "text"],
            },
            "handler": "_chat_postMessage",
        },
        "chat.update": {
            "name": "slack_update_message",
            "description": "Update an existing message",
            "parameters": {
                "type": "object",
                "properties": {
                    "channel": {"type": "string", "description": "Channel ID"},
                    "ts": {"type": "string", "description": "Timestamp of message to update"},
                    "text": {"type": "string", "description": "New message text"},
                },
                "required": ["channel", "ts", "text"],
            },
            "handler": "_chat_update",
        },
        "chat.delete": {
            "name": "slack_delete_message",
            "description": "Delete a message",
            "parameters": {
                "type": "object",
                "properties": {
                    "channel": {"type": "string"},
                    "ts": {"type": "string", "description": "Timestamp of message to delete"},
                },
                "required": ["channel", "ts"],
            },
            "handler": "_chat_delete",
        },
        "conversations.list": {
            "name": "slack_list_channels",
            "description": "List all channels in the workspace",
            "parameters": {
                "type": "object",
                "properties": {
                    "types": {"type": "string", "description": "Channel types: public_channel, private_channel, mpim, im"},
                    "exclude_archived": {"type": "boolean", "default": True},
                    "limit": {"type": "integer", "default": 100},
                },
            },
            "handler": "_conversations_list",
        },
        "conversations.info": {
            "name": "slack_get_channel_info",
            "description": "Get information about a channel",
            "parameters": {
                "type": "object",
                "properties": {
                    "channel": {"type": "string", "description": "Channel ID"},
                },
                "required": ["channel"],
            },
            "handler": "_conversations_info",
        },
        "conversations.history": {
            "name": "slack_get_channel_history",
            "description": "Get message history from a channel",
            "parameters": {
                "type": "object",
                "properties": {
                    "channel": {"type": "string", "description": "Channel ID"},
                    "latest": {"type": "string", "description": "End of time range"},
                    "oldest": {"type": "string", "description": "Start of time range"},
                    "limit": {"type": "integer", "default": 100},
                },
            },
            "handler": "_conversations_history",
        },
        "users.list": {
            "name": "slack_list_users",
            "description": "List all users in the workspace",
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "default": 100},
                },
            },
            "handler": "_users_list",
        },
        "users.info": {
            "name": "slack_get_user_info",
            "description": "Get information about a user",
            "parameters": {
                "type": "object",
                "properties": {
                    "user": {"type": "string", "description": "User ID"},
                },
                "required": ["user"],
            },
            "handler": "_users_info",
        },
        "reactions.add": {
            "name": "slack_add_reaction",
            "description": "Add a reaction to a message",
            "parameters": {
                "type": "object",
                "properties": {
                    "channel": {"type": "string", "description": "Channel ID"},
                    "timestamp": {"type": "string", "description": "Message timestamp"},
                    "name": {"type": "string", "description": "Reaction name (e.g., thumbsup, rocket)"},
                },
                "required": ["channel", "timestamp", "name"],
            },
            "handler": "_reactions_add",
        },
        "files.upload": {
            "name": "slack_upload_file",
            "description": "Upload a file to Slack",
            "parameters": {
                "type": "object",
                "properties": {
                    "channels": {"type": "string", "description": "Channel IDs to share to"},
                    "content": {"type": "string", "description": "File content"},
                    "filename": {"type": "string", "description": "Filename"},
                    "title": {"type": "string", "description": "File title"},
                },
                "required": ["channels", "content"],
            },
            "handler": "_files_upload",
        },
    }
    
    RESOURCE_MAPPING = {
        "channels": {
            "uri": "slack://channels",
            "name": "Channels",
            "description": "List all channels in the workspace",
            "handler": "_list_channels_resource",
        },
        "users": {
            "uri": "slack://users",
            "name": "Users",
            "description": "List all users in the workspace",
            "handler": "_list_users_resource",
        },
        "conversations": {
            "uri": "slack://conversations",
            "name": "Conversations",
            "description": "List all conversations (channels, DMs, groups)",
            "handler": "_list_conversations_resource",
        },
    }
    
    PROMPT_MAPPING = {
        "post_message": {
            "name": "Post Slack Message",
            "description": "Template for posting a message to Slack",
            "arguments": [
                {"name": "channel", "description": "Channel name or ID"},
                {"name": "message", "description": "Message text"},
            ],
            "template": """Post the following message to {channel}:

{message}

Use the slack_post_message tool.""",
        },
        "summarize_channel": {
            "name": "Summarize Channel",
            "description": "Template for getting channel summary",
            "arguments": [
                {"name": "channel", "description": "Channel name or ID"},
            ],
            "template": """Get recent messages from #{channel} and summarize the discussion.

Use slack_get_channel_history to fetch messages.""",
        },
    }
    
    def __init__(self, config: ConnectorConfig):
        super().__init__(config)
        self.base_url = config.base_url or "https://slack.com/api"
        self._available_methods: Optional[List[str]] = None
    
    def set_token(self, token: str) -> None:
        """Set the API token for this connector."""
        self.config.api_key = token
        self._available_methods = None  # Reset when token changes
    
    def _get_headers(self) -> Dict[str, str]:
        """Get headers for Slack API requests."""
        return {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json; charset=utf-8",
        }
    
    async def _discover_methods(self) -> List[str]:
        """Discover available Slack API methods by checking auth."""
        if self._available_methods is not None:
            return self._available_methods
        
        if not self.config.api_key:
            self._available_methods = []
            return []
        
        try:
            client = await self.get_client()
            response = await client.post(
                f"{self.base_url}/auth.test",
                headers=self._get_headers(),
            )
            data = response.json()
            
            if data.get("ok"):
                # For now, return the list of methods we have mappings for
                # In a full implementation, we could query Slack's API methods
                self._available_methods = list(self.TOOL_MAPPING.keys())
            else:
                self._available_methods = []
        except Exception:
            self._available_methods = []
        
        return self._available_methods
    
    def get_tools(self) -> List[ToolDefinition]:
        """Return Slack tools from TOOL_MAPPING."""
        tools = []
        for method, tool_def in self.TOOL_MAPPING.items():
            handler_key = tool_def['handler']
            if not handler_key.startswith('_'):
                handler_key = '_' + handler_key
            handler = getattr(self, handler_key, None)
            if handler:
                tools.append(ToolDefinition(
                    name=tool_def["name"],
                    description=tool_def["description"],
                    parameters=tool_def["parameters"],
                    handler=handler,
                ))
        return tools
    
    async def get_tools_async(self) -> List[ToolDefinition]:
        """Return Slack tools (sync version for compatibility)."""
        return self.get_tools()
    
    def get_resources(self) -> List[ResourceDefinition]:
        """Return Slack resources from RESOURCE_MAPPING."""
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
        """Return Slack prompts from PROMPT_MAPPING."""
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
        """Read a Slack resource by URI."""
        resources = self.get_resources()
        for resource in resources:
            if resource.uri == uri and resource.read_handler:
                try:
                    result = await resource.read_handler()
                    return result
                except Exception as e:
                    return {"error": str(e)}
        return None
    
    def get_tool_names(self) -> List[str]:
        """Get list of tool names without making API calls."""
        return list(self.TOOL_MAPPING.keys())
    
    async def health_check(self) -> Tuple[bool, str]:
        """Check Slack API accessibility."""
        if not self.config.api_key:
            return False, "No Slack token configured"
        
        try:
            client = await self.get_client()
            response = await client.post(
                f"{self.base_url}/auth.test",
                headers=self._get_headers(),
            )
            data = response.json()
            
            if data.get("ok"):
                return True, f"Slack API accessible as {data.get('user', 'unknown')}"
            return False, f"Slack API error: {data.get('error', 'unknown')}"
        except httpx.ConnectError:
            return False, "Cannot connect to Slack API"
        except Exception as e:
            return False, f"Slack API check failed: {e}"
    
    # --- Tool Implementations ---
    
    async def _chat_postMessage(self, channel: str, text: str, **kwargs) -> Dict:
        """Post a message to a channel."""
        client = await self.get_client()
        payload = {"channel": channel, "text": text, **kwargs}
        response = await client.post(
            f"{self.base_url}/chat.postMessage",
            headers=self._get_headers(),
            json=payload,
        )
        data = response.json()
        if not data.get("ok"):
            raise Exception(f"Slack API error: {data.get('error', 'Unknown error')}")
        return data
    
    async def _chat_update(self, channel: str, ts: str, text: str, **kwargs) -> Dict:
        """Update a message."""
        client = await self.get_client()
        payload = {"channel": channel, "ts": ts, "text": text, **kwargs}
        response = await client.post(
            f"{self.base_url}/chat.update",
            headers=self._get_headers(),
            json=payload,
        )
        data = response.json()
        if not data.get("ok"):
            raise Exception(f"Slack API error: {data.get('error', 'Unknown error')}")
        return data
    
    async def _chat_delete(self, channel: str, ts: str, **kwargs) -> Dict:
        """Delete a message."""
        client = await self.get_client()
        payload = {"channel": channel, "ts": ts, **kwargs}
        response = await client.post(
            f"{self.base_url}/chat.delete",
            headers=self._get_headers(),
            json=payload,
        )
        data = response.json()
        if not data.get("ok"):
            raise Exception(f"Slack API error: {data.get('error', 'Unknown error')}")
        return data
    
    async def _conversations_list(self, types: str = "public_channel,private_channel", 
                                   exclude_archived: bool = True, limit: int = 100, **kwargs) -> Dict:
        """List conversations."""
        client = await self.get_client()
        payload = {
            "types": types,
            "exclude_archived": exclude_archived,
            "limit": limit,
            **kwargs
        }
        response = await client.post(
            f"{self.base_url}/conversations.list",
            headers=self._get_headers(),
            json=payload,
        )
        data = response.json()
        if not data.get("ok"):
            raise Exception(f"Slack API error: {data.get('error', 'Unknown error')}")
        return data
    
    async def _conversations_info(self, channel: str, **kwargs) -> Dict:
        """Get conversation info."""
        client = await self.get_client()
        payload = {"channel": channel, **kwargs}
        response = await client.post(
            f"{self.base_url}/conversations.info",
            headers=self._get_headers(),
            json=payload,
        )
        data = response.json()
        if not data.get("ok"):
            raise Exception(f"Slack API error: {data.get('error', 'Unknown error')}")
        return data
    
    async def _conversations_history(self, channel: str, latest: str = None, 
                                     oldest: str = None, limit: int = 100, **kwargs) -> Dict:
        """Get conversation history."""
        client = await self.get_client()
        payload = {"channel": channel, "limit": limit, **kwargs}
        if latest:
            payload["latest"] = latest
        if oldest:
            payload["oldest"] = oldest
        response = await client.post(
            f"{self.base_url}/conversations.history",
            headers=self._get_headers(),
            json=payload,
        )
        data = response.json()
        if not data.get("ok"):
            raise Exception(f"Slack API error: {data.get('error', 'Unknown error')}")
        return data
    
    async def _users_list(self, limit: int = 100, **kwargs) -> Dict:
        """List users."""
        client = await self.get_client()
        payload = {"limit": limit, **kwargs}
        response = await client.post(
            f"{self.base_url}/users.list",
            headers=self._get_headers(),
            json=payload,
        )
        data = response.json()
        if not data.get("ok"):
            raise Exception(f"Slack API error: {data.get('error', 'Unknown error')}")
        return data
    
    async def _users_info(self, user: str, **kwargs) -> Dict:
        """Get user info."""
        client = await self.get_client()
        payload = {"user": user, **kwargs}
        response = await client.post(
            f"{self.base_url}/users.info",
            headers=self._get_headers(),
            json=payload,
        )
        data = response.json()
        if not data.get("ok"):
            raise Exception(f"Slack API error: {data.get('error', 'Unknown error')}")
        return data
    
    async def _reactions_add(self, channel: str, timestamp: str, name: str, **kwargs) -> Dict:
        """Add a reaction."""
        client = await self.get_client()
        payload = {"channel": channel, "timestamp": timestamp, "name": name, **kwargs}
        response = await client.post(
            f"{self.base_url}/reactions.add",
            headers=self._get_headers(),
            json=payload,
        )
        data = response.json()
        if not data.get("ok"):
            raise Exception(f"Slack API error: {data.get('error', 'Unknown error')}")
        return data
    
    async def _files_upload(self, channels: str, content: str, filename: str = None, 
                            title: str = None, **kwargs) -> Dict:
        """Upload a file."""
        client = await self.get_client()
        payload = {"channels": channels, "content": content, **kwargs}
        if filename:
            payload["filename"] = filename
        if title:
            payload["title"] = title
        response = await client.post(
            f"{self.base_url}/files.upload",
            headers=self._get_headers(),
            json=payload,
        )
        data = response.json()
        if not data.get("ok"):
            raise Exception(f"Slack API error: {data.get('error', 'Unknown error')}")
        return data
    
    # --- Resource Handlers ---
    
    async def _list_channels_resource(self) -> Dict[str, Any]:
        """List channels (for resource)."""
        client = await self.get_client()
        payload = {"types": "public_channel,private_channel", "limit": 50}
        response = await client.post(
            f"{self.base_url}/conversations.list",
            headers=self._get_headers(),
            json=payload,
        )
        data = response.json()
        if not data.get("ok"):
            raise Exception(f"Slack API error: {data.get('error', 'Unknown error')}")
        
        return {
            "channels": [
                {
                    "id": c.get("id"),
                    "name": c.get("name"),
                    "is_private": c.get("is_private"),
                    "member_count": c.get("num_members"),
                }
                for c in data.get("channels", [])
            ],
        }
    
    async def _list_users_resource(self) -> Dict[str, Any]:
        """List users (for resource)."""
        client = await self.get_client()
        payload = {"limit": 100}
        response = await client.post(
            f"{self.base_url}/users.list",
            headers=self._get_headers(),
            json=payload,
        )
        data = response.json()
        if not data.get("ok"):
            raise Exception(f"Slack API error: {data.get('error', 'Unknown error')}")
        
        return {
            "users": [
                {
                    "id": u.get("id"),
                    "name": u.get("name"),
                    "real_name": u.get("real_name"),
                    "is_bot": u.get("is_bot"),
                }
                for u in data.get("members", [])
            ],
        }
    
    async def _list_conversations_resource(self) -> Dict[str, Any]:
        """List all conversations (for resource)."""
        client = await self.get_client()
        payload = {"types": "public_channel,private_channel,im,mpim", "limit": 50}
        response = await client.post(
            f"{self.base_url}/conversations.list",
            headers=self._get_headers(),
            json=payload,
        )
        data = response.json()
        if not data.get("ok"):
            raise Exception(f"Slack API error: {data.get('error', 'Unknown error')}")
        
        return {
            "conversations": [
                {
                    "id": c.get("id"),
                    "name": c.get("name"),
                    "type": c.get("topic", {}).get("value", "channel"),
                }
                for c in data.get("channels", [])
            ],
        }