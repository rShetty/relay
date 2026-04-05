"""
Slack API Connector for Relay

Provides tools for:
- Messaging (post, update, delete, schedule)
- Channels (list, info, create, archive)
- Conversations (history, replies)
- Users (list, info)
- Reactions (add, remove)
- Files (upload, info)
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import httpx

from .github import BaseConnector, ConnectorConfig, ToolDefinition

logger = logging.getLogger(__name__)


class SlackConnector(BaseConnector):
    """
    Slack API connector.
    
    Supports both bot tokens (xoxb-) and user tokens (xoxp-).
    Implements Slack Web API methods as tools.
    """
    
    name = "slack"
    display_name = "Slack"
    description = "Slack API for messaging, channels, and team communication"
    
    def __init__(self, config: ConnectorConfig):
        super().__init__(config)
        self.base_url = config.base_url or "https://slack.com/api"
    
    def _get_headers(self) -> Dict[str, str]:
        """Get headers for Slack API requests."""
        return {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json; charset=utf-8",
        }
    
    def get_tools(self) -> List[ToolDefinition]:
        """Return Slack tools."""
        return [
            ToolDefinition(
                name="slack_post_message",
                description="Post a message to a Slack channel or user",
                parameters={
                    "type": "object",
                    "properties": {
                        "channel": {"type": "string", "description": "Channel ID or name (e.g., #general or C12345)"},
                        "text": {"type": "string", "description": "Message text"},
                        "blocks": {"type": "array", "description": "Slack Block Kit blocks for rich formatting"},
                        "attachments": {"type": "array", "description": "Message attachments"},
                        "thread_ts": {"type": "string", "description": "Parent message timestamp for threaded reply"},
                        "reply_broadcast": {"type": "boolean", "description": "Broadcast thread reply to channel"},
                        "unfurl_links": {"type": "boolean", "default": True},
                        "unfurl_media": {"type": "boolean", "default": True},
                    },
                    "required": ["channel", "text"],
                },
                handler=self._post_message,
            ),
            ToolDefinition(
                name="slack_update_message",
                description="Update an existing message",
                parameters={
                    "type": "object",
                    "properties": {
                        "channel": {"type": "string", "description": "Channel ID"},
                        "ts": {"type": "string", "description": "Timestamp of message to update"},
                        "text": {"type": "string", "description": "New message text"},
                        "blocks": {"type": "array", "description": "New blocks"},
                        "attachments": {"type": "array", "description": "New attachments"},
                    },
                    "required": ["channel", "ts", "text"],
                },
                handler=self._update_message,
            ),
            ToolDefinition(
                name="slack_delete_message",
                description="Delete a message",
                parameters={
                    "type": "object",
                    "properties": {
                        "channel": {"type": "string"},
                        "ts": {"type": "string", "description": "Timestamp of message to delete"},
                    },
                    "required": ["channel", "ts"],
                },
                handler=self._delete_message,
            ),
            ToolDefinition(
                name="slack_list_channels",
                description="List all channels in the workspace",
                parameters={
                    "type": "object",
                    "properties": {
                        "types": {"type": "string", "description": "Channel types: public_channel, private_channel, mpim, im"},
                        "exclude_archived": {"type": "boolean", "default": True},
                        "limit": {"type": "integer", "default": 100},
                    },
                },
                handler=self._list_channels,
            ),
            ToolDefinition(
                name="slack_get_channel_info",
                description="Get information about a channel",
                parameters={
                    "type": "object",
                    "properties": {
                        "channel": {"type": "string", "description": "Channel ID"},
                    },
                    "required": ["channel"],
                },
                handler=self._get_channel_info,
            ),
            ToolDefinition(
                name="slack_create_channel",
                description="Create a new channel",
                parameters={
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Channel name (lowercase, no spaces)"},
                        "is_private": {"type": "boolean", "default": False},
                        "description": {"type": "string"},
                        "team_id": {"type": "string", "description": "Workspace ID (for enterprise)"},
                    },
                    "required": ["name"],
                },
                handler=self._create_channel,
            ),
            ToolDefinition(
                name="slack_get_conversation_history",
                description="Get conversation history from a channel",
                parameters={
                    "type": "object",
                    "properties": {
                        "channel": {"type": "string"},
                        "limit": {"type": "integer", "default": 100},
                        "oldest": {"type": "string", "description": "Start of time range (timestamp)"},
                        "latest": {"type": "string", "description": "End of time range (timestamp)"},
                        "inclusive": {"type": "boolean", "default": False},
                    },
                    "required": ["channel"],
                },
                handler=self._get_conversation_history,
            ),
            ToolDefinition(
                name="slack_get_thread_replies",
                description="Get replies in a message thread",
                parameters={
                    "type": "object",
                    "properties": {
                        "channel": {"type": "string"},
                        "ts": {"type": "string", "description": "Parent message timestamp"},
                        "limit": {"type": "integer", "default": 100},
                    },
                    "required": ["channel", "ts"],
                },
                handler=self._get_thread_replies,
            ),
            ToolDefinition(
                name="slack_list_users",
                description="List all users in the workspace",
                parameters={
                    "type": "object",
                    "properties": {
                        "limit": {"type": "integer", "default": 100},
                        "include_locale": {"type": "boolean", "default": False},
                    },
                },
                handler=self._list_users,
            ),
            ToolDefinition(
                name="slack_get_user_info",
                description="Get information about a user",
                parameters={
                    "type": "object",
                    "properties": {
                        "user": {"type": "string", "description": "User ID"},
                    },
                    "required": ["user"],
                },
                handler=self._get_user_info,
            ),
            ToolDefinition(
                name="slack_add_reaction",
                description="Add a reaction to a message",
                parameters={
                    "type": "object",
                    "properties": {
                        "channel": {"type": "string"},
                        "timestamp": {"type": "string", "description": "Message timestamp"},
                        "name": {"type": "string", "description": "Emoji name without colons (e.g., thumbsup)"},
                    },
                    "required": ["channel", "timestamp", "name"],
                },
                handler=self._add_reaction,
            ),
            ToolDefinition(
                name="slack_remove_reaction",
                description="Remove a reaction from a message",
                parameters={
                    "type": "object",
                    "properties": {
                        "channel": {"type": "string"},
                        "timestamp": {"type": "string"},
                        "name": {"type": "string", "description": "Emoji name"},
                    },
                    "required": ["channel", "timestamp", "name"],
                },
                handler=self._remove_reaction,
            ),
            ToolDefinition(
                name="slack_search_messages",
                description="Search for messages in the workspace",
                parameters={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query"},
                        "sort": {"type": "string", "enum": ["score", "timestamp"], "default": "score"},
                        "count": {"type": "integer", "default": 20},
                    },
                    "required": ["query"],
                },
                handler=self._search_messages,
            ),
        ]
    
    # call_tool is inherited from BaseConnector
    
    async def health_check(self) -> Tuple[bool, str]:
        """Check Slack API accessibility."""
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
        except Exception as e:
            return False, f"Slack API check failed: {e}"
    
    async def _slack_api_call(
        self, 
        method: str, 
        payload: Optional[Dict] = None,
        params: Optional[Dict] = None,
    ) -> Dict:
        """Make a Slack API call."""
        client = await self.get_client()
        
        url = f"{self.base_url}/{method}"
        
        if payload:
            response = await self._retry_request(
                lambda: client.post(url, json=payload, headers=self._get_headers())
            )
        else:
            response = await self._retry_request(
                lambda: client.get(url, params=params, headers=self._get_headers())
            )
        
        data = response.json()
        
        if not data.get("ok"):
            raise Exception(f"Slack API error: {data.get('error', 'unknown')}")
        
        return data
    
    # --- Tool Implementations ---
    
    async def _post_message(
        self, 
        channel: str, 
        text: str,
        blocks: Optional[List] = None,
        attachments: Optional[List] = None,
        thread_ts: Optional[str] = None,
        reply_broadcast: bool = False,
        unfurl_links: bool = True,
        unfurl_media: bool = True,
    ) -> Dict:
        """Post a message."""
        payload = {
            "channel": channel,
            "text": text,
            "unfurl_links": unfurl_links,
            "unfurl_media": unfurl_media,
        }
        if blocks:
            payload["blocks"] = blocks
        if attachments:
            payload["attachments"] = attachments
        if thread_ts:
            payload["thread_ts"] = thread_ts
            payload["reply_broadcast"] = reply_broadcast
        
        data = await self._slack_api_call("chat.postMessage", payload=payload)
        
        return {
            "ok": True,
            "channel": data.get("channel"),
            "ts": data.get("ts"),
            "message": data.get("message"),
        }
    
    async def _update_message(
        self, 
        channel: str, 
        ts: str, 
        text: str,
        blocks: Optional[List] = None,
        attachments: Optional[List] = None,
    ) -> Dict:
        """Update a message."""
        payload = {"channel": channel, "ts": ts, "text": text}
        if blocks:
            payload["blocks"] = blocks
        if attachments:
            payload["attachments"] = attachments
        
        data = await self._slack_api_call("chat.update", payload=payload)
        
        return {
            "ok": True,
            "channel": data.get("channel"),
            "ts": data.get("ts"),
            "text": data.get("message", {}).get("text"),
        }
    
    async def _delete_message(self, channel: str, ts: str) -> Dict:
        """Delete a message."""
        await self._slack_api_call("chat.delete", payload={"channel": channel, "ts": ts})
        return {"ok": True, "deleted": True}
    
    async def _list_channels(
        self, 
        types: str = "public_channel,private_channel",
        exclude_archived: bool = True,
        limit: int = 100,
    ) -> Dict:
        """List channels."""
        params = {
            "types": types,
            "exclude_archived": str(exclude_archived).lower(),
            "limit": limit,
        }
        
        data = await self._slack_api_call("conversations.list", params=params)
        
        return {
            "channels": [
                {
                    "id": ch.get("id"),
                    "name": ch.get("name"),
                    "is_private": ch.get("is_private", False),
                    "is_archived": ch.get("is_archived", False),
                    "is_general": ch.get("is_general", False),
                    "topic": ch.get("topic", {}).get("value"),
                    "purpose": ch.get("purpose", {}).get("value"),
                    "num_members": ch.get("num_members", 0),
                }
                for ch in data.get("channels", [])
            ]
        }
    
    async def _get_channel_info(self, channel: str) -> Dict:
        """Get channel info."""
        data = await self._slack_api_call(
            "conversations.info", 
            params={"channel": channel}
        )
        
        ch = data.get("channel", {})
        return {
            "id": ch.get("id"),
            "name": ch.get("name"),
            "is_private": ch.get("is_private", False),
            "is_archived": ch.get("is_archived", False),
            "created": ch.get("created"),
            "creator": ch.get("creator"),
            "topic": ch.get("topic", {}).get("value"),
            "purpose": ch.get("purpose", {}).get("value"),
            "num_members": ch.get("num_members", 0),
        }
    
    async def _create_channel(
        self, 
        name: str,
        is_private: bool = False,
        description: Optional[str] = None,
        team_id: Optional[str] = None,
    ) -> Dict:
        """Create a channel."""
        payload = {"name": name, "is_private": is_private}
        if description:
            payload["description"] = description
        if team_id:
            payload["team_id"] = team_id
        
        data = await self._slack_api_call("conversations.create", payload=payload)
        
        ch = data.get("channel", {})
        return {
            "id": ch.get("id"),
            "name": ch.get("name"),
            "created": True,
        }
    
    async def _get_conversation_history(
        self,
        channel: str,
        limit: int = 100,
        oldest: Optional[str] = None,
        latest: Optional[str] = None,
        inclusive: bool = False,
    ) -> Dict:
        """Get conversation history."""
        params = {"channel": channel, "limit": limit, "inclusive": str(inclusive).lower()}
        if oldest:
            params["oldest"] = oldest
        if latest:
            params["latest"] = latest
        
        data = await self._slack_api_call("conversations.history", params=params)
        
        return {
            "messages": [
                {
                    "type": msg.get("type"),
                    "user": msg.get("user"),
                    "text": msg.get("text"),
                    "ts": msg.get("ts"),
                    "thread_ts": msg.get("thread_ts"),
                    "reply_count": msg.get("reply_count", 0),
                    "reactions": [
                        {"name": r.get("name"), "count": r.get("count")}
                        for r in msg.get("reactions", [])
                    ],
                }
                for msg in data.get("messages", [])
            ],
            "has_more": data.get("has_more", False),
        }
    
    async def _get_thread_replies(
        self, 
        channel: str, 
        ts: str,
        limit: int = 100,
    ) -> Dict:
        """Get thread replies."""
        data = await self._slack_api_call(
            "conversations.replies",
            params={"channel": channel, "ts": ts, "limit": limit}
        )
        
        return {
            "messages": [
                {
                    "user": msg.get("user"),
                    "text": msg.get("text"),
                    "ts": msg.get("ts"),
                }
                for msg in data.get("messages", [])
            ],
            "has_more": data.get("has_more", False),
        }
    
    async def _list_users(self, limit: int = 100, include_locale: bool = False) -> Dict:
        """List users."""
        data = await self._slack_api_call(
            "users.list",
            params={"limit": limit, "include_locale": str(include_locale).lower()}
        )
        
        return {
            "members": [
                {
                    "id": user.get("id"),
                    "name": user.get("name"),
                    "real_name": user.get("real_name"),
                    "display_name": user.get("profile", {}).get("display_name"),
                    "email": user.get("profile", {}).get("email"),
                    "is_bot": user.get("is_bot", False),
                    "is_admin": user.get("is_admin", False),
                    "is_owner": user.get("is_owner", False),
                    "tz": user.get("tz"),
                }
                for user in data.get("members", [])
                if not user.get("deleted") and not user.get("is_bot")
            ]
        }
    
    async def _get_user_info(self, user: str) -> Dict:
        """Get user info."""
        data = await self._slack_api_call(
            "users.info",
            params={"user": user}
        )
        
        u = data.get("user", {})
        return {
            "id": u.get("id"),
            "name": u.get("name"),
            "real_name": u.get("real_name"),
            "display_name": u.get("profile", {}).get("display_name"),
            "email": u.get("profile", {}).get("email"),
            "title": u.get("profile", {}).get("title"),
            "phone": u.get("profile", {}).get("phone"),
            "tz": u.get("tz"),
            "tz_label": u.get("tz_label"),
            "is_bot": u.get("is_bot", False),
            "is_admin": u.get("is_admin", False),
            "is_owner": u.get("is_owner", False),
        }
    
    async def _add_reaction(self, channel: str, timestamp: str, name: str) -> Dict:
        """Add reaction."""
        await self._slack_api_call(
            "reactions.add",
            payload={"channel": channel, "timestamp": timestamp, "name": name}
        )
        return {"ok": True, "reaction": name}
    
    async def _remove_reaction(self, channel: str, timestamp: str, name: str) -> Dict:
        """Remove reaction."""
        await self._slack_api_call(
            "reactions.remove",
            payload={"channel": channel, "timestamp": timestamp, "name": name}
        )
        return {"ok": True, "removed": name}
    
    async def _search_messages(self, query: str, sort: str = "score", count: int = 20) -> Dict:
        """Search messages."""
        data = await self._slack_api_call(
            "search.messages",
            params={"query": query, "sort": sort, "count": count}
        )
        
        return {
            "total": data.get("messages", {}).get("total", 0),
            "matches": [
                {
                    "type": msg.get("type"),
                    "user": msg.get("user"),
                    "username": msg.get("username"),
                    "text": msg.get("text"),
                    "ts": msg.get("ts"),
                    "channel": msg.get("channel", {}).get("name"),
                    "permalink": msg.get("permalink"),
                }
                for msg in data.get("messages", {}).get("matches", [])
            ]
        }
