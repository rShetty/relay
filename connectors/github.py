"""
Third-Party Service Connectors for Relay

Each connector implements:
- Authentication handling for the specific service
- Tool implementations that map MCP tool calls to API calls
- Error handling and rate limit awareness
- Response normalization

Connectors can be used by:
1. The Backend Manager for direct API calls
2. As standalone tools if needed
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import httpx

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Base Connector
# -----------------------------------------------------------------------------

@dataclass
class ToolDefinition:
    """Definition of a tool provided by a connector."""
    name: str
    description: str
    parameters: Dict[str, Any]  # JSON Schema
    handler: Callable
    requires_auth: bool = True


@dataclass 
class ConnectorConfig:
    """Configuration for a connector."""
    api_key: Optional[str] = None
    api_secret: Optional[str] = None
    base_url: Optional[str] = None
    timeout: int = 30
    max_retries: int = 3
    rate_limit_rpm: int = 60  # Requests per minute


class BaseConnector(ABC):
    """
    Abstract base class for all third-party connectors.
    
    Subclasses must implement:
    - get_tools(): Return list of available tools
    - get_tool_schema(): Return JSON Schema for a tool
    - Health check logic
    """
    
    name: str = "base"
    display_name: str = "Base Connector"
    description: str = "Base connector class"
    
    def __init__(self, config: ConnectorConfig):
        self.config = config
        self._client: Optional[httpx.AsyncClient] = None
        self._rate_limit_timestamps: List[float] = []
    
    async def get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.config.timeout, read=300.0),
                follow_redirects=True,
            )
        return self._client
    
    async def close(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    def _check_rate_limit(self) -> bool:
        """Check if we're within rate limits."""
        now = time.time()
        # Remove timestamps older than 1 minute
        self._rate_limit_timestamps = [
            ts for ts in self._rate_limit_timestamps 
            if ts > now - 60
        ]
        
        if len(self._rate_limit_timestamps) >= self.config.rate_limit_rpm:
            return False
        
        self._rate_limit_timestamps.append(now)
        return True
    
    @abstractmethod
    def get_tools(self) -> List[ToolDefinition]:
        """Return list of tools provided by this connector."""
        pass

    @abstractmethod
    async def health_check(self) -> Tuple[bool, str]:
        """Check if the service is accessible."""
        pass

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Tuple[bool, Any]:
        """
        Dispatch a tool call to the appropriate handler.

        Looks up the tool by name in get_tools() and invokes its handler.
        Subclasses can override for custom dispatch logic.
        """
        if not self._check_rate_limit():
            return False, {"error": "Rate limit exceeded", "retry_after": 60}

        # Build name→handler index once per call (tools list is small)
        tool_map: Dict[str, ToolDefinition] = {t.name: t for t in self.get_tools()}
        tool = tool_map.get(tool_name)
        if tool is None:
            return False, {"error": f"Unknown tool: {tool_name}"}

        try:
            result = await tool.handler(**arguments)
            return True, result
        except Exception as e:
            logger.error(f"Tool '{tool_name}' raised: {e}")
            return False, {"error": str(e)}
    
    async def _retry_request(
        self,
        request_fn: Callable,
        max_retries: Optional[int] = None,
    ) -> httpx.Response:
        """Execute request with retry logic."""
        retries = max_retries or self.config.max_retries
        last_error = None
        
        for attempt in range(retries + 1):
            try:
                return await request_fn()
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429:  # Rate limited
                    retry_after = int(e.response.headers.get("Retry-After", 60))
                    await asyncio.sleep(min(retry_after, 60))
                elif e.response.status_code >= 500:  # Server error
                    await asyncio.sleep(2 ** attempt)
                else:
                    raise
                last_error = e
            except httpx.RequestError as e:
                await asyncio.sleep(2 ** attempt)
                last_error = e
        
        raise last_error or Exception("Max retries exceeded")


# -----------------------------------------------------------------------------
# GitHub Connector
# -----------------------------------------------------------------------------

class GitHubConnector(BaseConnector):
    """
    GitHub API connector.
    
    Provides tools for:
    - Repository management (list, get, create)
    - Issues (list, get, create, update)
    - Pull requests (list, get, create, merge)
    - Code search
    - File operations
    """
    
    name = "github"
    display_name = "GitHub"
    description = "GitHub API for repositories, issues, PRs, and code"
    
    def __init__(self, config: ConnectorConfig):
        super().__init__(config)
        self.base_url = config.base_url or "https://api.github.com"
    
    def _get_headers(self) -> Dict[str, str]:
        """Get headers for GitHub API requests."""
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers
    
    def get_tools(self) -> List[ToolDefinition]:
        """Return GitHub tools."""
        return [
            ToolDefinition(
                name="github_search_repositories",
                description="Search GitHub repositories",
                parameters={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query"},
                        "sort": {"type": "string", "enum": ["stars", "forks", "updated"], "default": "best-match"},
                        "order": {"type": "string", "enum": ["asc", "desc"], "default": "desc"},
                        "limit": {"type": "integer", "default": 10, "maximum": 100},
                    },
                    "required": ["query"],
                },
                handler=self._search_repositories,
            ),
            ToolDefinition(
                name="github_get_repository",
                description="Get details of a GitHub repository",
                parameters={
                    "type": "object",
                    "properties": {
                        "owner": {"type": "string", "description": "Repository owner"},
                        "repo": {"type": "string", "description": "Repository name"},
                    },
                    "required": ["owner", "repo"],
                },
                handler=self._get_repository,
            ),
            ToolDefinition(
                name="github_list_issues",
                description="List issues in a repository",
                parameters={
                    "type": "object",
                    "properties": {
                        "owner": {"type": "string"},
                        "repo": {"type": "string"},
                        "state": {"type": "string", "enum": ["open", "closed", "all"], "default": "open"},
                        "labels": {"type": "string", "description": "Comma-separated label names"},
                        "limit": {"type": "integer", "default": 30},
                    },
                    "required": ["owner", "repo"],
                },
                handler=self._list_issues,
            ),
            ToolDefinition(
                name="github_create_issue",
                description="Create a new issue in a repository",
                parameters={
                    "type": "object",
                    "properties": {
                        "owner": {"type": "string"},
                        "repo": {"type": "string"},
                        "title": {"type": "string"},
                        "body": {"type": "string"},
                        "labels": {"type": "array", "items": {"type": "string"}},
                        "assignees": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["owner", "repo", "title"],
                },
                handler=self._create_issue,
            ),
            ToolDefinition(
                name="github_list_pull_requests",
                description="List pull requests in a repository",
                parameters={
                    "type": "object",
                    "properties": {
                        "owner": {"type": "string"},
                        "repo": {"type": "string"},
                        "state": {"type": "string", "enum": ["open", "closed", "all"], "default": "open"},
                        "limit": {"type": "integer", "default": 30},
                    },
                    "required": ["owner", "repo"],
                },
                handler=self._list_pull_requests,
            ),
            ToolDefinition(
                name="github_create_pull_request",
                description="Create a new pull request",
                parameters={
                    "type": "object",
                    "properties": {
                        "owner": {"type": "string"},
                        "repo": {"type": "string"},
                        "title": {"type": "string"},
                        "body": {"type": "string"},
                        "head": {"type": "string", "description": "Branch name for PR source"},
                        "base": {"type": "string", "description": "Branch name for PR target", "default": "main"},
                        "draft": {"type": "boolean", "default": False},
                    },
                    "required": ["owner", "repo", "title", "head"],
                },
                handler=self._create_pull_request,
            ),
            ToolDefinition(
                name="github_get_file_contents",
                description="Get contents of a file in a repository",
                parameters={
                    "type": "object",
                    "properties": {
                        "owner": {"type": "string"},
                        "repo": {"type": "string"},
                        "path": {"type": "string", "description": "File path in repository"},
                        "ref": {"type": "string", "description": "Branch/commit ref"},
                    },
                    "required": ["owner", "repo", "path"],
                },
                handler=self._get_file_contents,
            ),
            ToolDefinition(
                name="github_create_or_update_file",
                description="Create or update a file in a repository",
                parameters={
                    "type": "object",
                    "properties": {
                        "owner": {"type": "string"},
                        "repo": {"type": "string"},
                        "path": {"type": "string"},
                        "message": {"type": "string", "description": "Commit message"},
                        "content": {"type": "string", "description": "File content"},
                        "branch": {"type": "string"},
                        "sha": {"type": "string", "description": "Required for updates - the blob SHA"},
                    },
                    "required": ["owner", "repo", "path", "message", "content", "branch"],
                },
                handler=self._create_or_update_file,
            ),
            ToolDefinition(
                name="github_search_code",
                description="Search code in GitHub repositories",
                parameters={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query (supports GitHub code search syntax)"},
                        "limit": {"type": "integer", "default": 30},
                    },
                    "required": ["query"],
                },
                handler=self._search_code,
            ),
        ]
    
    # call_tool is inherited from BaseConnector
    
    async def health_check(self) -> Tuple[bool, str]:
        """Check GitHub API accessibility."""
        try:
            client = await self.get_client()
            response = await client.get(
                f"{self.base_url}/rate_limit",
                headers=self._get_headers(),
            )
            if response.status_code == 200:
                data = response.json()
                remaining = data.get("resources", {}).get("core", {}).get("remaining", 0)
                return True, f"GitHub API accessible, {remaining} requests remaining"
            return False, f"GitHub API returned status {response.status_code}"
        except Exception as e:
            return False, f"GitHub API check failed: {e}"
    
    # --- Tool Implementations ---
    
    async def _search_repositories(self, query: str, sort: str = "best-match", 
                                    order: str = "desc", limit: int = 10) -> Dict:
        """Search GitHub repositories."""
        client = await self.get_client()
        
        response = await self._retry_request(
            lambda: client.get(
                f"{self.base_url}/search/repositories",
                params={"q": query, "sort": sort, "order": order, "per_page": limit},
                headers=self._get_headers(),
            )
        )
        response.raise_for_status()
        data = response.json()
        
        return {
            "total_count": data.get("total_count", 0),
            "repositories": [
                {
                    "full_name": repo.get("full_name"),
                    "description": repo.get("description"),
                    "stars": repo.get("stargazers_count"),
                    "forks": repo.get("forks_count"),
                    "language": repo.get("language"),
                    "url": repo.get("html_url"),
                    "is_private": repo.get("private", False),
                }
                for repo in data.get("items", [])
            ],
        }
    
    async def _get_repository(self, owner: str, repo: str) -> Dict:
        """Get repository details."""
        client = await self.get_client()
        
        response = await self._retry_request(
            lambda: client.get(
                f"{self.base_url}/repos/{owner}/{repo}",
                headers=self._get_headers(),
            )
        )
        response.raise_for_status()
        data = response.json()
        
        return {
            "full_name": data.get("full_name"),
            "description": data.get("description"),
            "stars": data.get("stargazers_count"),
            "forks": data.get("forks_count"),
            "watchers": data.get("watchers_count"),
            "open_issues": data.get("open_issues_count"),
            "default_branch": data.get("default_branch"),
            "language": data.get("language"),
            "license": data.get("license", {}).get("spdx_id") if data.get("license") else None,
            "url": data.get("html_url"),
            "clone_url": data.get("clone_url"),
            "created_at": data.get("created_at"),
            "updated_at": data.get("updated_at"),
            "pushed_at": data.get("pushed_at"),
        }
    
    async def _list_issues(self, owner: str, repo: str, state: str = "open",
                           labels: Optional[str] = None, limit: int = 30) -> Dict:
        """List issues in a repository."""
        client = await self.get_client()
        
        params = {"state": state, "per_page": limit}
        if labels:
            params["labels"] = labels
        
        response = await self._retry_request(
            lambda: client.get(
                f"{self.base_url}/repos/{owner}/{repo}/issues",
                params=params,
                headers=self._get_headers(),
            )
        )
        response.raise_for_status()
        data = response.json()
        
        return {
            "issues": [
                {
                    "number": issue.get("number"),
                    "title": issue.get("title"),
                    "state": issue.get("state"),
                    "user": issue.get("user", {}).get("login"),
                    "labels": [l.get("name") for l in issue.get("labels", [])],
                    "comments": issue.get("comments"),
                    "created_at": issue.get("created_at"),
                    "updated_at": issue.get("updated_at"),
                    "url": issue.get("html_url"),
                }
                for issue in data
                if "pull_request" not in issue  # Exclude PRs
            ]
        }
    
    async def _create_issue(self, owner: str, repo: str, title: str,
                            body: Optional[str] = None,
                            labels: Optional[List[str]] = None,
                            assignees: Optional[List[str]] = None) -> Dict:
        """Create a new issue."""
        client = await self.get_client()
        
        payload = {"title": title}
        if body:
            payload["body"] = body
        if labels:
            payload["labels"] = labels
        if assignees:
            payload["assignees"] = assignees
        
        response = await self._retry_request(
            lambda: client.post(
                f"{self.base_url}/repos/{owner}/{repo}/issues",
                json=payload,
                headers=self._get_headers(),
            )
        )
        response.raise_for_status()
        data = response.json()
        
        return {
            "number": data.get("number"),
            "title": data.get("title"),
            "url": data.get("html_url"),
            "created": True,
        }
    
    async def _list_pull_requests(self, owner: str, repo: str, state: str = "open",
                                   limit: int = 30) -> Dict:
        """List pull requests."""
        client = await self.get_client()
        
        response = await self._retry_request(
            lambda: client.get(
                f"{self.base_url}/repos/{owner}/{repo}/pulls",
                params={"state": state, "per_page": limit},
                headers=self._get_headers(),
            )
        )
        response.raise_for_status()
        data = response.json()
        
        return {
            "pull_requests": [
                {
                    "number": pr.get("number"),
                    "title": pr.get("title"),
                    "state": pr.get("state"),
                    "user": pr.get("user", {}).get("login"),
                    "head": pr.get("head", {}).get("ref"),
                    "base": pr.get("base", {}).get("ref"),
                    "draft": pr.get("draft", False),
                    "mergeable": pr.get("mergeable"),
                    "url": pr.get("html_url"),
                }
                for pr in data
            ]
        }
    
    async def _create_pull_request(self, owner: str, repo: str, title: str,
                                    head: str, base: str = "main",
                                    body: Optional[str] = None,
                                    draft: bool = False) -> Dict:
        """Create a pull request."""
        client = await self.get_client()
        
        payload = {
            "title": title,
            "head": head,
            "base": base,
            "draft": draft,
        }
        if body:
            payload["body"] = body
        
        response = await self._retry_request(
            lambda: client.post(
                f"{self.base_url}/repos/{owner}/{repo}/pulls",
                json=payload,
                headers=self._get_headers(),
            )
        )
        response.raise_for_status()
        data = response.json()
        
        return {
            "number": data.get("number"),
            "title": data.get("title"),
            "url": data.get("html_url"),
            "created": True,
        }
    
    async def _get_file_contents(self, owner: str, repo: str, path: str,
                                  ref: Optional[str] = None) -> Dict:
        """Get file contents."""
        client = await self.get_client()
        
        url = f"{self.base_url}/repos/{owner}/{repo}/contents/{path}"
        params = {}
        if ref:
            params["ref"] = ref
        
        response = await self._retry_request(
            lambda: client.get(url, params=params, headers=self._get_headers())
        )
        response.raise_for_status()
        data = response.json()
        
        # Decode content if it's a file (not a directory)
        content = None
        if data.get("type") == "file" and data.get("encoding") == "base64":
            content = base64.b64decode(data.get("content", "")).decode("utf-8")
        
        return {
            "name": data.get("name"),
            "path": data.get("path"),
            "type": data.get("type"),
            "size": data.get("size"),
            "content": content,
            "sha": data.get("sha"),
            "url": data.get("html_url"),
        }
    
    async def _create_or_update_file(self, owner: str, repo: str, path: str,
                                      message: str, content: str, branch: str,
                                      sha: Optional[str] = None) -> Dict:
        """Create or update a file."""
        client = await self.get_client()
        
        payload = {
            "message": message,
            "content": base64.b64encode(content.encode()).decode(),
            "branch": branch,
        }
        if sha:
            payload["sha"] = sha
        
        response = await self._retry_request(
            lambda: client.put(
                f"{self.base_url}/repos/{owner}/{repo}/contents/{path}",
                json=payload,
                headers=self._get_headers(),
            )
        )
        response.raise_for_status()
        data = response.json()
        
        return {
            "commit": {
                "sha": data.get("commit", {}).get("sha"),
                "url": data.get("commit", {}).get("html_url"),
            },
            "content": data.get("content"),
            "updated": True,
        }
    
    async def _search_code(self, query: str, limit: int = 30) -> Dict:
        """Search code."""
        client = await self.get_client()
        
        response = await self._retry_request(
            lambda: client.get(
                f"{self.base_url}/search/code",
                params={"q": query, "per_page": limit},
                headers=self._get_headers(),
            )
        )
        response.raise_for_status()
        data = response.json()
        
        return {
            "total_count": data.get("total_count", 0),
            "results": [
                {
                    "repository": item.get("repository", {}).get("full_name"),
                    "path": item.get("path"),
                    "name": item.get("name"),
                    "url": item.get("html_url"),
                }
                for item in data.get("items", [])
            ],
        }
