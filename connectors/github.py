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
class ResourceDefinition:
    """Definition of a resource provided by a connector."""
    uri: str  # e.g., "github://repos" or "github://repos/owner/repo"
    name: str
    description: str
    mime_type: str = "application/json"
    read_handler: Optional[Callable] = None
    requires_auth: bool = True


@dataclass
class PromptDefinition:
    """Definition of a prompt template provided by a connector."""
    name: str
    description: str
    arguments: List[Dict[str, Any]] = field(default_factory=list)
    template: str = ""
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
    
    def get_resources(self) -> List[ResourceDefinition]:
        """Return list of resources provided by this connector."""
        return []
    
    def get_prompts(self) -> List[PromptDefinition]:
        """Return list of prompt templates provided by this connector."""
        return []
    
    async def read_resource(self, uri: str) -> Optional[Dict[str, Any]]:
        """Read a resource by URI. Returns None if resource not found."""
        return None
    
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
    
    TOOL_MAPPING = {
        "search_repositories": {
            "name": "github_search_repositories",
            "description": "Search GitHub repositories",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                    "sort": {"type": "string", "enum": ["stars", "forks", "updated"], "default": "best-match"},
                    "order": {"type": "string", "enum": ["asc", "desc"], "default": "desc"},
                    "limit": {"type": "integer", "default": 10, "maximum": 100},
                },
                "required": ["query"],
            },
            "handler": "_search_repositories",
        },
        "get_repository": {
            "name": "github_get_repository",
            "description": "Get details of a GitHub repository",
            "parameters": {
                "type": "object",
                "properties": {
                    "owner": {"type": "string", "description": "Repository owner"},
                    "repo": {"type": "string", "description": "Repository name"},
                },
                "required": ["owner", "repo"],
            },
            "handler": "_get_repository",
        },
        "list_issues": {
            "name": "github_list_issues",
            "description": "List issues in a repository",
            "parameters": {
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
            "handler": "_list_issues",
        },
        "create_issue": {
            "name": "github_create_issue",
            "description": "Create a new issue in a repository",
            "parameters": {
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
            "handler": "_create_issue",
        },
        "list_pull_requests": {
            "name": "github_list_pull_requests",
            "description": "List pull requests in a repository",
            "parameters": {
                "type": "object",
                "properties": {
                    "owner": {"type": "string"},
                    "repo": {"type": "string"},
                    "state": {"type": "string", "enum": ["open", "closed", "all"], "default": "open"},
                    "limit": {"type": "integer", "default": 30},
                },
                "required": ["owner", "repo"],
            },
            "handler": "_list_pull_requests",
        },
        "create_pull_request": {
            "name": "github_create_pull_request",
            "description": "Create a new pull request",
            "parameters": {
                "type": "object",
                "properties": {
                    "owner": {"type": "string"},
                    "repo": {"type": "string"},
                    "title": {"type": "string"},
                    "body": {"type": "string"},
                    "head": {"type": "string", "description": "The name of the branch where your changes are implemented"},
                    "base": {"type": "string", "description": "The name of the branch you want the changes pulled into"},
                },
                "required": ["owner", "repo", "title", "head", "base"],
            },
            "handler": "_create_pull_request",
        },
        "get_file_content": {
            "name": "github_get_file_content",
            "description": "Get the content of a file in a repository",
            "parameters": {
                "type": "object",
                "properties": {
                    "owner": {"type": "string"},
                    "repo": {"type": "string"},
                    "path": {"type": "string", "description": "Path to the file"},
                    "ref": {"type": "string", "description": "Branch or tag name"},
                },
                "required": ["owner", "repo", "path"],
            },
            "handler": "_get_file_contents",
        },
        "list_user_repos": {
            "name": "github_list_user_repositories",
            "description": "List repositories for a user",
            "parameters": {
                "type": "object",
                "properties": {
                    "username": {"type": "string"},
                    "sort": {"type": "string", "enum": ["created", "updated", "pushed", "full_name"], "default": "full_name"},
                    "per_page": {"type": "integer", "default": 30},
                },
                "required": ["username"],
            },
            "handler": "_list_user_repos",
        },
    }
    
    RESOURCE_MAPPING = {
        "repos": {
            "uri": "github://repos",
            "name": "Repositories",
            "description": "List repositories accessible to the user",
            "handler": "_list_repos_resource",
        },
        "user": {
            "uri": "github://user",
            "name": "Current User",
            "description": "Get current user profile",
            "handler": "_get_user_resource",
        },
        "rate_limit": {
            "uri": "github://rate_limit",
            "name": "Rate Limit",
            "description": "Get current API rate limit status",
            "handler": "_get_rate_limit_resource",
        },
    }
    
    PROMPT_MAPPING = {
        "create_issue": {
            "name": "Create GitHub Issue",
            "description": "Template for creating a GitHub issue",
            "arguments": [
                {"name": "owner", "description": "Repository owner"},
                {"name": "repo", "description": "Repository name"},
                {"name": "title", "description": "Issue title"},
                {"name": "body", "description": "Issue description"},
            ],
            "template": """Create a GitHub issue in {owner}/{repo}:

Title: {title}
Body:
{body}

Use the github_create_issue tool to create this issue.""",
        },
        "summarize_pr": {
            "name": "Summarize Pull Request",
            "description": "Template for summarizing a PR",
            "arguments": [
                {"name": "owner", "description": "Repository owner"},
                {"name": "repo", "description": "Repository name"},
                {"name": "pr_number", "description": "PR number"},
            ],
            "template": """Summarize pull request #{pr_number} in {owner}/{repo}:

1. What is this PR trying to accomplish?
2. What are the key changes?
3. Any concerns or things to watch for?

Use github_list_pull_requests to get the PR details.""",
        },
    }
    
    def __init__(self, config: ConnectorConfig):
        super().__init__(config)
        self.base_url = config.base_url or "https://api.github.com"
    
    def set_token(self, token: str) -> None:
        """Set the API token for this connector."""
        self.config.api_key = token
    
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
        """Return GitHub tools dynamically from TOOL_MAPPING."""
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
        """Return GitHub tools (sync version for compatibility)."""
        return self.get_tools()
    
    def get_resources(self) -> List[ResourceDefinition]:
        """Return GitHub resources from RESOURCE_MAPPING."""
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
        """Return GitHub prompts from PROMPT_MAPPING."""
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
        """Read a GitHub resource by URI."""
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
            elif response.status_code == 401:
                return False, "GitHub API requires authentication. Connect your account."
            elif response.status_code == 403:
                return False, "GitHub API access forbidden. Check token permissions."
            return False, f"GitHub API returned status {response.status_code}"
        except httpx.ConnectError:
            return False, "Cannot connect to GitHub API"
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
    
    # --- Resource Handlers ---
    
    async def _list_repos_resource(self) -> Dict[str, Any]:
        """List repositories accessible to the user (for resource)."""
        client = await self.get_client()
        response = await self._retry_request(
            lambda: client.get(
                f"{self.base_url}/user/repos",
                params={"sort": "updated", "per_page": 30},
                headers=self._get_headers(),
            )
        )
        response.raise_for_status()
        data = response.json()
        
        return {
            "repos": [
                {
                    "name": r.get("full_name"),
                    "description": r.get("description"),
                    "private": r.get("private"),
                    "url": r.get("html_url"),
                }
                for r in data
            ],
        }
    
    async def _get_user_resource(self) -> Dict[str, Any]:
        """Get current user profile (for resource)."""
        client = await self.get_client()
        response = await client.get(
            f"{self.base_url}/user",
            headers=self._get_headers(),
        )
        response.raise_for_status()
        data = response.json()
        
        return {
            "login": data.get("login"),
            "name": data.get("name"),
            "email": data.get("email"),
            "avatar_url": data.get("avatar_url"),
        }
    
    async def _get_rate_limit_resource(self) -> Dict[str, Any]:
        """Get rate limit status (for resource)."""
        client = await self.get_client()
        response = await client.get(
            f"{self.base_url}/rate_limit",
            headers=self._get_headers(),
        )
        response.raise_for_status()
        data = response.json()
        
        core = data.get("resources", {}).get("core", {})
        return {
            "limit": core.get("limit"),
            "remaining": core.get("remaining"),
            "reset": core.get("reset"),
        }
