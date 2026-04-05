"""
Linear API Connector for Relay

Provides tools for Linear issue tracking:
- Issues (create, update, search, get)
- Projects (list, get)
- Teams (list, get)
- Cycles (list, get)
- Comments (create, list)
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import httpx

from .github import BaseConnector, ConnectorConfig, ToolDefinition, ResourceDefinition, PromptDefinition

logger = logging.getLogger(__name__)


class LinearConnector(BaseConnector):
    """
    Linear GraphQL API connector.
    
    Uses Linear's GraphQL API for issue tracking operations.
    """
    
    name = "linear"
    display_name = "Linear"
    description = "Linear issue tracking and project management"
    
    TOOL_MAPPING = {
        "create_issue": {
            "name": "linear_create_issue",
            "description": "Create a new Linear issue",
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Issue title"},
                    "description": {"type": "string", "description": "Issue description"},
                    "team_id": {"type": "string", "description": "Team ID"},
                    "priority": {"type": "integer", "description": "Priority (0-4)"},
                    "status": {"type": "string", "description": "Status name"},
                    "assignee_id": {"type": "string", "description": "User ID"},
                },
                "required": ["title", "team_id"],
            },
            "handler": "_create_issue",
        },
        "update_issue": {
            "name": "linear_update_issue",
            "description": "Update an existing Linear issue",
            "parameters": {
                "type": "object",
                "properties": {
                    "issue_id": {"type": "string", "description": "Issue ID"},
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "priority": {"type": "integer"},
                    "status": {"type": "string"},
                    "assignee_id": {"type": "string"},
                },
                "required": ["issue_id"],
            },
            "handler": "_update_issue",
        },
        "list_issues": {
            "name": "linear_list_issues",
            "description": "List issues in a team or project",
            "parameters": {
                "type": "object",
                "properties": {
                    "team_id": {"type": "string"},
                    "project_id": {"type": "string"},
                    "limit": {"type": "integer", "default": 50},
                },
            },
            "handler": "_list_issues",
        },
        "get_issue": {
            "name": "linear_get_issue",
            "description": "Get a specific issue by ID",
            "parameters": {
                "type": "object",
                "properties": {
                    "issue_id": {"type": "string"},
                },
                "required": ["issue_id"],
            },
            "handler": "_get_issue",
        },
        "list_teams": {
            "name": "linear_list_teams",
            "description": "List all teams in the workspace",
            "parameters": {"type": "object", "properties": {}},
            "handler": "_list_teams",
        },
        "list_projects": {
            "name": "linear_list_projects",
            "description": "List all projects",
            "parameters": {
                "type": "object",
                "properties": {
                    "team_id": {"type": "string"},
                    "limit": {"type": "integer", "default": 50},
                },
            },
            "handler": "_list_projects",
        },
        "list_cycles": {
            "name": "linear_list_cycles",
            "description": "List cycles (sprints) for a team",
            "parameters": {
                "type": "object",
                "properties": {
                    "team_id": {"type": "string"},
                    "limit": {"type": "integer", "default": 20},
                },
                "required": ["team_id"],
            },
            "handler": "_list_cycles",
        },
        "create_comment": {
            "name": "linear_create_comment",
            "description": "Add a comment to an issue",
            "parameters": {
                "type": "object",
                "properties": {
                    "issue_id": {"type": "string"},
                    "body": {"type": "string", "description": "Comment body"},
                },
                "required": ["issue_id", "body"],
            },
            "handler": "_create_comment",
        },
        "list_users": {
            "name": "linear_list_users",
            "description": "List all users in the workspace",
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "default": 50},
                },
            },
            "handler": "_list_users",
        },
    }
    
    RESOURCE_MAPPING = {
        "teams": {
            "uri": "linear://teams",
            "name": "Teams",
            "description": "List all teams in the workspace",
            "handler": "_list_teams_resource",
        },
        "projects": {
            "uri": "linear://projects",
            "name": "Projects",
            "description": "List all projects",
            "handler": "_list_projects_resource",
        },
        "my_issues": {
            "uri": "linear://my_issues",
            "name": "My Issues",
            "description": "List issues assigned to current user",
            "handler": "_list_my_issues_resource",
        },
    }
    
    PROMPT_MAPPING = {
        "create_issue": {
            "name": "Create Linear Issue",
            "description": "Template for creating a Linear issue",
            "arguments": [
                {"name": "team_id", "description": "Team ID"},
                {"name": "title", "description": "Issue title"},
                {"name": "description", "description": "Issue description"},
            ],
            "template": """Create a Linear issue:

Team: {team_id}
Title: {title}
Description:
{description}

Use the linear_create_issue tool to create this issue.""",
        },
        "summarize_project": {
            "name": "Summarize Project",
            "description": "Template for summarizing a project",
            "arguments": [
                {"name": "project_id", "description": "Project ID"},
            ],
            "template": """Get details of project {project_id} and summarize:
- What is the project about?
- Current status
- Key issues

Use linear_list_projects to find the project.""",
        },
    }
    
    def __init__(self, config: ConnectorConfig):
        super().__init__(config)
        self.base_url = config.base_url or "https://api.linear.app/graphql"
    
    def set_token(self, token: str) -> None:
        """Set the API token for this connector."""
        self.config.api_key = token
    
    def _get_headers(self) -> Dict[str, str]:
        """Get headers for Linear API requests."""
        return {
            "Authorization": self.config.api_key,
            "Content-Type": "application/json",
        }
    
    def get_tools(self) -> List[ToolDefinition]:
        """Return Linear tools dynamically from TOOL_MAPPING."""
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
        """Return Linear tools (sync version for compatibility)."""
        return self.get_tools()
    
    def get_resources(self) -> List[ResourceDefinition]:
        """Return Linear resources from RESOURCE_MAPPING."""
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
        """Return Linear prompts from PROMPT_MAPPING."""
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
        """Read a Linear resource by URI."""
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
        """Check Linear API accessibility."""
        try:
            result = await self._graphql_query("""
                query { viewer { id name } }
            """)
            if result.get("viewer"):
                return True, f"Linear API accessible as {result['viewer'].get('name')}"
            return False, "Linear API returned no viewer data"
        except httpx.ConnectError:
            return False, "Cannot connect to Linear API"
        except Exception as e:
            err_msg = str(e)
            if "401" in err_msg or "unauthorized" in err_msg.lower():
                return False, "Linear API requires authentication. Connect your account."
            return False, f"Linear API check failed: {e}"
    
    async def _graphql_query(self, query: str, variables: Optional[Dict] = None) -> Dict:
        """Execute a GraphQL query."""
        client = await self.get_client()
        
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        
        response = await self._retry_request(
            lambda: client.post(
                self.base_url,
                json=payload,
                headers=self._get_headers(),
            )
        )
        response.raise_for_status()
        
        data = response.json()
        
        if "errors" in data:
            raise Exception(f"GraphQL error: {data['errors'][0].get('message', 'unknown')}")
        
        return data.get("data", {})
    
    # --- Tool Implementations ---
    
    async def _create_issue(
        self,
        title: str,
        team_id: str,
        description: Optional[str] = None,
        priority: Optional[int] = None,
        status: Optional[str] = None,
        assignee_id: Optional[str] = None,
        label_ids: Optional[List[str]] = None,
        project_id: Optional[str] = None,
        cycle_id: Optional[str] = None,
        parent_id: Optional[str] = None,
    ) -> Dict:
        """Create a Linear issue."""
        # Build the input object
        input_obj = {"title": title, "teamId": team_id}
        if description:
            input_obj["description"] = description
        if priority is not None:
            input_obj["priority"] = priority
        if status:
            status_id = await self._get_status_id(team_id, status)
            if status_id:
                input_obj["statusId"] = status_id
        if assignee_id:
            input_obj["assigneeId"] = assignee_id
        if label_ids:
            input_obj["labelIds"] = label_ids
        if project_id:
            input_obj["projectId"] = project_id
        if cycle_id:
            input_obj["cycleId"] = cycle_id
        if parent_id:
            input_obj["parentId"] = parent_id
        
        mutation = """
            mutation CreateIssue($input: IssueCreateInput!) {
                issueCreate(input: $input) {
                    success
                    issue {
                        id
                        identifier
                        title
                        url
                    }
                }
            }
        """
        
        result = await self._graphql_query(mutation, {"input": input_obj})
        
        issue = result.get("issueCreate", {}).get("issue", {})
        return {
            "id": issue.get("id"),
            "identifier": issue.get("identifier"),
            "title": issue.get("title"),
            "url": issue.get("url"),
            "created": True,
        }
    
    async def _update_issue(self, issue_id: str, **updates) -> Dict:
        """Update a Linear issue."""
        # Map parameter names to Linear API
        input_obj = {}
        if "title" in updates:
            input_obj["title"] = updates["title"]
        if "description" in updates:
            input_obj["description"] = updates["description"]
        if "priority" in updates:
            input_obj["priority"] = updates["priority"]
        if "assignee_id" in updates:
            input_obj["assigneeId"] = updates["assignee_id"]
        if "project_id" in updates:
            input_obj["projectId"] = updates["project_id"]
        if "cycle_id" in updates:
            input_obj["cycleId"] = updates["cycle_id"]
        
        if not input_obj:
            return {"updated": False, "message": "No updates provided"}
        
        mutation = """
            mutation UpdateIssue($id: String!, $input: IssueUpdateInput!) {
                issueUpdate(id: $id, input: $input) {
                    success
                    issue {
                        id
                        identifier
                        title
                    }
                }
            }
        """
        
        result = await self._graphql_query(mutation, {"id": issue_id, "input": input_obj})
        
        issue = result.get("issueUpdate", {}).get("issue", {})
        return {
            "id": issue.get("id"),
            "identifier": issue.get("identifier"),
            "title": issue.get("title"),
            "updated": True,
        }
    
    async def _get_issue(self, issue_id: str) -> Dict:
        """Get issue details."""
        query = """
            query GetIssue($id: String!) {
                issue(id: $id) {
                    id
                    identifier
                    title
                    description
                    priority
                    url
                    createdAt
                    updatedAt
                    status { id name type }
                    assignee { id name displayName }
                    creator { id name displayName }
                    team { id name key }
                    project { id name }
                    cycle { id name number }
                    labels { id name color }
                    parent { id identifier title }
                    children { nodes { id identifier title } }
                }
            }
        """
        
        result = await self._graphql_query(query, {"id": issue_id})
        issue = result.get("issue", {})
        
        if not issue:
            return {"error": f"Issue {issue_id} not found"}
        
        return {
            "id": issue.get("id"),
            "identifier": issue.get("identifier"),
            "title": issue.get("title"),
            "description": issue.get("description"),
            "priority": issue.get("priority"),
            "url": issue.get("url"),
            "status": issue.get("status", {}).get("name") if issue.get("status") else None,
            "assignee": issue.get("assignee", {}).get("displayName") if issue.get("assignee") else None,
            "creator": issue.get("creator", {}).get("displayName") if issue.get("creator") else None,
            "team": issue.get("team", {}).get("name") if issue.get("team") else None,
            "project": issue.get("project", {}).get("name") if issue.get("project") else None,
            "labels": [l.get("name") for l in issue.get("labels", [])],
            "created_at": issue.get("createdAt"),
            "updated_at": issue.get("updatedAt"),
        }
    
    async def _search_issues(
        self,
        query: Optional[str] = None,
        team_id: Optional[str] = None,
        assignee_id: Optional[str] = None,
        status: Optional[str] = None,
        priority: Optional[int] = None,
        limit: int = 20,
    ) -> Dict:
        """Search issues."""
        # Build filter
        filter_obj = {}
        if query:
            filter_obj["search"] = query
        if team_id:
            filter_obj["team"] = {"id": {"eq": team_id}}
        if assignee_id:
            filter_obj["assignee"] = {"id": {"eq": assignee_id}}
        if priority is not None:
            filter_obj["priority"] = {"eq": priority}
        
        gql_query = """
            query SearchIssues($filter: IssueFilter, $limit: Int) {
                issues(filter: $filter, first: $limit) {
                    nodes {
                        id
                        identifier
                        title
                        priority
                        status { name }
                        assignee { displayName }
                        team { key }
                        url
                    }
                }
            }
        """
        
        result = await self._graphql_query(
            gql_query, 
            {"filter": filter_obj, "limit": limit}
        )
        
        issues = result.get("issues", {}).get("nodes", [])
        
        return {
            "issues": [
                {
                    "id": i.get("id"),
                    "identifier": i.get("identifier"),
                    "title": i.get("title"),
                    "priority": i.get("priority"),
                    "status": i.get("status", {}).get("name") if i.get("status") else None,
                    "assignee": i.get("assignee", {}).get("displayName") if i.get("assignee") else None,
                    "team": i.get("team", {}).get("key") if i.get("team") else None,
                    "url": i.get("url"),
                }
                for i in issues
            ],
            "total": len(issues),
        }
    
    async def _list_teams(self, limit: int = 50) -> Dict:
        """List teams."""
        query = """
            query ListTeams($limit: Int) {
                teams(first: $limit) {
                    nodes {
                        id
                        name
                        key
                        description
                        iconUrl
                    }
                }
            }
        """
        
        result = await self._graphql_query(query, {"limit": limit})
        teams = result.get("teams", {}).get("nodes", [])
        
        return {
            "teams": [
                {
                    "id": t.get("id"),
                    "name": t.get("name"),
                    "key": t.get("key"),
                    "description": t.get("description"),
                }
                for t in teams
            ]
        }
    
    async def _list_projects(self, team_id: Optional[str] = None, limit: int = 50) -> Dict:
        """List projects."""
        filter_obj = {}
        if team_id:
            filter_obj["team"] = {"id": {"eq": team_id}}
        
        query = """
            query ListProjects($filter: ProjectFilter, $limit: Int) {
                projects(filter: $filter, first: $limit) {
                    nodes {
                        id
                        name
                        description
                        status
                        lead { displayName }
                        team { name key }
                        url
                    }
                }
            }
        """
        
        result = await self._graphql_query(query, {"filter": filter_obj, "limit": limit})
        projects = result.get("projects", {}).get("nodes", [])
        
        return {
            "projects": [
                {
                    "id": p.get("id"),
                    "name": p.get("name"),
                    "description": p.get("description"),
                    "status": p.get("status"),
                    "lead": p.get("lead", {}).get("displayName") if p.get("lead") else None,
                    "team": p.get("team", {}).get("name") if p.get("team") else None,
                }
                for p in projects
            ]
        }
    
    async def _list_cycles(self, team_id: str, limit: int = 20) -> Dict:
        """List cycles for a team."""
        query = """
            query ListCycles($teamId: ID!, $limit: Int) {
                team(id: $teamId) {
                    cycles(first: $limit) {
                        nodes {
                            id
                            name
                            number
                            startDate
                            endDate
                            progress
                        }
                    }
                }
            }
        """
        
        result = await self._graphql_query(query, {"teamId": team_id, "limit": limit})
        cycles = result.get("team", {}).get("cycles", {}).get("nodes", [])
        
        return {
            "cycles": [
                {
                    "id": c.get("id"),
                    "name": c.get("name"),
                    "number": c.get("number"),
                    "start_date": c.get("startDate"),
                    "end_date": c.get("endDate"),
                    "progress": c.get("progress"),
                }
                for c in cycles
            ]
        }
    
    async def _create_comment(self, issue_id: str, body: str) -> Dict:
        """Create a comment."""
        mutation = """
            mutation CreateComment($input: CommentCreateInput!) {
                commentCreate(input: $input) {
                    success
                    comment {
                        id
                        body
                        url
                    }
                }
            }
        """
        
        result = await self._graphql_query(
            mutation, 
            {"input": {"issueId": issue_id, "body": body}}
        )
        
        comment = result.get("commentCreate", {}).get("comment", {})
        return {
            "id": comment.get("id"),
            "url": comment.get("url"),
            "created": True,
        }
    
    async def _list_comments(self, issue_id: str, limit: int = 50) -> Dict:
        """List comments on an issue."""
        query = """
            query ListComments($issueId: String!, $limit: Int) {
                issue(id: $issueId) {
                    comments(first: $limit) {
                        nodes {
                            id
                            body
                            createdAt
                            user { displayName }
                        }
                    }
                }
            }
        """
        
        result = await self._graphql_query(query, {"issueId": issue_id, "limit": limit})
        comments = result.get("issue", {}).get("comments", {}).get("nodes", [])
        
        return {
            "comments": [
                {
                    "id": c.get("id"),
                    "body": c.get("body"),
                    "author": c.get("user", {}).get("displayName") if c.get("user") else None,
                    "created_at": c.get("createdAt"),
                }
                for c in comments
            ]
        }
    
    async def _list_labels(self, team_id: Optional[str] = None, limit: int = 50) -> Dict:
        """List labels."""
        filter_obj = {}
        if team_id:
            filter_obj["team"] = {"id": {"eq": team_id}}
        
        query = """
            query ListLabels($filter: IssueLabelFilter, $limit: Int) {
                issueLabels(filter: $filter, first: $limit) {
                    nodes {
                        id
                        name
                        color
                        description
                        team { name }
                    }
                }
            }
        """
        
        result = await self._graphql_query(query, {"filter": filter_obj, "limit": limit})
        labels = result.get("issueLabels", {}).get("nodes", [])
        
        return {
            "labels": [
                {
                    "id": l.get("id"),
                    "name": l.get("name"),
                    "color": l.get("color"),
                    "description": l.get("description"),
                    "team": l.get("team", {}).get("name") if l.get("team") else None,
                }
                for l in labels
            ]
        }
    
    async def _list_users(self, limit: int = 50) -> Dict:
        """List users."""
        query = """
            query ListUsers($limit: Int) {
                users(first: $limit) {
                    nodes {
                        id
                        name
                        displayName
                        email
                        avatarUrl
                    }
                }
            }
        """
        
        result = await self._graphql_query(query, {"limit": limit})
        users = result.get("users", {}).get("nodes", [])
        
        return {
            "users": [
                {
                    "id": u.get("id"),
                    "name": u.get("name"),
                    "display_name": u.get("displayName"),
                    "email": u.get("email"),
                }
                for u in users
            ]
        }


    async def _get_status_id(self, team_id: str, status_name: str) -> Optional[str]:
        """Resolve a workflow state name to its ID for the given team."""
        query = """
            query GetWorkflowStates($teamId: String!) {
                workflowStates(filter: { team: { id: { eq: $teamId } } }) {
                    nodes { id name }
                }
            }
        """
        try:
            result = await self._graphql_query(query, {"teamId": team_id})
            for node in result.get("workflowStates", {}).get("nodes", []):
                if node.get("name", "").lower() == status_name.lower():
                    return node.get("id")
        except Exception as e:
            logger.warning(f"Failed to resolve status '{status_name}' for team {team_id}: {e}")
        return None
    
    # --- Resource Handlers ---
    
    async def _list_teams_resource(self) -> Dict[str, Any]:
        """List teams (for resource)."""
        query = """
            query ListTeams($limit: Int) {
                teams(first: $limit) {
                    nodes {
                        id
                        name
                        key
                        description
                    }
                }
            }
        """
        result = await self._graphql_query(query, {"limit": 50})
        teams = result.get("teams", {}).get("nodes", [])
        return {
            "teams": [
                {
                    "id": t.get("id"),
                    "name": t.get("name"),
                    "key": t.get("key"),
                    "description": t.get("description"),
                }
                for t in teams
            ],
        }
    
    async def _list_projects_resource(self) -> Dict[str, Any]:
        """List projects (for resource)."""
        query = """
            query ListProjects($limit: Int) {
                projects(first: $limit) {
                    nodes {
                        id
                        name
                        description
                        status
                    }
                }
            }
        """
        result = await self._graphql_query(query, {"limit": 50})
        projects = result.get("projects", {}).get("nodes", [])
        return {
            "projects": [
                {
                    "id": p.get("id"),
                    "name": p.get("name"),
                    "description": p.get("description"),
                    "status": p.get("status"),
                }
                for p in projects
            ],
        }
    
    async def _list_my_issues_resource(self) -> Dict[str, Any]:
        """List issues assigned to current user (for resource)."""
        query = """
            query MyIssues($limit: Int) {
                issues(filter: { assignee: { isMe: { eq: true } } }, first: $limit) {
                    nodes {
                        id
                        identifier
                        title
                        state { name }
                        priority
                    }
                }
            }
        """
        result = await self._graphql_query(query, {"limit": 20})
        issues = result.get("issues", {}).get("nodes", [])
        return {
            "issues": [
                {
                    "id": i.get("identifier"),
                    "title": i.get("title"),
                    "state": i.get("state", {}).get("name"),
                    "priority": i.get("priority"),
                }
                for i in issues
            ],
        }
