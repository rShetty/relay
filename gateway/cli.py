"""
Relay CLI

Command-line interface for managing the Relay.
"""

import argparse
import asyncio
import json
import os
import sys
from typing import Optional


def cmd_serve(args):
    """Start the Relay server."""
    from gateway.server import run_server
    run_server()


def cmd_mcp(args):
    """Start the MCP server (stdio mode for MCP clients)."""
    from gateway.server import run_mcp_server
    run_mcp_server()


def cmd_register_client(args):
    """Register a new OAuth client."""
    import requests
    
    response = requests.post(
        f"{args.gateway_url}/oauth/register",
        json={
            "client_name": args.name,
            "redirect_uris": args.redirect_uris,
        }
    )
    
    if response.status_code == 200:
        data = response.json()
        print("Client registered successfully!")
        print(f"  Client ID: {data['client_id']}")
        print(f"  Client Name: {data['client_name']}")
        print(f"  Redirect URIs: {data['redirect_uris']}")
    else:
        print(f"Error: {response.text}")


def cmd_authorize(args):
    """Start OAuth authorization flow."""
    # Generate PKCE verifier and challenge
    from auth.oauth import generate_code_verifier, generate_code_challenge
    
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    
    print(f"Code Verifier: {code_verifier}")
    print(f"Code Challenge: {code_challenge}")
    print()
    
    # Build authorization URL
    import requests
    from urllib.parse import urlencode
    
    params = {
        "client_id": args.client_id,
        "redirect_uri": args.redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "scope": args.scope,
    }
    
    url = f"{args.gateway_url}/oauth/authorize?{urlencode(params)}"
    print(f"Authorization URL: {url}")
    print()
    print("Open this URL in your browser, authorize, then paste the code here:")
    
    code = input("Authorization code: ").strip()
    
    # Exchange code for token
    response = requests.post(
        f"{args.gateway_url}/oauth/token",
        json={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": code_verifier,
            "client_id": args.client_id,
            "redirect_uri": args.redirect_uri,
        }
    )
    
    if response.status_code == 200:
        data = response.json()
        print("\nToken obtained!")
        print(f"  Access Token: {data['access_token'][:50]}...")
        print(f"  Refresh Token: {data['refresh_token'][:50]}...")
        print(f"  Expires In: {data['expires_in']} seconds")
        print(f"  Scope: {data['scope']}")
        
        # Save tokens
        if args.output:
            with open(args.output, "w") as f:
                json.dump(data, f, indent=2)
            print(f"\nTokens saved to: {args.output}")
    else:
        print(f"Error: {response.text}")


def cmd_list_backends(args):
    """List available backends."""
    import requests
    
    headers = {"Authorization": f"Bearer {args.token}"}
    response = requests.get(
        f"{args.gateway_url}/mcp/backends",
        headers=headers,
    )
    
    if response.status_code == 200:
        backends = response.json()
        print(f"Found {len(backends)} backends:\n")
        for b in backends:
            status_icon = "✓" if b["status"] == "healthy" else "✗"
            print(f"  [{status_icon}] {b['id']}: {b['name']}")
            print(f"      Type: {b['type']}")
            print(f"      Status: {b['status']}")
            print(f"      Tools: {', '.join(b['tools'][:5])}{'...' if len(b['tools']) > 5 else ''}")
            print()
    else:
        print(f"Error: {response.text}")


def cmd_call_tool(args):
    """Call a tool through the gateway."""
    import requests
    
    try:
        arguments = json.loads(args.arguments)
    except json.JSONDecodeError:
        arguments = {"input": args.arguments}
    
    headers = {"Authorization": f"Bearer {args.token}"}
    response = requests.post(
        f"{args.gateway_url}/mcp/call",
        headers=headers,
        json={
            "tool_name": args.tool,
            "arguments": arguments,
            "backend_id": args.backend,
        }
    )
    
    if response.status_code == 200:
        result = response.json()
        print(json.dumps(result, indent=2))
    else:
        print(f"Error: {response.text}")


def cmd_mcp_proxy(args):
    """Run the Relay as a proxy to a backend."""
    from gateway.server import run_mcp_proxy
    run_mcp_proxy(backend_id=args.backend)


def cmd_github_search(args):
    """Search GitHub repositories through the gateway."""
    import json
    import urllib.request
    import urllib.error

    api_key = args.api_key or os.getenv("GATEWAY_API_KEY")
    if not api_key:
        print("Error: No API key provided. Use --api-key or set GATEWAY_API_KEY env var.")
        return

    query = args.query
    if "in:name" not in query:
        query = f"{query} in:name"

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "tool_name": "search_repositories",
        "arguments": {
            "query": query,
            "sort": args.sort,
            "order": args.order,
            "limit": args.limit,
        },
    }

    url = f"{args.gateway_url}/v1/call"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"Error ({e.code}): {e.read().decode('utf-8')}")
        return
    except urllib.error.URLError as e:
        print(f"Error connecting to gateway: {e.reason}")
        return

    if not result.get("success"):
        print(f"Error: {result.get('error', 'Unknown error')}")
        return

    data = result.get("result", {})
    total = data.get("total_count", 0)
    repos = data.get("repositories", [])

    if not repos:
        print(f"No repositories found matching '{args.query}'.")
        return

    print(f"\nFound {total} repositories matching '{args.query}':\n")

    for i, repo in enumerate(repos, 1):
        print(f"  {i}. {repo['full_name']}")
        if repo.get("description"):
            print(f"     {repo['description']}")
        print(f"     Stars: {repo['stars']}  |  Forks: {repo['forks']}  |  Language: {repo['language'] or 'N/A'}")
        print(f"     URL: {repo['url']}")
        print()


def cmd_generate_pkce(args):
    """Generate PKCE code verifier and challenge."""
    from auth.oauth import generate_code_verifier, generate_code_challenge

    verifier = generate_code_verifier(args.length)
    challenge = generate_code_challenge(verifier, args.method)

    print(f"Code Verifier: {verifier}")
    print(f"Code Challenge: {challenge}")
    print(f"Method: {args.method}")


def main():
    parser = argparse.ArgumentParser(
        description="Relay CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start the HTTP server
  relay serve --port 8000
  
  # Start the MCP server (for stdio)
  relay mcp
  
  # Register an OAuth client
  relay register-client --name "My App" --redirect-uri "http://localhost:3000/callback"
  
  # Authorize a client
  relay authorize --client-id CLIENT_ID --redirect-uri "http://localhost:3000/callback"
  
  # List backends
  relay list-backends --token YOUR_ACCESS_TOKEN
  
  # Call a tool
  relay call --tool search_repositories --arguments '{"query": "mcp"}' --token YOUR_TOKEN
""",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # serve
    serve_parser = subparsers.add_parser("serve", help="Start the HTTP server")
    serve_parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    serve_parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    serve_parser.set_defaults(func=cmd_serve)
    
    # mcp
    mcp_parser = subparsers.add_parser("mcp", help="Start the MCP server (stdio mode)")
    mcp_parser.set_defaults(func=cmd_mcp)
    
    # mcp-proxy
    proxy_parser = subparsers.add_parser("mcp-proxy", help="Run gateway as MCP proxy to a backend")
    proxy_parser.add_argument(
        "--backend", 
        default="github", 
        help="Backend ID to proxy to (default: github)"
    )
    proxy_parser.set_defaults(func=cmd_mcp_proxy)
    
    # register-client
    reg_parser = subparsers.add_parser("register-client", help="Register an OAuth client")
    reg_parser.add_argument("--name", required=True, help="Client name")
    reg_parser.add_argument("--redirect-uri", action="append", dest="redirect_uris", required=True,
                           help="Allowed redirect URI (can be specified multiple times)")
    reg_parser.add_argument("--gateway-url", default="http://localhost:8000", help="Gateway URL")
    reg_parser.set_defaults(func=cmd_register_client)
    
    # authorize
    auth_parser = subparsers.add_parser("authorize", help="Start OAuth authorization flow")
    auth_parser.add_argument("--client-id", required=True, help="Client ID")
    auth_parser.add_argument("--redirect-uri", required=True, help="Redirect URI")
    auth_parser.add_argument("--scope", default="mcp:tools", help="OAuth scope")
    auth_parser.add_argument("--gateway-url", default="http://localhost:8000", help="Gateway URL")
    auth_parser.add_argument("--output", help="Output file for tokens")
    auth_parser.set_defaults(func=cmd_authorize)
    
    # list-backends
    list_parser = subparsers.add_parser("list-backends", help="List available backends")
    list_parser.add_argument("--token", required=True, help="Access token")
    list_parser.add_argument("--gateway-url", default="http://localhost:8000", help="Gateway URL")
    list_parser.set_defaults(func=cmd_list_backends)
    
    # call
    call_parser = subparsers.add_parser("call", help="Call a tool through the gateway")
    call_parser.add_argument("--tool", required=True, help="Tool name")
    call_parser.add_argument("--arguments", default="{}", help="JSON arguments")
    call_parser.add_argument("--backend", help="Backend ID")
    call_parser.add_argument("--token", required=True, help="Access token")
    call_parser.add_argument("--gateway-url", default="http://localhost:8000", help="Gateway URL")
    call_parser.set_defaults(func=cmd_call_tool)
    
    # github-search
    gh_parser = subparsers.add_parser("github-search", help="Search GitHub repositories through the gateway")
    gh_parser.add_argument("query", help="Repository name or search term")
    gh_parser.add_argument("--sort", default="stars", choices=["stars", "forks", "updated"], help="Sort order")
    gh_parser.add_argument("--order", default="desc", choices=["asc", "desc"], help="Sort direction")
    gh_parser.add_argument("--limit", type=int, default=30, help="Max results (default: 30)")
    gh_parser.add_argument("--api-key", help="Gateway API key (or set GATEWAY_API_KEY env var)")
    gh_parser.add_argument("--gateway-url", default="http://localhost:8000", help="Gateway URL")
    gh_parser.set_defaults(func=cmd_github_search)

    # generate-pkce
    pkce_parser = subparsers.add_parser("generate-pkce", help="Generate PKCE verifier and challenge")
    pkce_parser.add_argument("--length", type=int, default=128, help="Code verifier length")
    pkce_parser.add_argument("--method", default="S256", help="Challenge method (S256 or plain)")
    pkce_parser.set_defaults(func=cmd_generate_pkce)
    
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        sys.exit(1)
    
    args.func(args)


if __name__ == "__main__":
    main()
