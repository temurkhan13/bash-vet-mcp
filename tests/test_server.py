"""Server protocol-wiring tests — tools / resources / prompts register + dispatch correctly."""
from __future__ import annotations

import json

import pytest

from bash_vet_mcp.server import build_server


def test_build_server() -> None:
    server = build_server()
    assert server is not None
    assert server.name == "bash-vet"


# ───────────── Tool registration ─────────────


async def test_list_tools_returns_three() -> None:
    from mcp.types import ListToolsRequest

    server = build_server()
    handler = server.request_handlers[ListToolsRequest]
    result = await handler(ListToolsRequest(method="tools/list"))
    names = {t.name for t in result.root.tools}
    expected = {"vet_command", "vet_command_chain", "list_detection_rules"}
    assert names == expected


async def test_tools_have_valid_schemas() -> None:
    from mcp.types import ListToolsRequest

    server = build_server()
    handler = server.request_handlers[ListToolsRequest]
    result = await handler(ListToolsRequest(method="tools/list"))
    for tool in result.root.tools:
        assert isinstance(tool.inputSchema, dict)
        assert tool.inputSchema.get("type") == "object"


# ───────────── vet_command ─────────────


async def test_call_tool_vet_command_clean() -> None:
    from mcp.types import CallToolRequest, CallToolRequestParams

    server = build_server()
    handler = server.request_handlers[CallToolRequest]
    result = await handler(
        CallToolRequest(
            method="tools/call",
            params=CallToolRequestParams(
                name="vet_command",
                arguments={"command": "ls -la /home/user"},
            ),
        )
    )
    parsed = json.loads(result.root.content[0].text)
    assert parsed["verdict"] == "clean"
    assert parsed["finding_count"] == 0


async def test_call_tool_vet_command_blocks_rm_rf_root() -> None:
    from mcp.types import CallToolRequest, CallToolRequestParams

    server = build_server()
    handler = server.request_handlers[CallToolRequest]
    result = await handler(
        CallToolRequest(
            method="tools/call",
            params=CallToolRequestParams(
                name="vet_command",
                arguments={"command": "rm -rf /"},
            ),
        )
    )
    parsed = json.loads(result.root.content[0].text)
    assert parsed["verdict"] == "block"
    assert any(f["rule_id"] == "DESTRUCTIVE.RM_RECURSIVE_ROOT" for f in parsed["findings"])


async def test_call_tool_vet_command_blocks_apt_glob() -> None:
    from mcp.types import CallToolRequest, CallToolRequestParams

    server = build_server()
    handler = server.request_handlers[CallToolRequest]
    result = await handler(
        CallToolRequest(
            method="tools/call",
            params=CallToolRequestParams(
                name="vet_command",
                arguments={"command": "sudo apt remove '*nvidia*'"},
            ),
        )
    )
    parsed = json.loads(result.root.content[0].text)
    assert parsed["verdict"] == "block"


# ───────────── vet_command_chain ─────────────


async def test_call_tool_vet_command_chain_escalates() -> None:
    from mcp.types import CallToolRequest, CallToolRequestParams

    server = build_server()
    handler = server.request_handlers[CallToolRequest]
    cmd = "make install && git reset --hard HEAD~1"
    # Normal mode
    normal = await handler(
        CallToolRequest(
            method="tools/call",
            params=CallToolRequestParams(name="vet_command", arguments={"command": cmd}),
        )
    )
    normal_parsed = json.loads(normal.root.content[0].text)
    assert normal_parsed["verdict"] == "review"
    # Chain mode escalates MEDIUM → HIGH → BLOCK
    chain = await handler(
        CallToolRequest(
            method="tools/call",
            params=CallToolRequestParams(name="vet_command_chain", arguments={"command": cmd}),
        )
    )
    chain_parsed = json.loads(chain.root.content[0].text)
    assert chain_parsed["verdict"] == "block"


# ───────────── list_detection_rules ─────────────


async def test_call_tool_list_detection_rules() -> None:
    from mcp.types import CallToolRequest, CallToolRequestParams

    server = build_server()
    handler = server.request_handlers[CallToolRequest]
    result = await handler(
        CallToolRequest(
            method="tools/call",
            params=CallToolRequestParams(name="list_detection_rules", arguments={}),
        )
    )
    parsed = json.loads(result.root.content[0].text)
    assert parsed["total_rules"] >= 24
    assert isinstance(parsed["rules"], list)
    assert all("rule_id" in r for r in parsed["rules"])


async def test_call_tool_unknown_returns_error() -> None:
    from mcp.types import CallToolRequest, CallToolRequestParams

    server = build_server()
    handler = server.request_handlers[CallToolRequest]
    result = await handler(
        CallToolRequest(
            method="tools/call",
            params=CallToolRequestParams(name="not_a_tool", arguments={}),
        )
    )
    parsed = json.loads(result.root.content[0].text)
    assert "error" in parsed


# ───────────── Resources ─────────────


async def test_list_resources_returns_three() -> None:
    from mcp.types import ListResourcesRequest

    server = build_server()
    handler = server.request_handlers[ListResourcesRequest]
    result = await handler(ListResourcesRequest(method="resources/list"))
    uris = {str(r.uri) for r in result.root.resources}
    assert {
        "bash-vet://demo/clean",
        "bash-vet://demo/dangerous",
        "bash-vet://demo/sneaky",
    } <= uris


async def test_read_resource_clean_demo() -> None:
    from mcp.types import ReadResourceRequest, ReadResourceRequestParams

    server = build_server()
    handler = server.request_handlers[ReadResourceRequest]
    from pydantic import AnyUrl

    result = await handler(
        ReadResourceRequest(
            method="resources/read",
            params=ReadResourceRequestParams(uri=AnyUrl("bash-vet://demo/clean")),
        )
    )
    text = result.root.contents[0].text
    parsed = json.loads(text)
    assert parsed["verdict"] == "clean"


async def test_read_resource_dangerous_demo() -> None:
    from mcp.types import ReadResourceRequest, ReadResourceRequestParams

    server = build_server()
    handler = server.request_handlers[ReadResourceRequest]
    from pydantic import AnyUrl

    result = await handler(
        ReadResourceRequest(
            method="resources/read",
            params=ReadResourceRequestParams(uri=AnyUrl("bash-vet://demo/dangerous")),
        )
    )
    text = result.root.contents[0].text
    parsed = json.loads(text)
    assert parsed["verdict"] == "block"
    assert parsed["finding_count"] >= 1


# ───────────── Prompts ─────────────


async def test_list_prompts_returns_two() -> None:
    from mcp.types import ListPromptsRequest

    server = build_server()
    handler = server.request_handlers[ListPromptsRequest]
    result = await handler(ListPromptsRequest(method="prompts/list"))
    names = {p.name for p in result.root.prompts}
    assert names == {"vet-this-command", "audit-script"}


@pytest.mark.parametrize("prompt_name", ["vet-this-command", "audit-script"])
async def test_get_prompt_returns_walkthrough_text(prompt_name: str) -> None:
    from mcp.types import GetPromptRequest, GetPromptRequestParams

    server = build_server()
    handler = server.request_handlers[GetPromptRequest]
    result = await handler(
        GetPromptRequest(
            method="prompts/get",
            params=GetPromptRequestParams(name=prompt_name, arguments={}),
        )
    )
    text = result.root.messages[0].content.text
    assert len(text) > 50
    # Each prompt should reference at least one of the tools it walks through
    assert any(tool in text for tool in {"vet_command", "vet_command_chain", "list_detection_rules"})


async def test_get_prompt_vet_chain_arg_passed() -> None:
    """When chain=true is passed, the walkthrough should reference vet_command_chain."""
    from mcp.types import GetPromptRequest, GetPromptRequestParams

    server = build_server()
    handler = server.request_handlers[GetPromptRequest]
    result = await handler(
        GetPromptRequest(
            method="prompts/get",
            params=GetPromptRequestParams(name="vet-this-command", arguments={"chain": "true"}),
        )
    )
    text = result.root.messages[0].content.text
    assert "vet_command_chain" in text


# ─────────────── Coverage gap fillers (overnight Phase 1) ───────────────


async def test_read_resource_sneaky_demo() -> None:
    """Coverage: server.py:182-183 — sneaky demo URI dispatch."""
    from mcp.types import ReadResourceRequest, ReadResourceRequestParams

    server = build_server()
    handler = server.request_handlers[ReadResourceRequest]
    from pydantic import AnyUrl

    result = await handler(
        ReadResourceRequest(
            method="resources/read",
            params=ReadResourceRequestParams(uri=AnyUrl("bash-vet://demo/sneaky")),
        )
    )
    text = result.root.contents[0].text
    parsed = json.loads(text)
    # The sneaky demo's command_chain=True escalation should yield BLOCK
    assert parsed["verdict"] in ("block", "review", "caution")


async def test_read_resource_unknown_uri_returns_error() -> None:
    """Coverage: server.py:184 — unknown URI fallback."""
    from mcp.types import ReadResourceRequest, ReadResourceRequestParams

    server = build_server()
    handler = server.request_handlers[ReadResourceRequest]
    from pydantic import AnyUrl

    result = await handler(
        ReadResourceRequest(
            method="resources/read",
            params=ReadResourceRequestParams(uri=AnyUrl("bash-vet://demo/does-not-exist")),
        )
    )
    text = result.root.contents[0].text
    parsed = json.loads(text)
    assert "error" in parsed


async def test_get_prompt_unknown_returns_unknown_prompt_result() -> None:
    """Coverage: server.py:262 — unknown prompt name fallback."""
    from mcp.types import GetPromptRequest, GetPromptRequestParams

    server = build_server()
    handler = server.request_handlers[GetPromptRequest]
    result = await handler(
        GetPromptRequest(
            method="prompts/get",
            params=GetPromptRequestParams(name="not-a-real-prompt", arguments={}),
        )
    )
    text = result.root.messages[0].content.text
    assert "Unknown prompt" in text or "not-a-real-prompt" in text
