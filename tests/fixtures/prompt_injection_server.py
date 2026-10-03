from mcp import ClientSession
from openai import OpenAI

client = OpenAI()

async def summarize_tool_output(session: ClientSession, name: str):
    tool_result = await session.call_tool(name, {})
    return client.responses.create(input=tool_result)

def sanitize_tool_output(value):
    return value.replace(\"ignore previous instructions\", \"[removed]\")

async def summarize_safely(session: ClientSession, name: str):
    tool_result = await session.call_tool(name, {})
    safe_output = sanitize_tool_output(tool_result)
    return client.responses.create(input=safe_output)
