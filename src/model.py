"""Simple and clean LLM model interface supporting both cloud and local models"""

import json
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

import httpx
from google import genai
from openai import OpenAI

from global_config import global_config, logger

try:
    import anthropic

    ANTHROPIC_AVAILABLE = True
except ImportError:
    anthropic = None
    ANTHROPIC_AVAILABLE = False

# Global clients
clients: Dict[str, Any] = {}
model_config = {
    "model": "gpt-4o",
    "temperature": 1.0,
    "max_tokens": 16000,
    "timeout": 900,
    "stall_timeout": 180,
    "stream": True,
    "extra_body": {},
    "stage_options": {},
}

# One stable id per process: providers such as OpenCode Go use it for routing
# and prompt caching ("x-opencode-session").
SESSION_ID = f"knighter-{uuid.uuid4().hex[:16]}"
USER_AGENT = "knighter/0.2"

_metrics_lock = threading.Lock()
_metrics_path: Optional[Path] = None


def init_llm():
    """Initialize LLM clients from configuration"""
    keys = global_config.get_key_config()

    # Initialize OpenAI client (or compatible)
    if "openai_key" in keys:
        clients["openai"] = OpenAI(api_key=keys["openai_key"])

    # Initialize local/custom OpenAI-compatible client
    if "base_url" in keys:
        clients["local"] = OpenAI(
            base_url=keys["base_url"], api_key=keys.get("api_key", "dummy")
        )

    # Initialize Claude client
    if "claude_key" in keys and ANTHROPIC_AVAILABLE:
        clients["claude"] = anthropic.Anthropic(api_key=keys["claude_key"])

    # Initialize Google client
    if "google_key" in keys:
        clients["google"] = genai.Client(api_key=keys["google_key"])

    # Initialize DeepSeek client
    if "deepseek_key" in keys:
        clients["deepseek"] = OpenAI(
            api_key=keys["deepseek_key"], base_url="https://api.deepseek.com/v1"
        )

    # Set model configuration from config.yaml
    model_config["model"] = global_config.get("model", "gpt-4o")
    model_config["temperature"] = global_config.get("temperature", 1.0)
    model_config["max_tokens"] = global_config.get("max_tokens", 16000)
    model_config["timeout"] = global_config.get("llm_timeout", 900)
    model_config["stall_timeout"] = global_config.get("llm_stall_timeout", 180)
    model_config["stream"] = global_config.get("llm_stream", True)
    model_config["extra_body"] = global_config.get("llm_extra_body", {}) or {}
    model_config["stage_options"] = global_config.get("stage_options", {}) or {}

    # Initialize custom providers (OpenAI-compatible endpoints)
    providers = keys.get("providers", {})
    for name, config in providers.items():
        headers = {"User-Agent": USER_AGENT}
        headers.update(config.get("headers", {}))
        if config.get("session_header"):
            headers[config["session_header"]] = SESSION_ID
        clients[name] = OpenAI(
            base_url=config["base_url"],
            api_key=config.get("api_key", "dummy"),
            default_headers=headers,
            # With streaming, `read` is the longest silence between chunks: a
            # live reasoning model streams tokens every few seconds, so this
            # detects stalled requests without capping long generations.
            timeout=httpx.Timeout(
                connect=30, read=model_config["stall_timeout"], write=60, pool=60
            ),
            max_retries=0,  # retries are handled (and logged) in invoke_llm
        )
        clients[name]._knighter_stream = model_config["stream"]

    global _metrics_path
    result_dir = global_config.get("result_dir")
    if result_dir:
        _metrics_path = Path(result_dir) / "llm_calls.jsonl"
        _metrics_path.parent.mkdir(parents=True, exist_ok=True)

    logger.info(
        f"Init LLM with model: {model_config['model']} (session {SESSION_ID})"
    )

    if not clients:
        raise ValueError("No LLM clients configured")


def get_client_and_model(model_name: str) -> tuple:
    """Determine which client to use and actual model name"""

    # Model to client mapping
    model_mapping = {
        # OpenAI models
        "gpt-4o": ("openai", "gpt-4o"),
        "o1": ("openai", "o1"),
        "o3-mini": ("openai", "o3-mini"),
        "o4-mini": ("openai", "o4-mini"),
        "o1-preview": ("openai", "o1-preview"),
        "gpt-5": ("openai", "gpt-5"),
        # Claude models
        "claude": ("claude", "claude-3-5-sonnet-20241022"),
        "claude-3-5-sonnet": ("claude", "claude-3-5-sonnet-20241022"),
        "claude-3-5-haiku": ("claude", "claude-3-5-haiku-20241022"),
        "claude-3-opus": ("claude", "claude-3-opus-20240229"),
        # Google models
        "google": ("google", "gemini-2.0-flash-exp"),
        "gemini": ("google", "gemini-2.0-flash-exp"),
        # DeepSeek models
        "deepseek-reasoner": ("deepseek", "deepseek-reasoner"),
        "deepseek-chat": ("deepseek", "deepseek-chat"),
    }

    # Check if it's a known model
    if model_name in model_mapping:
        client_name, actual_model = model_mapping[model_name]
        if client_name in clients:
            return clients[client_name], actual_model

    # Check if it's a local model (format: local:model_name)
    if model_name.startswith("local:") and "local" in clients:
        actual_model = model_name[6:]  # Remove "local:" prefix
        return clients["local"], actual_model

    # Check custom providers (format: provider:model_name)
    if ":" in model_name:
        provider, actual_model = model_name.split(":", 1)
        if provider in clients:
            return clients[provider], actual_model

    # Default to local client if available
    if "local" in clients:
        return clients["local"], model_name

    # Fallback to OpenAI if available
    if "openai" in clients:
        return clients["openai"], model_name

    raise ValueError(f"No client available for model {model_name}")


def _record_call(entry: Dict[str, Any]):
    """Append one line per LLM call (for speed/cost analysis)."""
    if _metrics_path is None:
        return
    entry["session"] = SESSION_ID
    with _metrics_lock, open(_metrics_path, "a") as handle:
        handle.write(json.dumps(entry) + "\n")


def _usage_fields(response) -> Dict[str, Any]:
    usage = getattr(response, "usage", None)
    if usage is None:
        return {}
    details = getattr(usage, "completion_tokens_details", None)
    prompt_details = getattr(usage, "prompt_tokens_details", None)
    return {
        "prompt_tokens": getattr(usage, "prompt_tokens", None),
        "completion_tokens": getattr(usage, "completion_tokens", None),
        "reasoning_tokens": getattr(details, "reasoning_tokens", None),
        "cached_tokens": getattr(prompt_details, "cached_tokens", None),
    }


def _stream_completion(client, kwargs: Dict[str, Any], start: float):
    """Stream a chat completion; returns (content, usage fields).

    Two independent limits:
    * stall: the httpx ``read`` timeout (``llm_stall_timeout``) fires when no
      bytes arrive for that long;
    * deadline: a watchdog timer closes the connection once the whole call
      exceeds ``llm_timeout``. It cannot be a check inside the chunk loop:
      SSE keep-alive comments keep the connection alive without yielding
      chunks, which kept one request open for 6164 s (see RESEARCH_LOG).
    """
    stream = client.chat.completions.create(
        **kwargs, stream=True, stream_options={"include_usage": True}
    )
    deadline = model_config["timeout"]
    expired = threading.Event()

    def kill():
        expired.set()
        try:
            stream.response.close()
        except Exception:
            pass

    watchdog = threading.Timer(max(1.0, deadline - (time.monotonic() - start)), kill)
    watchdog.daemon = True
    watchdog.start()
    parts = []
    usage: Dict[str, Any] = {}
    try:
        for chunk in stream:
            if chunk.usage is not None:
                usage = _usage_fields(chunk)
            if chunk.choices:
                delta = chunk.choices[0].delta
                if delta is not None and delta.content:
                    parts.append(delta.content)
    except Exception:
        if expired.is_set():
            raise TimeoutError(f"LLM call exceeded {deadline}s")
        raise
    finally:
        watchdog.cancel()
        stream.close()
    if expired.is_set():
        raise TimeoutError(f"LLM call exceeded {deadline}s")
    return "".join(parts), usage


def invoke_llm(
    prompt: str,
    temperature: Optional[float] = None,
    model: Optional[str] = None,
    max_tokens: Optional[int] = None,
    stage: str = "unknown",
) -> Optional[str]:
    """Invoke LLM with the given prompt.

    ``stage`` names the pipeline step (e.g. "patch2pattern", "repair_syntax"):
    it selects ``stage_options[stage]`` from the config (model, temperature,
    max_tokens, extra_body) and tags the call in ``llm_calls.jsonl``.
    """
    options = model_config["stage_options"].get(stage, {})
    model = model or options.get("model") or model_config["model"]
    if temperature is None:
        temperature = options.get("temperature", model_config["temperature"])
    max_tokens = max_tokens or options.get("max_tokens") or model_config["max_tokens"]
    extra_body = {**model_config["extra_body"], **options.get("extra_body", {})}

    logger.info(f"Start LLM process: {model} [{stage}]")

    # Simple token check
    if len(prompt) > 400000:  # ~100k tokens
        logger.warning("Prompt too long, skipping")
        return None

    # Get client and actual model name
    try:
        client, actual_model = get_client_and_model(model)
    except ValueError as e:
        logger.error(f"Error getting client and model for  {model}")
        logger.error(str(e))
        return None

    # Retry logic
    for attempt in range(6):
        start = time.monotonic()
        usage: Dict[str, Any] = {}
        try:
            # Handle different client types
            if isinstance(
                client, anthropic.Anthropic if ANTHROPIC_AVAILABLE else type(None)
            ):
                # Claude API
                response = client.messages.create(
                    model=actual_model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
                answer = response.content[0].text

            elif isinstance(client, genai.Client):
                response = client.models.generate_content(
                    model=actual_model,
                    contents=prompt,
                )
                answer = response.text

            else:  # OpenAI or compatible
                kwargs = {
                    "model": actual_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_completion_tokens": max_tokens,
                }

                # Only add temperature for models that support it
                no_temp_models = ["o1", "o3-mini", "o4-mini", "o1-preview", "gpt-5"]
                if not any(m in actual_model for m in no_temp_models):
                    kwargs["temperature"] = temperature
                if extra_body:
                    kwargs["extra_body"] = extra_body

                if getattr(client, "_knighter_stream", False):
                    answer, usage = _stream_completion(client, kwargs, start)
                else:
                    response = client.chat.completions.create(**kwargs)
                    usage = _usage_fields(response)
                    answer = response.choices[0].message.content

            if not answer or not answer.strip():
                # Seen in practice: a reasoning model spends the whole budget
                # thinking and returns no content. Retry instead of passing
                # None downstream.
                raise ValueError("empty response content")

            duration = time.monotonic() - start
            logger.info(f"Finish LLM process [{stage}] in {duration:.1f}s")
            _record_call(
                {"ts": time.time(), "stage": stage, "model": model, "ok": True,
                 "attempt": attempt + 1, "seconds": round(duration, 2),
                 "prompt_chars": len(prompt), **usage}
            )

            # Remove think tags if present
            if answer and "<think>" in answer:
                answer = answer.split("</think>")[-1].strip()

            return answer

        except Exception as e:
            duration = time.monotonic() - start
            logger.error(f"Error attempt {attempt + 1} [{stage}]: {e}")
            _record_call(
                {"ts": time.time(), "stage": stage, "model": model, "ok": False,
                 "attempt": attempt + 1, "seconds": round(duration, 2),
                 "prompt_chars": len(prompt), "error": str(e)[:300], **usage}
            )
            if attempt >= 5:
                logger.error("Failed too many times")
                raise e
            time.sleep(min(2 ** (attempt + 1), 60))

    return None


def get_embeddings(text: str) -> list:
    """Get embeddings using OpenAI API"""
    if "openai" not in clients:
        raise ValueError("OpenAI client required for embeddings")

    response = clients["openai"].embeddings.create(
        input=text, model="text-embedding-ada-002"
    )
    return response.data[0].embedding


# Backwards compatibility
def num_tokens_from_string(string: str) -> int:
    """Simple token approximation"""
    return len(string) // 4
