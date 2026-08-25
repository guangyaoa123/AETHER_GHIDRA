from __future__ import annotations

import json
import logging
import os
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_BRIDGE_URL = "http://127.0.0.1:8765"
PROTOCOL_VERSION = 1
logger = logging.getLogger(__name__)


class BridgeError(RuntimeError):
    """An error returned by, or while connecting to, the Java bridge."""

    def __init__(self, message: str, *, code: str = "bridge_error") -> None:
        super().__init__(message)
        self.code = code


class BridgeClient:
    """Small synchronous client for the versioned local Ghidra bridge."""

    def __init__(self, base_url: str | None = None) -> None:
        self.base_url = (base_url or os.getenv("AETHER_GHIDRA_URL", DEFAULT_BRIDGE_URL)).rstrip("/")

    def health(self) -> dict[str, Any]:
        response = self._request("GET", "/health")
        if response.get("protocol_version") != PROTOCOL_VERSION:
            raise BridgeError(
                f"Unsupported Ghidra bridge protocol version: {response.get('protocol_version')}",
                code="protocol_mismatch",
            )
        return response

    def list_programs(self) -> list[dict[str, Any]]:
        response = self._request("GET", "/v1/programs")
        return response["programs"]

    def invoke(
        self,
        program_id: str,
        capability: str,
        arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        response = self._request(
            "POST",
            "/v1/invoke",
            {
                "program_id": program_id,
                "capability": capability,
                "arguments": arguments or {},
            },
        )
        return response["result"]

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        started = time.monotonic()
        logger.debug("bridge request method=%s path=%s", method, path)
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(
            f"{self.base_url}{path}",
            data=body,
            method=method,
            headers={
                "Accept": "application/json",
                **({"Content-Type": "application/json"} if body is not None else {}),
            },
        )
        try:
            with urlopen(request, timeout=30) as response:
                decoded = json.loads(response.read().decode("utf-8"))
                logger.debug("bridge response method=%s path=%s status=%s duration=%.3fs", method, path, response.status, time.monotonic() - started)
        except HTTPError as error:
            decoded = self._decode_error(error)
            logger.warning("bridge HTTP error method=%s path=%s status=%s code=%s", method, path, error.code, decoded.get("error", {}).get("code", "http_error"))
            raise BridgeError(
                decoded.get("error", {}).get("message", str(error)),
                code=decoded.get("error", {}).get("code", "http_error"),
            ) from error
        except URLError as error:
            logger.warning("bridge unreachable method=%s path=%s reason=%s", method, path, error.reason)
            raise BridgeError(f"Could not connect to Ghidra bridge: {error.reason}", code="unreachable") from error
        except json.JSONDecodeError as error:
            logger.warning("bridge invalid JSON method=%s path=%s", method, path)
            raise BridgeError("Ghidra bridge returned invalid JSON", code="invalid_response") from error

        if "ok" in decoded and not decoded["ok"]:
            error = decoded.get("error", {})
            raise BridgeError(error.get("message", "Bridge request failed"), code=error.get("code", "bridge_error"))
        return decoded

    @staticmethod
    def _decode_error(error: HTTPError) -> dict[str, Any]:
        try:
            return json.loads(error.read().decode("utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
