"""PSYCHE AI — Windows Local HTTPS/mTLS Companion Gateway (Starlette + Uvicorn ASGI)."""

from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import parse_qs

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect

from core.contracts.validator import ContractValidationError
from core.pipeline.orchestrator import PsycheIntelligenceOrchestrator
from core.storage.database import PsycheDatabase, utc_now_iso
from core.subsystems.fortress.crypto_vault import VaultLockedError


class PsycheGatewayService:
    """Stateful local gateway coordinator bridging Android sync requests to PSYCHE Orchestrator."""

    def __init__(
        self,
        *,
        db: PsycheDatabase,
        orchestrator: PsycheIntelligenceOrchestrator | None = None,
        windows_host_endpoint: str = "https://127.0.0.1:8443",
        windows_tls_cert_sha256: str = "a" * 64,
        enforce_clock_skew: bool = True,
    ) -> None:
        self.db = db
        self.orchestrator = orchestrator or PsycheIntelligenceOrchestrator(db=db)
        self.pairing = self.orchestrator.people_memory.pairing
        self.presence = self.orchestrator.presence
        self.windows_host_endpoint = windows_host_endpoint
        self.windows_tls_cert_sha256 = windows_tls_cert_sha256
        self.enforce_clock_skew = enforce_clock_skew
        self._ws_subscribers: set[asyncio.Queue[dict[str, Any]]] = set()

    def _broadcast_event(self, event_type: str, payload: dict[str, Any]) -> None:
        message = {
            "event_type": event_type,
            "timestamp_utc": utc_now_iso(),
            "payload": payload,
        }
        for q in list(self._ws_subscribers):
            q.put_nowait(message)

    @staticmethod
    def _error_response(status_code: int, error_code: str, message: str) -> JSONResponse:
        return JSONResponse(
            {"error_code": error_code, "message": message},
            status_code=status_code,
        )

    @staticmethod
    def _map_exception(exc: Exception) -> JSONResponse:
        if isinstance(exc, VaultLockedError):
            return PsycheGatewayService._error_response(423, "VAULT_LOCKED", str(exc))
        if isinstance(exc, PermissionError):
            return PsycheGatewayService._error_response(
                401, "SIGNATURE_OR_DEVICE_UNAUTHORIZED", str(exc)
            )
        if isinstance(exc, ContractValidationError):
            if exc.error_code in {"REPLAY_BATCH_DETECTED", "CLOCK_SKEW_EXCEEDED"}:
                return PsycheGatewayService._error_response(409, exc.error_code, str(exc))
            return PsycheGatewayService._error_response(422, exc.error_code, str(exc))
        if isinstance(exc, KeyError):
            return PsycheGatewayService._error_response(404, "RESOURCE_NOT_FOUND", str(exc))
        return PsycheGatewayService._error_response(400, "BAD_REQUEST", str(exc))

    async def handle_health(self, request: Request) -> JSONResponse:
        hw = self.orchestrator.economy.capture_hardware_snapshot()
        return JSONResponse(
            {
                "status": "OK",
                "schema_version": "1.0.0",
                "timestamp_utc": utc_now_iso(),
                "vault_locked": self.db.vault.is_locked,
                "desktop_presence_state": self.presence.desktop_presence_state,
                "recommended_sync_mode": self.presence.get_recommended_sync_mode(
                    self.presence.get_latest_mobile_presence()
                ),
                "gpu_name": hw.gpu_name,
                "free_vram_mib": hw.vram_free_mib,
                "total_vram_mib": hw.vram_total_mib,
                "process_ram_mib": hw.process_rss_mib,
                "external_providers_enabled": False,
            }
        )

    async def handle_pair_init(self, request: Request) -> JSONResponse:
        try:
            if self.db.vault.is_locked:
                raise VaultLockedError("Database access denied: PSYCHE FORTRESS vault is locked")
            raw_body = await request.body()
            body = json.loads(raw_body.decode("utf-8")) if raw_body.strip() else {}
            qr_payload = self.pairing.initiate_pairing_session(
                windows_host_endpoint=body.get(
                    "windows_host_endpoint", self.windows_host_endpoint
                ),
                windows_tls_cert_sha256=body.get(
                    "windows_tls_cert_sha256", self.windows_tls_cert_sha256
                ),
                ttl_seconds=int(body.get("ttl_seconds", 300)),
            )
            return JSONResponse(qr_payload, status_code=200)
        except Exception as exc:
            return self._map_exception(exc)

    async def handle_pair_confirm(self, request: Request) -> JSONResponse:
        try:
            if self.db.vault.is_locked:
                raise VaultLockedError("Database access denied: PSYCHE FORTRESS vault is locked")
            payload = await request.json()
            sas_6digit = (
                request.headers.get("x-user-confirmed-sas")
                or request.query_params.get("sas_6digit")
            )
            resp = self.pairing.confirm_pairing(
                payload,
                user_confirmed_sas_6digit=sas_6digit,
            )
            status_code = 200 if resp["status"] == "PAIRED" else 403
            if resp["status"] == "PAIRED":
                self._broadcast_event("DEVICE_PAIRED", {"device_id": resp["device_id"]})
            return JSONResponse(resp, status_code=status_code)
        except Exception as exc:
            return self._map_exception(exc)

    async def handle_contacts_sync(self, request: Request) -> JSONResponse:
        try:
            payload = await request.json()
            resp = self.orchestrator.people_memory.sync_android_contacts(
                payload,
                require_crypto_signature=True,
            )
            self._broadcast_event(
                "CONTACTS_SYNCED",
                {"count": len(resp.get("resolved_mappings", []))},
            )
            return JSONResponse(resp, status_code=200)
        except Exception as exc:
            return self._map_exception(exc)

    async def handle_notifications_ingest(self, request: Request) -> JSONResponse:
        try:
            payload = await request.json()
            resp = self.orchestrator.people_memory.ingest_notification_batch(
                payload,
                require_crypto_signature=True,
                enforce_clock_skew=self.enforce_clock_skew,
            )
            self._broadcast_event(
                "NOTIFICATIONS_INGESTED",
                {
                    "batch_id": resp["batch_id"],
                    "acked_event_ids": resp["acked_event_ids"],
                },
            )
            return JSONResponse(resp, status_code=200)
        except Exception as exc:
            return self._map_exception(exc)

    async def handle_presence_heartbeat(self, request: Request) -> JSONResponse:
        try:
            payload = await request.json()
            resp = self.presence.process_heartbeat(
                payload,
                require_crypto_signature=True,
            )
            self._broadcast_event("PRESENCE_UPDATED", resp)
            return JSONResponse(resp, status_code=200)
        except Exception as exc:
            return self._map_exception(exc)

    async def handle_synthesize_event(self, request: Request) -> JSONResponse:
        try:
            event_id = request.path_params["event_id"]
            raw_body = await request.body()
            body = json.loads(raw_body.decode("utf-8")) if raw_body.strip() else {}
            packet = self.orchestrator.synthesize_for_event(
                event_id=event_id,
                user_explicit_assumption=body.get("user_explicit_assumption"),
                reference_now_utc=body.get("reference_now_utc"),
            )
            self._broadcast_event(
                "SYNTHESIS_READY",
                {
                    "synthesis_id": packet["synthesis_id"],
                    "trigger_event_id": packet["trigger_event_id"],
                    "person_id": packet["person_id"],
                },
            )
            return JSONResponse(packet, status_code=200)
        except Exception as exc:
            return self._map_exception(exc)

    async def handle_synthesis_review(self, request: Request) -> JSONResponse:
        try:
            synthesis_id = request.path_params["synthesis_id"]
            payload = await request.json()
            raw_decision = payload["decision"]
            decision_map = {
                "APPROVED_AS_IS": "ACCEPTED_AS_IS",
                "EDITED_AND_APPROVED": "EDITED_BY_USER",
            }
            decision = decision_map.get(raw_decision, raw_decision)
            final_text = payload.get("user_final_edited_text", payload.get("final_user_text"))
            res = self.orchestrator.record_user_review_decision(
                synthesis_id=synthesis_id,
                decision=decision,
                user_final_edited_text=final_text,
            )
            self._broadcast_event("SYNTHESIS_REVIEWED", res)
            return JSONResponse(res, status_code=200)
        except Exception as exc:
            return self._map_exception(exc)

    async def handle_websocket_events(self, websocket: WebSocket) -> None:
        await websocket.accept()
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._ws_subscribers.add(queue)
        try:
            await websocket.send_json(
                {
                    "event_type": "GATEWAY_CONNECTED",
                    "timestamp_utc": utc_now_iso(),
                    "payload": {
                        "desktop_presence_state": self.presence.desktop_presence_state,
                        "vault_locked": self.db.vault.is_locked,
                    },
                }
            )
            while True:
                recv_task = asyncio.create_task(websocket.receive_text())
                queue_task = asyncio.create_task(queue.get())
                done, pending = await asyncio.wait(
                    {recv_task, queue_task},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for p in pending:
                    p.cancel()
                if recv_task in done:
                    msg = recv_task.result()
                    if msg.strip().upper() == "PING":
                        await websocket.send_json(
                            {"event_type": "PONG", "timestamp_utc": utc_now_iso()}
                        )
                if queue_task in done:
                    await websocket.send_json(queue_task.result())
        except WebSocketDisconnect:
            pass
        finally:
            self._ws_subscribers.discard(queue)


def create_gateway_app(
    *,
    db: PsycheDatabase,
    orchestrator: PsycheIntelligenceOrchestrator | None = None,
    windows_host_endpoint: str = "https://127.0.0.1:8443",
    windows_tls_cert_sha256: str = "a" * 64,
    enforce_clock_skew: bool = True,
) -> tuple[Starlette, PsycheGatewayService]:
    """Builds the Starlette ASGI application and bound PsycheGatewayService instance."""
    service = PsycheGatewayService(
        db=db,
        orchestrator=orchestrator,
        windows_host_endpoint=windows_host_endpoint,
        windows_tls_cert_sha256=windows_tls_cert_sha256,
        enforce_clock_skew=enforce_clock_skew,
    )
    routes = [
        Route("/v1/health", service.handle_health, methods=["GET"]),
        Route("/v1/pair/init", service.handle_pair_init, methods=["POST"]),
        Route("/v1/pair/confirm", service.handle_pair_confirm, methods=["POST"]),
        Route("/v1/contacts/sync", service.handle_contacts_sync, methods=["POST"]),
        Route("/v1/notifications/ingest", service.handle_notifications_ingest, methods=["POST"]),
        Route("/v1/presence/heartbeat", service.handle_presence_heartbeat, methods=["POST"]),
        Route("/v1/syntheses/{event_id}", service.handle_synthesize_event, methods=["POST"]),
        Route(
            "/v1/syntheses/{synthesis_id}/review",
            service.handle_synthesis_review,
            methods=["POST"],
        ),
        WebSocketRoute("/v1/ws/events", service.handle_websocket_events),
    ]
    app = Starlette(debug=False, routes=routes)
    app.state.gateway_service = service
    return app, service


class AsgiResponse:
    """Minimal HTTP response returned by AsgiTestClient."""

    def __init__(self, status_code: int, headers: dict[str, str], body: bytes) -> None:
        self.status_code = status_code
        self.headers = headers
        self.body = body

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))


class AsgiTestClient:
    """Zero-dependency ASGI HTTP & WebSocket client for Starlette tests without httpx2."""

    def __init__(self, app: Starlette) -> None:
        self.app = app

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | list[Any] | None = None,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
    ) -> AsgiResponse:
        if json_body is not None:
            raw_body = json.dumps(json_body).encode("utf-8")
        else:
            raw_body = body

        clean_path, _, query_str = path.partition("?")
        raw_headers: list[tuple[bytes, bytes]] = [(b"host", b"127.0.0.1:8443")]
        if json_body is not None:
            raw_headers.append((b"content-type", b"application/json"))
        raw_headers.append((b"content-length", str(len(raw_body)).encode("ascii")))
        if headers:
            for k, v in headers.items():
                raw_headers.append((k.lower().encode("latin-1"), v.encode("latin-1")))

        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method.upper(),
            "scheme": "https",
            "path": clean_path,
            "raw_path": clean_path.encode("ascii"),
            "query_string": query_str.encode("latin-1"),
            "headers": raw_headers,
            "client": ("127.0.0.1", 54321),
            "server": ("127.0.0.1", 8443),
            "state": {},
        }

        sent_body = False
        resp_status = 500
        resp_headers: dict[str, str] = {}
        resp_chunks: list[bytes] = []

        async def receive() -> dict[str, Any]:
            nonlocal sent_body
            if not sent_body:
                sent_body = True
                return {"type": "http.request", "body": raw_body, "more_body": False}
            return {"type": "http.disconnect"}

        async def send(message: dict[str, Any]) -> None:
            nonlocal resp_status
            if message["type"] == "http.response.start":
                resp_status = int(message["status"])
                for hk, hv in message.get("headers", []):
                    resp_headers[hk.decode("latin-1").lower()] = hv.decode("latin-1")
            elif message["type"] == "http.response.body":
                resp_chunks.append(message.get("body", b""))

        asyncio.run(self.app(scope, receive, send))
        return AsgiResponse(resp_status, resp_headers, b"".join(resp_chunks))

    def get(self, path: str, *, headers: dict[str, str] | None = None) -> AsgiResponse:
        return self.request("GET", path, headers=headers)

    def post(
        self,
        path: str,
        *,
        json_body: dict[str, Any] | list[Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> AsgiResponse:
        return self.request("POST", path, json_body=json_body, headers=headers)

    def websocket_probe(
        self,
        path: str = "/v1/ws/events",
        *,
        send_text: str | None = "PING",
    ) -> list[dict[str, Any]]:
        """Opens a raw ASGI WebSocket scope, captures greeting + optional PONG, and disconnects."""
        received_frames: list[dict[str, Any]] = []
        clean_path, _, query_str = path.partition("?")
        scope = {
            "type": "websocket",
            "asgi": {"version": "3.0"},
            "scheme": "wss",
            "path": clean_path,
            "raw_path": clean_path.encode("ascii"),
            "query_string": query_str.encode("latin-1"),
            "headers": [(b"host", b"127.0.0.1:8443")],
            "subprotocols": [],
            "client": ("127.0.0.1", 54322),
            "server": ("127.0.0.1", 8443),
            "state": {},
        }

        async def _run() -> None:
            in_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
            await in_queue.put({"type": "websocket.connect"})
            if send_text is not None:
                await in_queue.put({"type": "websocket.receive", "text": send_text})

            done_event = asyncio.Event()

            async def receive() -> dict[str, Any]:
                return await in_queue.get()

            async def send(message: dict[str, Any]) -> None:
                if message["type"] == "websocket.send" and "text" in message:
                    received_frames.append(json.loads(message["text"]))
                    expected_count = 2 if send_text is not None else 1
                    if len(received_frames) >= expected_count:
                        await in_queue.put({"type": "websocket.disconnect", "code": 1000})
                        done_event.set()
                elif message["type"] == "websocket.close":
                    done_event.set()

            app_task = asyncio.create_task(self.app(scope, receive, send))
            try:
                await asyncio.wait_for(done_event.wait(), timeout=2.0)
                await asyncio.wait_for(app_task, timeout=2.0)
            except asyncio.TimeoutError:
                await in_queue.put({"type": "websocket.disconnect", "code": 1000})
                app_task.cancel()

        asyncio.run(_run())
        return received_frames
