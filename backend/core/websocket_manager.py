"""AISS - WebSocket Manager
Handles real-time broadcasting of threats to all connected clients.

BUG FIX: Added user_id parameter to broadcast() so the AgentOrchestrator's
_broadcast(user_id=..., data=...) calls work correctly. The user_id is
accepted but currently broadcasts to all connections (kept for future
per-user channel support without breaking callers).
"""

import json
from fastapi import WebSocket
from utils.logger import setup_logger

logger = setup_logger("websocket_manager")


class WebSocketManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"🔌 WebSocket connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"🔌 WebSocket disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, data: dict, user_id: str | None = None) -> None:
        """
        Broadcast data to all connected clients.

        Args:
            data:    The JSON-serialisable payload to send.
            user_id: Optional — reserved for future per-user routing.
                     Currently broadcasts to all connections so that agent
                     events (which supply user_id) are not silently dropped.
        """
        message = json.dumps(data)
        dead = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                dead.append(connection)
        for conn in dead:
            self.disconnect(conn)

    async def send_personal(self, websocket: WebSocket, data: dict):
        await websocket.send_text(json.dumps(data))
