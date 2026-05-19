"""
broker.py — Taskiq Redis Broker (shared singleton)
===================================================
Both main.py (FastAPI) and scanner/tasks.py (worker) import this module.
Keeping it in its own file prevents circular imports.

To start the worker process:
    taskiq worker broker:broker scanner.tasks

Environment variables:
    REDIS_URL — default "redis://localhost:6379"
"""

import os
from dotenv import load_dotenv

load_dotenv()

# pyrefly: ignore [missing-import]
from taskiq_redis import ListQueueBroker, RedisAsyncResultBackend

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

# ── Result backend — stores task return values in Redis ───────────────────────
result_backend = RedisAsyncResultBackend(REDIS_URL)

# ── Broker — ListQueueBroker uses a Redis List as a FIFO task queue ───────────
# ListQueueBroker is the recommended Taskiq broker for Redis.
# It is simpler than PubSubBroker and handles worker crashes gracefully
# (tasks are re-queued if the worker dies mid-execution).
broker = ListQueueBroker(REDIS_URL).with_result_backend(result_backend)
