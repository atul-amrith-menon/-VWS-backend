"""
test_ai_pipeline.py — Quick smoke test for the AI scan pipeline.
Run from project root: python test_ai_pipeline.py
"""
import asyncio
import os
import sys

sys.path.insert(0, ".")

from dotenv import load_dotenv
load_dotenv()

from openai import AsyncOpenAI


def section(title):
    print(f"\n{'='*50}")
    print(f"  {title}")
    print('='*50)


async def main():
    # ── 1. Env vars ───────────────────────────────────────────────────────────
    section("1. Environment Variables")
    vllm_url  = os.getenv("VLLM_BASE_URL", "NOT SET")
    analyst   = os.getenv("ANALYST_ADAPTER",  "NOT SET")
    executor  = os.getenv("EXECUTOR_ADAPTER", "NOT SET")
    redis_url = os.getenv("REDIS_URL", "NOT SET")
    jwt_key   = os.getenv("JWT_SECRET", "NOT SET")

    print(f"  VLLM_BASE_URL    : {vllm_url}")
    print(f"  ANALYST_ADAPTER  : {analyst}")
    print(f"  EXECUTOR_ADAPTER : {executor}")
    print(f"  REDIS_URL        : {redis_url}")
    print(f"  JWT_SECRET       : {jwt_key[:12]}...")

    all_set = all(v != "NOT SET" for v in [vllm_url, analyst, executor, redis_url, jwt_key])
    print(f"\n  Status: {'OK' if all_set else 'MISSING VALUES — check .env'}")

    # ── 2. Ollama model list ──────────────────────────────────────────────────
    section("2. Ollama Connectivity")
    client = AsyncOpenAI(base_url=vllm_url, api_key="not-needed")

    try:
        models_response = await client.models.list()
        model_ids = [m.id for m in models_response.data]
        print(f"  Available models: {model_ids}")
    except Exception as e:
        print(f"  ERROR: Cannot reach Ollama at {vllm_url}")
        print(f"  Detail: {e}")
        sys.exit(1)

    analyst_ok  = analyst  in model_ids
    executor_ok = executor in model_ids
    print(f"\n  Analyst  '{analyst}' : {'FOUND' if analyst_ok  else 'NOT FOUND'}")
    print(f"  Executor '{executor}' : {'FOUND' if executor_ok else 'NOT FOUND'}")

    if not analyst_ok or not executor_ok:
        print("\n  Fix: Update ANALYST_ADAPTER / EXECUTOR_ADAPTER in .env to match the model IDs above.")
        sys.exit(1)

    # ── 3. Single inference test ──────────────────────────────────────────────
    section("3. Analyst Model Inference Test")
    print(f"  Warming up '{analyst}' (first call loads weights into VRAM — may take 2-3 min)...")
    try:
        response = await asyncio.wait_for(
            client.chat.completions.create(
                model=analyst,
                messages=[
                    {"role": "system", "content": "You are a security analyst. Reply in one sentence."},
                    {"role": "user",   "content": "What is SQL Injection?"},
                ],
                max_tokens=60,
                temperature=0.1,
            ),
            timeout=300,   # 5 min — generous enough for cold VRAM load
        )
        reply = response.choices[0].message.content.strip()
        print(f"  Model reply: {reply[:120]}")
        print("\n  Status: OK")
    except asyncio.TimeoutError:
        print("  ERROR: Model timed out (300s). Try running `ollama run vultix-analyst` in a")
        print("         separate terminal first to pre-warm it, then re-run this test.")
        sys.exit(1)
    except Exception as e:
        print(f"  ERROR: {e}")
        sys.exit(1)

    # ── 4. Redis connectivity ─────────────────────────────────────────────────
    section("4. Redis Connectivity")
    import redis.asyncio as aioredis
    try:
        r = aioredis.from_url(redis_url, decode_responses=True)
        await r.ping()
        await r.aclose()
        print(f"  Redis at {redis_url}: OK")
    except Exception as e:
        print(f"  ERROR: Cannot reach Redis at {redis_url}")
        print(f"  Detail: {e}")
        sys.exit(1)

    # ── Result ────────────────────────────────────────────────────────────────
    section("RESULT")
    print("  ALL CHECKS PASSED!")
    print("  The AI scan pipeline is fully configured and ready.")
    print()


asyncio.run(main())
