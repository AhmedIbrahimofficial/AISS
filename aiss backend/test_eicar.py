import asyncio
import httpx
import uuid

BASE = "http://127.0.0.1:8000"


async def main():
    uid = str(uuid.uuid4())[:8]
    email = f"test{uid}@example.com"
    async with httpx.AsyncClient() as c:
        r = await c.post(
            f"{BASE}/api/auth/register",
            json={"username": f"test{uid}", "email": email, "password": "TestPass123!"},
        )
        print("register", r.status_code)
        r = await c.post(
            f"{BASE}/api/auth/login",
            json={"email": email, "password": "TestPass123!"},
        )
        data = r.json()
        token = data["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        r = await c.post(f"{BASE}/api/security/eicar-test", headers=headers)
        print("eicar", r.status_code, r.json())
        tid = r.json()["task_id"]

        for i in range(20):
            await asyncio.sleep(5)
            r = await c.get(f"{BASE}/api/security/tasks/{tid}", headers=headers)
            d = r.json()["data"]
            print(
                f"[{i + 1}] status={d['status']} findings={d['findings_count']} error={d['error']}"
            )
            if d["status"] in ("completed", "failed", "cancelled"):
                print("findings:", d["findings"])
                break


if __name__ == "__main__":
    asyncio.run(main())
