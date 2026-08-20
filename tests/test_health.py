import asyncio

from httpx import ASGITransport, AsyncClient

from threat_alerting.main import create_app
from threat_alerting.settings import Settings


def test_health_returns_typed_service_metadata() -> None:
    app = create_app(Settings(app_name="Test Alerting", app_env="test"))

    async def get_health():
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.get("/health")

    response = asyncio.run(get_health())

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "Test Alerting",
        "environment": "test",
        "version": "0.1.0",
    }
