import pytest

from app.main import health


@pytest.mark.asyncio
async def test_health() -> None:
    result = await health()
    assert result["status"] == "ok"
