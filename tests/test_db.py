"""Tests for database manager."""

import pytest
from pathlib import Path


@pytest.mark.asyncio
async def test_database_init():
    """Test database initialization."""
    from wafford.db.manager import DatabaseManager
    
    db = DatabaseManager(db_path=Path("/tmp/test_wafford.db"))
    await db.init_db()
    assert db._initialized
    await db.close()


@pytest.mark.asyncio
async def test_create_session():
    """Test session creation."""
    from wafford.db.manager import DatabaseManager
    
    db = DatabaseManager(db_path=Path("/tmp/test_wafford.db"))
    await db.init_db()
    session_id = await db.create_session("Test Session", "Test description")
    assert session_id > 0
    await db.close()


@pytest.mark.asyncio
async def test_get_sessions():
    """Test retrieving sessions."""
    from wafford.db.manager import DatabaseManager
    
    db = DatabaseManager(db_path=Path("/tmp/test_wafford.db"))
    await db.init_db()
    await db.create_session("Session 1")
    sessions = await db.get_sessions()
    assert len(sessions) > 0
    await db.close()
