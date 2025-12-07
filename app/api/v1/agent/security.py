from fastapi import Header, HTTPException, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from .models import Agent
from datetime import datetime


def validate_agent_id(
    x_agent_id: str = Header(None, alias="X-Agent-ID"),
    x_api_key: str = Header(None, alias="X-API-Key"),
    db: Session = Depends(get_db)
):
    """
    Valida que el agente exista y que su API KEY coincida.
    """

    if not x_agent_id:
        raise HTTPException(401, "Missing X-Agent-ID header")

    agent = db.query(Agent).filter(Agent.id == x_agent_id).first()

    if not agent:
        raise HTTPException(401, "Invalid Agent ID")

    # 🔥 Nueva validación obligatoria
    if agent.api_key and x_api_key != agent.api_key:
        raise HTTPException(401, "Invalid API Key")

    # Update last_seen automáticamente
    agent.last_seen = datetime.utcnow()
    db.commit()

    return agent
