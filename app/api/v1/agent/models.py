from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base

# AGENT (equipo remoto que envía reportes)
class Agent(Base):
    __tablename__ = "agents"

    # ID único del agente (proporcionado por el instalador)
    id = Column(String, primary_key=True)

    hostname = Column(String, nullable=True)
    os_type = Column(String, nullable=False)

    api_key = Column(String, nullable=False)

    last_seen = Column(DateTime, default=func.now(), onupdate=func.now())

    # Reportes enviados por el agente
    reports = relationship(
        "AgentReport",
        back_populates="agent",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    # Comandos enviados hacia el agente
    commands = relationship(
        "CommandQueue",
        back_populates="agent",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

# AGENT REPORT (datos enviados por el agente)
class AgentReport(Base):
    __tablename__ = "agent_reports"

    id = Column(Integer, primary_key=True, index=True)

    # Agente asociado
    agent_id = Column(String, ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)

    # NUEVO
    # IP del equipo desde donde el agente envió el reporte
    ip_address = Column(String(45), nullable=True)

    # Puertos abiertos reportados (JSON)
    ports = Column(JSON, nullable=False)

    timestamp = Column(
        DateTime,
        server_default=func.now(),
        nullable=False
    )

    agent = relationship("Agent", back_populates="reports")

# COMMAND QUEUE (comandos enviados al agente)
class CommandQueue(Base):
    __tablename__ = "command_queue"

    id = Column(Integer, primary_key=True)

    # Agente que ejecutará el comando
    agent_id = Column(String, ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)

    action = Column(String, nullable=False)  # Ej: "close_port"
    port = Column(Integer)

    executed = Column(Boolean, default=False)

    timestamp = Column(DateTime, default=func.now())

    agent = relationship("Agent", back_populates="commands")


