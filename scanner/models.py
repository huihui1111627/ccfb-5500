"""扫描平台数据模型与存储层。"""
import json
import os
import time
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, ForeignKey, Integer, String, Text, create_engine, event, func,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "scanner", "data", "scanner.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

Base = declarative_base()


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ScanTask(Base):
    __tablename__ = "scan_tasks"

    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    target_url = Column(String(500), nullable=False)
    auth_config = Column(Text, default="{}")   # JSON: 多角色账号
    scope_config = Column(Text, default="{}")  # JSON: 范围/排除/限速
    status = Column(String(30), default="pending")  # pending running paused completed stopped failed
    stage = Column(String(30), default="")
    progress = Column(Integer, default=0)      # 0-100
    message = Column(Text, default="")
    request_count = Column(Integer, default=0)
    state = Column(Text, default="{}")           # JSON: 已完成阶段/断点
    created_at = Column(String(30), default=now_iso)
    started_at = Column(String(30))
    finished_at = Column(String(30))

    assets = relationship("Asset", back_populates="task", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="task", cascade="all, delete-orphan")


class Suppression(Base):
    """人工标记的误报,跨任务生效:下次扫描同 key 直接跳过。"""
    __tablename__ = "suppressions"

    id = Column(Integer, primary_key=True)
    host = Column(String(200), nullable=False, index=True)
    dedup_key = Column(String(400), nullable=False, index=True)
    category = Column(String(40))
    reason = Column(Text, default="")
    finding_id = Column(Integer)
    created_at = Column(String(30), default=now_iso)


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True)
    task_id = Column(Integer, ForeignKey("scan_tasks.id"), nullable=False)
    url = Column(String(800), nullable=False)
    method = Column(String(10), default="GET")
    kind = Column(String(20), default="page")   # page / api / form / websocket
    source = Column(String(20), default="crawl")  # crawl / replay / manual
    params = Column(Text, default="[]")         # JSON [{name, in, sample}]
    role = Column(String(30), default="")       # 发现该资产的登录角色
    status_code = Column(Integer)
    content_type = Column(String(120))
    fingerprint = Column(String(200))
    discovered_at = Column(String(30), default=now_iso)

    task = relationship("ScanTask", back_populates="assets")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)
    task_id = Column(Integer, ForeignKey("scan_tasks.id"), nullable=False)
    vuln_id = Column(String(20), index=True)     # 埋点清单 ID
    vuln_ids = Column(Text, default="[]")        # JSON:一个发现覆盖的多个埋点 ID
    category = Column(String(40), nullable=False)
    title = Column(String(300), nullable=False)
    severity = Column(String(10), default="medium")
    url = Column(String(800))
    method = Column(String(10))
    param = Column(String(120))
    role = Column(String(30))
    status = Column(String(20), default="suspected")  # suspected confirmed false_positive
    confidence = Column(String(10), default="medium")
    dedup_key = Column(String(300), index=True)
    evidence = Column(Text)        # JSON: 判定依据
    request = Column(Text)         # 原始请求
    response = Column(Text)        # 原始响应(截断)
    verify_request = Column(Text)
    verify_response = Column(Text)
    verification = Column(Text)    # JSON: 复现结论
    occurrences = Column(Text, default="[]")  # 同漏洞多参数合并记录
    note = Column(Text, default="")
    created_at = Column(String(30), default=now_iso)
    updated_at = Column(String(30), default=now_iso)

    task = relationship("ScanTask", back_populates="findings")


class CrawlEntry(Base):
    """已从靶场抓取到的接口/页面记录,供后续按角色重放。"""
    __tablename__ = "crawl_entries"

    id = Column(Integer, primary_key=True)
    task_id = Column(Integer, ForeignKey("scan_tasks.id"), nullable=False, index=True)
    method = Column(String(10))
    url = Column(String(1000))
    template = Column(String(1000))  # 归一化模板,用于去重
    headers = Column(Text)
    body = Column(Text)
    role = Column(String(30))
    kind = Column(String(20), default="request")
    created_at = Column(String(30), default=now_iso)


engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})


@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_connection, _record):
    cur = dbapi_connection.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA foreign_keys=ON")
    cur.close()


SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def init_db():
    Base.metadata.create_all(engine)


def new_session():
    return SessionLocal()


def json_load(raw, default=None):
    if not raw:
        return default if default is not None else {}
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return default if default is not None else {}
