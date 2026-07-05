from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, date
from typing import Optional
from dotenv import load_dotenv
import os
import json

load_dotenv()

DATABASE_URL = os.getenv('DATABASE_URL')
engine = create_engine(DATABASE_URL)
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine)

class AnalysisLog(Base):
    __tablename__ = 'analysis_logs'

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    region_analyzed = Column(String(50))
    ec2_count = Column(Integer, default=0)

    # Overall scores
    risk_score = Column(Integer)
    risk_level = Column(String(20))

    # Category scores
    security_score = Column(Integer, default=0)
    availability_score = Column(Integer, default=0)
    cost_score = Column(Integer, default=0)

    # Counts
    critical_count = Column(Integer, default=0)
    moderate_count = Column(Integer, default=0)

    # Full data
    findings_json = Column(Text)
    llm_response = Column(Text)

    # Metadata
    latency_ms = Column(Integer)
    tokens_used = Column(Integer, default=0)
    prompt_version = Column(String(20), default='v1.0')
    aws_account_id = Column(String(20), default='')    # NEW — for rate limiting

class DriftEvent(Base):
    __tablename__ = 'drift_events'
    id               = Column(Integer, primary_key=True, autoincrement=True)
    aws_account_id   = Column(String(20), index=True)
    detected_at      = Column(DateTime, default=datetime.utcnow)
    change_type      = Column(String(30))   # 'new_finding' | 'finding_fixed'
    rule_id          = Column(String(50))
    resource_id      = Column(String(200))
    issue            = Column(Text)
    severity         = Column(String(20))
    mitre_technique_id = Column(String(20))
    current_scan_id  = Column(Integer)
    previous_scan_id = Column(Integer)
    auto_pr_url      = Column(Text)

class SimulationLog(Base):
    __tablename__ = 'simulation_logs'
    id               = Column(Integer, primary_key=True, autoincrement=True)
    aws_account_id   = Column(String(20), index=True)
    analysis_id      = Column(String(100))
    query            = Column(Text)
    timestamp        = Column(DateTime, default=datetime.utcnow)

class Feedback(Base):
    __tablename__ = 'feedback'
    id               = Column(Integer, primary_key=True, autoincrement=True)
    message          = Column(Text)
    name             = Column(String(100))
    email            = Column(String(200))
    aws_account_id   = Column(String(20))
    page             = Column(String(50))
    timestamp        = Column(DateTime, default=datetime.utcnow)

class LLMUsage(Base):
    __tablename__ = 'llm_usage'
    id               = Column(Integer, primary_key=True, autoincrement=True)
    aws_account_id   = Column(String(20), index=True)
    endpoint_type    = Column(String(30))   # "insight" | "terraform"
    timestamp        = Column(DateTime, default=datetime.utcnow)


class TFResource(Base):
    """Index of Terraform resources found in a user's GitHub repo."""
    __tablename__ = 'tf_resources'
    id               = Column(Integer, primary_key=True, autoincrement=True)
    installation_id  = Column(Integer, index=True)
    repo_full_name   = Column(String(200), index=True)
    resource_type    = Column(String(100))   # e.g. "aws_security_group"
    resource_name    = Column(String(200))   # e.g. "ssh_open"
    file_path        = Column(String(500))   # e.g. "infra/security-groups.tf"
    line_number      = Column(Integer)
    identifiers_json = Column(Text)          # JSON dict of identifier attrs
    block_content    = Column(Text)          # raw HCL of the resource block
    indexed_at       = Column(DateTime, default=datetime.utcnow)


class CIAPIKey(Base):
    """API keys for CI/CD gate endpoint authentication."""
    __tablename__ = 'ci_api_keys'
    id               = Column(Integer, primary_key=True, autoincrement=True)
    installation_id  = Column(Integer, index=True)
    api_key          = Column(String(64), unique=True, index=True)
    repo_full_name   = Column(String(200))
    created_at       = Column(DateTime, default=datetime.utcnow)
    last_used_at     = Column(DateTime, nullable=True)
    is_active        = Column(Integer, default=1)  # 1=active, 0=revoked

def create_tables():
    Base.metadata.create_all(engine)
    print('Database tables created successfully')

def save_analysis(data: dict) -> int:
    session = SessionLocal()
    try:
        log = AnalysisLog(
            region_analyzed=data.get('region_analyzed'),
            ec2_count=data.get('ec2_count', 0),
            risk_score=data.get('risk_score'),
            risk_level=data.get('risk_level'),
            security_score=data.get('security_score', 0),
            availability_score=data.get('availability_score', 0),
            cost_score=data.get('cost_score', 0),
            critical_count=data.get('critical_count', 0),
            moderate_count=data.get('moderate_count', 0),
            findings_json=json.dumps(data.get('findings_json', {})),
            llm_response=data.get('llm_response', ''),
            latency_ms=data.get('latency_ms', 0),
            tokens_used=data.get('tokens_used', 0),
            prompt_version=data.get('prompt_version', 'v1.0'),
            aws_account_id=data.get('aws_account_id', ''),    # NEW
        )
        session.add(log)
        session.commit()
        session.refresh(log)
        return log.id
    except Exception as e:
        session.rollback()
        print(f'Error saving analysis: {e}')
        return -1
    finally:
        session.close()

def get_recent_logs(limit: int = 20, account_id: str = None) -> list:
    session = SessionLocal()
    try:
        q = session.query(AnalysisLog)
        if account_id:
            q = q.filter(AnalysisLog.aws_account_id == account_id)
        logs = q.order_by(
            AnalysisLog.timestamp.desc()
        ).limit(limit).all()

        return [
            {
                'id': log.id,
                'timestamp': str(log.timestamp),
                'region_analyzed': log.region_analyzed,
                'risk_score': log.risk_score,
                'risk_level': log.risk_level,
                'security_score': log.security_score,
                'availability_score': log.availability_score,
                'cost_score': log.cost_score,
                'critical_count': log.critical_count,
                'moderate_count': log.moderate_count,
                'latency_ms': log.latency_ms
            }
            for log in logs
        ]
    except Exception as e:
        print(f'Error fetching logs: {e}')
        return []
    finally:
        session.close()

def get_log_by_id(log_id: int, account_id: str = None) -> dict:
    session = SessionLocal()
    try:
        q = session.query(AnalysisLog).filter(
            AnalysisLog.id == log_id
        )
        if account_id:
            q = q.filter(AnalysisLog.aws_account_id == account_id)
        log = q.first()
        if not log:
            return {}
        return {
            'id': log.id,
            'timestamp': str(log.timestamp),
            'region_analyzed': log.region_analyzed,
            'risk_score': log.risk_score,
            'risk_level': log.risk_level,
            'security_score': log.security_score,
            'availability_score': log.availability_score,
            'cost_score': log.cost_score,
            'critical_count': log.critical_count,
            'moderate_count': log.moderate_count,
            'findings_json': log.findings_json,
            'llm_response': log.llm_response,
            'latency_ms': log.latency_ms,
            'tokens_used': log.tokens_used,
            'prompt_version': log.prompt_version
        }
    except Exception as e:
        print(f'Error fetching log: {e}')
        return {}
    finally:
        session.close()

def get_scan_count_today(account_id: str) -> int:
    # Returns how many successful scans this AWS account has done today
    # Used for rate limiting — max 5 scans per account per day
    # If the DB check itself fails, we return 0 and allow the scan
    # Better to let a scan through than to block a legitimate user due to a DB error
    session = SessionLocal()
    try:
        today = date.today()
        count = session.query(AnalysisLog).filter(
            AnalysisLog.aws_account_id == account_id,
            AnalysisLog.timestamp >= datetime.combine(today, datetime.min.time())
        ).count()
        return count
    except Exception as e:
        print(f'Error checking scan count: {e}')
        return 0
    finally:
        session.close()

def get_previous_scan_for_account(account_id: str, exclude_id: int) -> dict:
    session = SessionLocal()
    try:
        log = session.query(AnalysisLog).filter(
            AnalysisLog.aws_account_id == account_id,
            AnalysisLog.id != exclude_id
        ).order_by(AnalysisLog.timestamp.desc()).first()
        if not log:
            return {}
        return {'id': log.id, 'findings_json': log.findings_json, 'risk_score': log.risk_score}
    except Exception as e:
        print(f"get_previous_scan error: {e}")
        return {}
    finally:
        session.close()

def save_drift_events(events: list) -> None:
    session = SessionLocal()
    try:
        for e in events:
            session.add(DriftEvent(**e))
        session.commit()
    except Exception as ex:
        session.rollback()
        print(f"save_drift_events error: {ex}")
    finally:
        session.close()

def get_drift_events(account_id: str = None, limit: int = 20) -> list:
    session = SessionLocal()
    try:
        q = session.query(DriftEvent)
        if account_id:
            q = q.filter(DriftEvent.aws_account_id == account_id)
        rows = q.order_by(DriftEvent.detected_at.desc()).limit(limit).all()
        return [{
            'id': r.id, 'aws_account_id': r.aws_account_id,
            'detected_at': str(r.detected_at), 'change_type': r.change_type,
            'rule_id': r.rule_id, 'resource_id': r.resource_id,
            'issue': r.issue, 'severity': r.severity,
            'mitre_technique_id': r.mitre_technique_id,
            'current_scan_id': r.current_scan_id,
            'previous_scan_id': r.previous_scan_id,
            'auto_pr_url': r.auto_pr_url
        } for r in rows]
    except Exception:
        return []
    finally:
        session.close()


def save_simulation_log(aws_account_id: str, analysis_id: str, query: str) -> None:
    session = SessionLocal()
    try:
        session.add(SimulationLog(
            aws_account_id=aws_account_id,
            analysis_id=analysis_id,
            query=query
        ))
        session.commit()
    except Exception as e:
        session.rollback()
        print(f'Error saving simulation log: {e}')
    finally:
        session.close()

def get_simulation_count_today(aws_account_id: str) -> int:
    session = SessionLocal()
    try:
        today = date.today()
        count = session.query(SimulationLog).filter(
            SimulationLog.aws_account_id == aws_account_id,
            SimulationLog.timestamp >= datetime.combine(today, datetime.min.time())
        ).count()
        return count
    except Exception as e:
        print(f'Error checking simulation count: {e}')
        return 0
    finally:
        session.close()


def save_feedback(message: str, name: str = '', email: str = '', aws_account_id: str = '', page: str = '') -> int:
    session = SessionLocal()
    try:
        fb = Feedback(message=message, name=name, email=email, aws_account_id=aws_account_id, page=page)
        session.add(fb)
        session.commit()
        session.refresh(fb)
        return fb.id
    except Exception as e:
        session.rollback()
        print(f'Error saving feedback: {e}')
        return -1
    finally:
        session.close()

def get_feedback(limit: int = 50) -> list:
    session = SessionLocal()
    try:
        rows = session.query(Feedback).order_by(Feedback.timestamp.desc()).limit(limit).all()
        return [{
            'id': r.id, 'message': r.message, 'name': r.name, 'email': r.email,
            'aws_account_id': r.aws_account_id, 'page': r.page, 'timestamp': str(r.timestamp)
        } for r in rows]
    except Exception:
        return []
    finally:
        session.close()


def save_llm_usage(aws_account_id: str, endpoint_type: str) -> None:
    """Insert a row into llm_usage to track daily LLM API usage per account."""
    session = SessionLocal()
    try:
        session.add(LLMUsage(
            aws_account_id=aws_account_id,
            endpoint_type=endpoint_type
        ))
        session.commit()
    except Exception as e:
        session.rollback()
        print(f'Error saving LLM usage: {e}')
    finally:
        session.close()

def get_llm_usage_count_today(aws_account_id: str, endpoint_type: str) -> int:
    """Count how many LLM requests this account has made today for the given endpoint type."""
    session = SessionLocal()
    try:
        today = date.today()
        count = session.query(LLMUsage).filter(
            LLMUsage.aws_account_id == aws_account_id,
            LLMUsage.endpoint_type == endpoint_type,
            LLMUsage.timestamp >= datetime.combine(today, datetime.min.time())
        ).count()
        return count
    except Exception as e:
        print(f'Error checking LLM usage count: {e}')
        return 0
    finally:
        session.close()


# ── TF INDEX FUNCTIONS ────────────────────────────────────────────

def save_tf_index(installation_id: int, repo_full_name: str, resources: list[dict]) -> int:
    """
    Save a TF resource index for a repo. Replaces any existing index for this repo.
    Returns the number of resources indexed.
    """
    session = SessionLocal()
    try:
        # Delete existing index for this repo
        session.query(TFResource).filter(
            TFResource.installation_id == installation_id,
            TFResource.repo_full_name == repo_full_name
        ).delete()

        # Insert new index
        for r in resources:
            session.add(TFResource(
                installation_id=installation_id,
                repo_full_name=repo_full_name,
                resource_type=r['resource_type'],
                resource_name=r['resource_name'],
                file_path=r['file_path'],
                line_number=r['line_number'],
                identifiers_json=json.dumps(r.get('identifiers', {})),
                block_content=r.get('block_content', ''),
            ))
        session.commit()
        return len(resources)
    except Exception as e:
        session.rollback()
        print(f'Error saving TF index: {e}')
        return 0
    finally:
        session.close()


def get_tf_index(installation_id: int, repo_full_name: str) -> list[dict]:
    """Get the TF resource index for a repo."""
    session = SessionLocal()
    try:
        rows = session.query(TFResource).filter(
            TFResource.installation_id == installation_id,
            TFResource.repo_full_name == repo_full_name
        ).all()
        return [{
            'id': r.id,
            'resource_type': r.resource_type,
            'resource_name': r.resource_name,
            'file_path': r.file_path,
            'line_number': r.line_number,
            'identifiers': json.loads(r.identifiers_json) if r.identifiers_json else {},
            'block_content': r.block_content,
            'indexed_at': str(r.indexed_at),
        } for r in rows]
    except Exception as e:
        print(f'Error getting TF index: {e}')
        return []
    finally:
        session.close()


def get_tf_index_status(installation_id: int, repo_full_name: str) -> dict:
    """Get indexing status for a repo (count + last indexed time)."""
    session = SessionLocal()
    try:
        rows = session.query(TFResource).filter(
            TFResource.installation_id == installation_id,
            TFResource.repo_full_name == repo_full_name
        ).all()
        if not rows:
            return {"indexed": False, "count": 0, "last_indexed": None}
        last = max(r.indexed_at for r in rows)
        return {"indexed": True, "count": len(rows), "last_indexed": str(last)}
    except Exception:
        return {"indexed": False, "count": 0, "last_indexed": None}
    finally:
        session.close()


# ── CI API KEY FUNCTIONS ──────────────────────────────────────────

def create_ci_api_key(installation_id: int, repo_full_name: str) -> str:
    """Create a new CI/CD API key for an installation. Returns the key string."""
    import secrets
    session = SessionLocal()
    try:
        api_key = secrets.token_hex(32)  # 64-char hex string
        session.add(CIAPIKey(
            installation_id=installation_id,
            api_key=api_key,
            repo_full_name=repo_full_name,
        ))
        session.commit()
        return api_key
    except Exception as e:
        session.rollback()
        print(f'Error creating CI API key: {e}')
        return ''
    finally:
        session.close()


def validate_ci_api_key(api_key: str) -> Optional[dict]:
    """
    Validate a CI API key. Returns installation info if valid, None if invalid.
    Also updates last_used_at.
    """
    session = SessionLocal()
    try:
        row = session.query(CIAPIKey).filter(
            CIAPIKey.api_key == api_key,
            CIAPIKey.is_active == 1
        ).first()
        if not row:
            return None
        # Update last_used_at
        row.last_used_at = datetime.utcnow()
        session.commit()
        return {
            'installation_id': row.installation_id,
            'repo_full_name': row.repo_full_name,
        }
    except Exception as e:
        print(f'Error validating CI API key: {e}')
        return None
    finally:
        session.close()


def revoke_ci_api_key(api_key: str) -> bool:
    """Revoke a CI API key."""
    session = SessionLocal()
    try:
        row = session.query(CIAPIKey).filter(CIAPIKey.api_key == api_key).first()
        if not row:
            return False
        row.is_active = 0
        session.commit()
        return True
    except Exception as e:
        session.rollback()
        print(f'Error revoking CI API key: {e}')
        return False
    finally:
        session.close()


def get_ci_api_keys(installation_id: int) -> list[dict]:
    """List all CI API keys for an installation."""
    session = SessionLocal()
    try:
        rows = session.query(CIAPIKey).filter(
            CIAPIKey.installation_id == installation_id
        ).all()
        return [{
            'id': r.id,
            'api_key_prefix': r.api_key[:8] + '...',  # Only show prefix
            'repo_full_name': r.repo_full_name,
            'created_at': str(r.created_at),
            'last_used_at': str(r.last_used_at) if r.last_used_at else None,
            'is_active': bool(r.is_active),
        } for r in rows]
    except Exception:
        return []
    finally:
        session.close()
