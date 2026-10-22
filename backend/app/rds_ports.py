"""Default listener ports for RDS engines.

Defaults per the AWS RDS documentation (Creating a DB instance / "Port" in
CreateDBInstance): MySQL, MariaDB and Aurora MySQL 3306; PostgreSQL and Aurora
PostgreSQL 5432; Oracle 1521; SQL Server 1433; Db2 50000.
"""
from typing import Any, Mapping, Optional

_EXACT = {"mysql": 3306, "mariadb": 3306, "aurora": 3306, "aurora-mysql": 3306,
          "postgres": 5432, "aurora-postgresql": 5432}
_PREFIX = (("oracle", 1521), ("sqlserver", 1433), ("db2", 50000))


def _get(item: Any, name: str) -> Any:
    return item.get(name) if isinstance(item, Mapping) else getattr(item, name, None)


def rds_port(instance: Any) -> Optional[int]:
    """The port the database listens on, or None when unknown."""
    port = _get(instance, "port")
    if port is not None:
        return int(port)
    engine = _get(instance, "engine")
    if not engine:
        return None
    engine = str(engine).lower()
    if engine in _EXACT:
        return _EXACT[engine]
    for prefix, value in _PREFIX:
        if engine.startswith(prefix):
            return value
    return None


def ports_cover(ports: Any, port: Optional[int]) -> bool:
    """True when an evidence/rule port range includes the port (unknown port: True)."""
    if port is None or ports == ["all"]:
        return True
    return int(ports[0]) <= port <= int(ports[1])
