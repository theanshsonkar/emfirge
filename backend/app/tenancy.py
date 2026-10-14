from app.auth import Caller
from app.database import AccountBinding


def allowed_accounts(caller: Caller, db) -> set[str] | None:
    """Return the accounts visible to a caller; None means self-host is unrestricted."""
    if caller.mode != 'hosted':
        return None
    return {
        row.aws_account_id
        for row in db.query(AccountBinding.aws_account_id)
        .filter(AccountBinding.project_id == caller.project_id)
        .all()
    }


def account_visible(caller: Caller, db, account_id: str) -> bool:
    allowed = allowed_accounts(caller, db)
    return allowed is None or account_id in allowed
