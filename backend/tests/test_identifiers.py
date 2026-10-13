from app.identifiers import customer_identifiers, tokenize, tokenize_obj
from tests.incidents.base import ACCOUNT, ROLE_ARN, build_incident_base


def test_customer_identifiers_only_collects_identifier_fields():
    identifiers = customer_identifiers(build_incident_base(), ACCOUNT)

    for expected in ("i-inc-web", "sg-inc-web", "inc-data-bucket", ROLE_ARN):
        assert expected in identifiers
    for ordinary in ("tcp", "running", "t3.micro", "Allow", "s3:GetObject", "ap-south-1", "0.0.0.0/0"):
        assert ordinary not in identifiers


def test_tokenize_is_deterministic_and_preserves_ordinary_words():
    identifiers = ["arn:aws:iam::000000000000:role/EmfirgeDemoAppRole", "i-inc-web"]
    text = "i-inc-web can reach the role arn:aws:iam::000000000000:role/EmfirgeDemoAppRole"

    assert tokenize(text, identifiers) == tokenize(text, identifiers)
    assert tokenize(text, identifiers).count("res-1") == 1
    assert tokenize(text, identifiers).count("res-2") == 1
    ordinary = "open tcp port 22 on a running t3.micro"
    assert tokenize(ordinary, identifiers) == ordinary
    assert tokenize_obj({"query": text}, identifiers)["query"] == tokenize(text, identifiers)
