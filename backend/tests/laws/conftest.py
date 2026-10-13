import os

from hypothesis import settings

from tests.incidents.test_incidents import incident_branch_db

settings.register_profile("default", max_examples=200, deadline=None)
settings.register_profile("ci", max_examples=200, deadline=None)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))
