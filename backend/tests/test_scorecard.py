import json
import xml.etree.ElementTree as ET

from scripts import scorecard


def write_xml(tmp_path, cases):
    xml = ET.Element("testsuite")
    for attrs, child in cases:
        testcase = ET.SubElement(xml, "testcase", attrs)
        if child:
            ET.SubElement(testcase, child[0], child[1])
    path = tmp_path / "results.xml"
    ET.ElementTree(xml).write(path)
    return path


def run(tmp_path, cases):
    junit = write_xml(tmp_path, cases)
    output = tmp_path / "scorecard.json"
    markdown = tmp_path / "scorecard.md"
    result = scorecard.main([str(junit), "--json", str(output), "--md", str(markdown)])
    return result, json.loads(output.read_text())


def test_scorecard_statuses_grouping_and_precedence(tmp_path):
    cases = [
        ({"classname": "tests.incidents.test_incidents", "name": "test_incident_scenario[R01]"}, None),
        ({"classname": "tests.incidents.test_incidents", "name": "test_incident_scenario[R01]"}, ("skipped", {"type": "pytest.xfail", "message": "gap"})),
        ({"classname": "tests.incidents.test_incidents", "name": "test_incident_scenario[R02]"}, ("failure", {})),
        ({"classname": "tests.incidents.test_incidents", "name": "test_incident_scenario[R03]"}, ("skipped", {"message": "xfail: gap"})),
        ({"classname": "tests.incidents.test_incidents", "name": "test_incident_scenario[R04]"}, ("skipped", {"message": "not available"})),
        ({"classname": "tests.imported.test_pathfinding_paths", "name": "test_pathfinding_path_is_blocked[P01]"}, None),
        ({"classname": "tests.imported.test_pathfinding_paths", "name": "test_pathfinding_path_is_blocked[P02]"}, ("error", {})),
        ({"classname": "tests.imported.test_pathfinding_paths", "name": "test_pathfinding_path_requires_every_action[P01-without-x]"}, ("skipped", {"type": "pytest.xfail", "message": "gap"})),
        ({"classname": "tests.laws.test_laws", "name": "test_L1_rule[a]"}, None),
        ({"classname": "tests.laws.test_laws", "name": "test_l1_rule[b]"}, ("skipped", {"type": "pytest.xfail", "message": "gap"})),
        ({"classname": "tests.laws.test_laws", "name": "test_L1_rule[c]"}, ("failure", {})),
        ({"classname": "tests.laws.test_delete_laws", "name": "test_data_lost_requires_block"}, None),
    ]
    result, output = run(tmp_path, cases)
    assert result == 0
    assert output["categories"]["incidents"] == {
        "total": 4, "pass": 0, "known_gap": 2, "fail": 1, "skipped": 1,
        "items": [{"id": "R01", "status": "known_gap"}, {"id": "R02", "status": "fail"}, {"id": "R03", "status": "known_gap"}, {"id": "R04", "status": "skipped"}],
    }
    paths = output["categories"]["escalation_paths"]
    assert {key: paths["must_block"][key] for key in ("total", "pass", "fail", "known_gap", "skipped")} == {"total": 2, "pass": 1, "fail": 1, "known_gap": 0, "skipped": 0}
    assert {key: paths["negatives"][key] for key in ("total", "pass", "fail", "known_gap", "skipped")} == {"total": 1, "pass": 0, "fail": 0, "known_gap": 1, "skipped": 0}
    assert output["categories"]["laws"]["items"] == [{"id": "L1", "status": "fail"}]
    assert output["categories"]["laws"]["unlabelled"] == [{"id": "test_data_lost_requires_block", "status": "pass"}]
    assert output["categories"]["scanners"]["status"] == "not_run"
    assert "known gaps" in output["headline"]


def test_empty_category_is_nonzero(tmp_path):
    cases = [({"classname": "tests.incidents.test_incidents", "name": "test_incident_scenario[R01]"}, None)]
    result, _ = run(tmp_path, cases)
    assert result != 0
