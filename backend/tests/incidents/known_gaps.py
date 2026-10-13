KNOWN_GAPS = {
}

KNOWN_GAPS_PHASE_D = {
    **{f"D{i:02d}": "Phase D: synthetic base loader + delete lens not built" for i in range(1, 15)},
    "D03": "Phase I: terraform plan ingest",
}
