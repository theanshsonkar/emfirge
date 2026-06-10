"""
Emfirge AWS Risk Agent — core application package.

Modules:
    aws_collector   – Parallel AWS API data collection (16 services)
    graph     – Infrastructure graph builder + BFS attack paths
    compliance      – CIS 1.5 & SOC 2 framework evaluation
    database        – Supabase/Postgres persistence layer
    demo_seed       – Synthetic infrastructure for demo mode
    drift_service   – Scan-to-scan diff for regression detection
    fix_mutations   – Deterministic infra mutations for verify-fix
    github_service  – GitHub App integration (PR creation)
    llm             – Gemini/Claude orchestration for AI summaries
    main            – FastAPI routes and middleware
    models          – Pydantic data models
    rules           – 60+ security/cost/availability rule checks
    scoring         – Weighted, blast-radius-aware risk scoring
    storage         – S3 report persistence
"""
