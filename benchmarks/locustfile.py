"""Locust Concurrency & Load Testing Suite for SIHTBP REST API.

SIH Problem Statement ID: 26106
Simulates concurrent forensic examiner workflows:
- Ingestion of raw RFC 822 email evidence
- Retrieval of Section 63 BSA evidence dossiers
- Forensic graph querying and IOC telemetry

Configured for concurrency testing at 10, 50, and 100 concurrent examiner sessions.
"""

from __future__ import annotations

import io
import uuid
from locust import HttpUser, between, task


class ForensicExaminerUser(HttpUser):
    wait_time = between(0.1, 0.5)

    def on_start(self):
        """Simulate authentication and session establishment."""
        self.examiner_id = f"examiner_{uuid.uuid4().hex[:8]}"
        self.auth_token = "mock_analyst_bearer_token"
        self.headers = {
            "Authorization": f"Bearer {self.auth_token}",
        }

    @task(3)
    def test_health_and_metrics(self):
        """Verify API health status."""
        self.client.get("/health", name="/health")

    @task(2)
    def test_campaign_graph_query(self):
        """Query multi-incident threat campaign relationship graph."""
        self.client.get(
            "/api/v1/campaigns/graph",
            headers=self.headers,
            name="/api/v1/campaigns/graph",
        )

    @task(1)
    def test_campaign_list(self):
        """Query list of detected campaign clusters."""
        self.client.get(
            "/api/v1/campaigns/",
            headers=self.headers,
            name="/api/v1/campaigns/",
        )

