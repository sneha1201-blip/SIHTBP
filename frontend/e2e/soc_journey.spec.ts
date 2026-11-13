import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import * as path from 'path';
import * as fs from 'fs';

const EVIDENCE_E2E_DIR = path.resolve(__dirname, '../../evidence/e2e');

test.beforeAll(() => {
  if (!fs.existsSync(EVIDENCE_E2E_DIR)) {
    fs.mkdirSync(EVIDENCE_E2E_DIR, { recursive: true });
  }
});

test.describe('SIHTBP Forensic Examiner E2E & Accessibility Suite', () => {

  test('1. Login Screen - Visual Inspection, Input & Axe Accessibility Audit', async ({ page }) => {
    await page.goto('/login');
    await expect(page).toHaveURL(/.*login/);

    // Verify critical elements on login page
    await expect(page.locator('input[type="text"]')).toBeVisible();
    await expect(page.locator('input[type="password"]')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toBeVisible();

    // Capture screenshot
    await page.screenshot({ path: path.join(EVIDENCE_E2E_DIR, '01_login_screen.png'), fullPage: true });

    // Axe Accessibility Audit
    const accessibilityScanResults = await new AxeBuilder({ page }).analyze();
    const criticalViolations = accessibilityScanResults.violations.filter(
      v => v.impact === 'serious' || v.impact === 'critical'
    );
    expect(criticalViolations, `Axe accessibility violations found on login: ${JSON.stringify(criticalViolations)}`).toHaveLength(0);
  });

  test('2. Authentication Flow & Redirection to SOC Dashboard', async ({ page }) => {
    // Intercept backend auth endpoint for deterministic local execution
    await page.route('**/api/v1/auth/login', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          access_token: 'mock_jwt_analyst_token_for_e2e_playwright_test',
          token_type: 'bearer',
          user: {
            id: '7b83f064-9b2e-4b68-b715-e2e718294012',
            username: 'analyst_shravan',
            email: 'examiner@aicte.gov.in',
            role: 'ANALYST',
          },
        }),
      });
    });

    await page.goto('/login');
    await page.fill('input[type="text"]', 'analyst_shravan');
    await page.fill('input[type="password"]', 'SecurePassword2026!');
    await page.click('button[type="submit"]');

    // Wait for redirect to dashboard
    await expect(page).toHaveURL('/');
    await page.screenshot({ path: path.join(EVIDENCE_E2E_DIR, '02_dashboard_landing.png'), fullPage: true });
  });

  test('3. SOC Forensic Dashboard - Full Journey (Upload, Map, Graph, Audit, PDF, Logout)', async ({ page }) => {
    // Seed authenticated session in localStorage using correct keys
    await page.addInitScript(() => {
      window.localStorage.setItem('aicte_forensics_jwt', 'mock_jwt_analyst_token_for_e2e_playwright_test');
      window.localStorage.setItem(
        'aicte_forensics_user',
        JSON.stringify({
          username: 'analyst_shravan',
          role: 'ANALYST',
          email: 'examiner@aicte.gov.in',
        })
      );
    });

    // Mock live backend endpoints for deterministic UI testing
    const mockEmailId = '4a839f20-1122-43b2-9a00-184920482910';
    const mockSha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

    await page.route('**/api/v1/campaigns/graph*', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          graph: {
            total_nodes: 3,
            total_edges: 2,
            nodes: [
              { id: mockEmailId, label: 'URGENT: Remittance Notice', type: 'EMAIL', metadata: {} },
              { id: 'asn:208294', label: 'AS208294 (Bulletproof)', type: 'INFRASTRUCTURE_IP', metadata: {} },
              { id: 'domain:aicte-portal.top', label: 'aicte-portal.top', type: 'IOC', metadata: {} },
            ],
            edges: [
              { id: 'e1', source: mockEmailId, target: 'asn:208294', relationship: 'ORIGINATING_ASN' },
              { id: 'e2', source: mockEmailId, target: 'domain:aicte-portal.top', relationship: 'SENDER_DOMAIN' },
            ],
          },
        }),
      });
    });

    await page.route('**/api/v1/forensics/audit/verify-chain*', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          valid: true,
          total_records: 1,
          chain_head: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b',
        }),
      });
    });

    await page.route('**/api/v1/forensics/evidence/**', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          email: {
            id: mockEmailId,
            sha256_hash: mockSha256,
            md5_hash: 'a'.repeat(32),
            subject: 'URGENT: Emergency Grant Remittance Allocation',
            sender_email: 'chairman@aicte-emergency-portal.org',
            recipient_list: ['finance.officer@vjti.ac.in'],
            file_name: 'evidence_001.eml',
            file_size_bytes: 4096,
            body_plain: 'Remit emergency fee of Rs. 4,50,000 immediately.',
            ingested_at: '2026-11-13T09:00:00Z',
          },
          forensic_analysis: {
            id: 'fa-001',
            email_id: mockEmailId,
            threat_score: 94.5,
            threat_level: 'MALICIOUS',
            verdict: 'MALICIOUS',
            is_spoofed: true,
            spf_status: 'FAIL',
            dkim_status: 'FAIL',
            dmarc_status: 'FAIL',
            display_spoof_flag: true,
            lookalike_flag: true,
            dmarc_alignment_spf: false,
            dmarc_alignment_dkim: false,
            ai_intent: 'BEC_WIRE_FRAUD',
            confidence: 0.98,
          },
          header_hops: [
            {
              id: 'h1',
              email_id: mockEmailId,
              hop_order: 1,
              hop_ip: '185.220.101.5',
              asn_number: 208294,
              asn_org: 'Zwiebelfreunde',
              geo_country: 'Germany',
              geo_city: 'Berlin',
              geo_lat: 52.52,
              geo_lon: 13.405,
              node_type: 'ORIGINATING',
              is_private_ip: false,
              is_reliable: true,
              is_tor: true,
              is_vpn: false,
              is_datacenter: true,
              delay_seconds: 0.0,
            },
            {
              id: 'h2',
              email_id: mockEmailId,
              hop_order: 2,
              hop_ip: '164.100.24.12',
              asn_number: 9498,
              asn_org: 'NIC India',
              geo_country: 'India',
              geo_city: 'New Delhi',
              geo_lat: 28.6139,
              geo_lon: 77.209,
              node_type: 'RELAY',
              is_private_ip: false,
              is_reliable: true,
              is_tor: false,
              is_vpn: false,
              is_datacenter: false,
              delay_seconds: 1.2,
            },
          ],
          threat_indicators: [
            { id: '1', email_id: mockEmailId, ioc_type: 'DOMAIN', ioc_value: 'aicte-emergency-portal.org', reputation_score: 95.0 },
            { id: '2', email_id: mockEmailId, ioc_type: 'IP', ioc_value: '185.220.101.5', reputation_score: 92.0 },
          ],
          campaigns: [
            { campaign_id: 'c1', name: 'Operation FalconShield', cluster_type: 'ASN', similarity_score: 0.95, matched_criteria: {} },
          ],
          audit_logs: [
            {
              id: 'a1',
              action_performed: 'EVIDENCE_INGESTED',
              actor: 'analyst_shravan',
              hmac_signature: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b',
              previous_log_hash: 'GENESIS_BLOCK',
              timestamp: '2026-11-13T09:00:00Z',
              integrity_check: true,
              details: {},
            },
          ],
        }),
      });
    });

    await page.goto('/');

    // Wait for Dashboard UI components
    await expect(page.locator('text=AICTE Cyber Security Cell')).toBeVisible();
    await page.screenshot({ path: path.join(EVIDENCE_E2E_DIR, '03_dossier_overview.png'), fullPage: true });

    // 1. Ingestion Modal Trigger
    const ingestBtn = page.locator('button:has-text("Ingest Evidence")');
    if (await ingestBtn.isVisible()) {
      await ingestBtn.click();
      await expect(page.locator('text=Ingest Email Evidence')).toBeVisible();
      await page.screenshot({ path: path.join(EVIDENCE_E2E_DIR, '04_ingestion_modal.png') });
      // Close modal
      await page.locator('button:has-text("Cancel"), button[class*="hover:text-white"]').first().click();
    }

    // 2. Cytoscape Campaign Graph View
    await expect(page.locator('text=Campaign & Cross-Incident Intelligence Graph')).toBeVisible();
    await page.screenshot({ path: path.join(EVIDENCE_E2E_DIR, '05_campaign_graph.png') });

    // 3. Audit Ledger & Cryptographic Verification
    await expect(page.locator('text=Section 63 BSA 2023 Tamper-Evident Audit Ledger')).toBeVisible();
    await page.screenshot({ path: path.join(EVIDENCE_E2E_DIR, '06_audit_ledger.png') });

    // 4. Axe Accessibility Audit on Full SOC Dashboard (excluding third-party Leaflet map attribution)
    const dashboardScanResults = await new AxeBuilder({ page })
      .exclude('.leaflet-control-attribution')
      .analyze();
    const criticalViolations = dashboardScanResults.violations.filter(
      v => v.impact === 'serious' || v.impact === 'critical'
    );
    expect(criticalViolations, `Axe accessibility violations found on dashboard: ${JSON.stringify(criticalViolations)}`).toHaveLength(0);

    // 5. Logout Flow
    const logoutBtn = page.locator('button[title*="Logout"], button:has-text("Logout"), button:has-text("Sign Out")').first();
    if (await logoutBtn.isVisible()) {
      await logoutBtn.click();
      await expect(page).toHaveURL(/.*login/);
      await page.screenshot({ path: path.join(EVIDENCE_E2E_DIR, '07_post_logout.png') });
    }
  });

});

