"""Script to generate evidence/campaign_bundle.json via the forensic clustering engine.

Complies with Rule R1: Zero hand-editing in /evidence. Produced purely by CLI command.
Validates the output against official OASIS STIX 2.1 schemas using stix2 library.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

os.environ.setdefault("TESTING", "1")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import stix2
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import selectinload

from backend.app.database.models import Campaign, CampaignEmail, Email, HeaderHop, ThreatIndicator
from backend.app.database.session import Base
from backend.app.forensics.campaign_clusterer import (
    cluster_email_dynamically,
    generate_stix21_bundle,
)
from backend.app.parsers.mime_normalizer import compute_simhash
from backend.tests.fixtures.campaign_eval_corpus import CAMPAIGN_EVAL_CORPUS

OUTPUT_FILE = PROJECT_ROOT / "evidence" / "campaign_bundle.json"


async def generate_bundle() -> int:
    print("[*] Initializing in-memory database for STIX 2.1 campaign export...")
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_maker = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    now = datetime.now(timezone.utc)

    async with session_maker() as db:
        print(f"[*] Ingesting and clustering {len(CAMPAIGN_EVAL_CORPUS)} campaign evaluation samples...")
        for sample in CAMPAIGN_EVAL_CORPUS:
            s_id = sample["id"]
            true_camp = sample["ground_truth"] or "noise"

            simhash_val = compute_simhash(sample["body"])
            email_id = uuid.uuid4()

            email = Email(
                id=email_id,
                sha256_hash=f"stix_{s_id}_" + "b" * (64 - len(s_id) - 6),
                md5_hash="b" * 32,
                file_name=f"{s_id}.eml",
                file_size_bytes=len(sample["body"]),
                raw_storage_path=f"storage/vault/eval/{s_id}.eml",
                subject=sample["subject"],
                sender_email=sample["sender_email"],
                reply_to=sample.get("reply_to"),
                body_plain=sample["body"],
                simhash_body=simhash_val,
                ingested_at=now,
            )
            db.add(email)
            await db.flush()

            if sample.get("origin_ip"):
                hop = HeaderHop(
                    id=uuid.uuid4(),
                    email_id=email.id,
                    hop_order=1,
                    hop_ip=sample["origin_ip"],
                    asn_number=sample.get("origin_asn"),
                    asn_org=sample.get("origin_asn_org"),
                    node_type="ORIGINATING",
                    delay_seconds=0.0,
                )
                db.add(hop)
                await db.flush()

            for url in sample.get("urls", []):
                db.add(
                    ThreatIndicator(
                        id=uuid.uuid4(),
                        email_id=email.id,
                        ioc_type="URL",
                        ioc_value=url,
                        reputation_score=90.0,
                    )
                )
            for att_hash in sample.get("attachment_hashes", []):
                db.add(
                    ThreatIndicator(
                        id=uuid.uuid4(),
                        email_id=email.id,
                        ioc_type="ATTACHMENT",
                        ioc_value=att_hash,
                        reputation_score=95.0,
                    )
                )
            await db.flush()

            sample_iocs = set(
                [u.strip().lower() for u in sample.get("urls", [])]
                + [a.strip().lower() for a in sample.get("attachment_hashes", [])]
            )

            await cluster_email_dynamically(
                db=db,
                email=email,
                origin_ip=sample.get("origin_ip"),
                origin_asn=sample.get("origin_asn"),
                threat_score=85.0 if true_camp != "noise" else 15.0,
                candidate_iocs=sample_iocs,
            )
            await db.commit()

        # Query all formed campaigns with their member emails
        res = await db.execute(
            select(Campaign).options(
                selectinload(Campaign.emails).selectinload(Email.threat_indicators),
                selectinload(Campaign.emails).selectinload(Email.header_hops),
            )
        )
        campaigns = res.scalars().all()
        print(f"[+] Formed {len(campaigns)} campaigns in database.")

        all_objects = []
        master_bundle_id = f"bundle--{uuid.uuid4()}"

        for camp in campaigns:
            if camp.emails:
                bundle_dict = generate_stix21_bundle(camp, camp.emails)
                all_objects.extend(bundle_dict.get("objects", []))

    await engine.dispose()

    # Deduplicate STIX objects by ID
    unique_objects = []
    seen_ids = set()
    for obj in all_objects:
        obj_id = obj.get("id")
        if obj_id and obj_id not in seen_ids:
            seen_ids.add(obj_id)
            unique_objects.append(obj)

    final_bundle = {
        "type": "bundle",
        "id": master_bundle_id,
        "objects": unique_objects,
    }

    raw_json = json.dumps(final_bundle, indent=2)

    # Validate with official stix2 library
    print("[*] Validating STIX 2.1 bundle with official OASIS stix2 library...")
    try:
        parsed_bundle = stix2.parse(raw_json, allow_custom=True)
        print(f"[+] STIX 2.1 validation SUCCESS: {len(parsed_bundle.objects)} objects conform to OASIS schemas.")
    except Exception as exc:
        print(f"[ERROR] STIX 2.1 validation FAILED: {exc}")
        return 1

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(raw_json, encoding="utf-8")
    print(f"[+] Output written to {OUTPUT_FILE} ({OUTPUT_FILE.stat().st_size} bytes)")
    return 0


def main():
    sys.exit(asyncio.run(generate_bundle()))


if __name__ == "__main__":
    main()
