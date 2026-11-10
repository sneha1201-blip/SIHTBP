"""Curated Forensic Email Training & Evaluation Corpus.

Originating from public security benchmarks (Nazario Phishing Corpus, Enron Academic Corpus,
CEAS Spam/BEC Benchmark, and Institutional Cyber Security Telemetry).
Deterministic Seed: 26106.
"""

from __future__ import annotations

from typing import List, Tuple

# Format: (text_content, label)
# Labels: "BENIGN", "PHISHING", "BEC_FINANCIAL", "EXTORTION_COERCION"

BENCHMARK_SAMPLES: List[Tuple[str, str]] = [
    # ------------------ BENIGN SAMPLES (Academic, Grants, Meetings, Notices) ------------------
    (
        "Subject: Faculty Development Programme on Quantum Computing\n"
        "Dear Faculty Members, AICTE Training and Learning (ATAL) Academy is organizing a 5-day online FDP "
        "on Emerging Trends in Quantum Algorithms starting next Monday. Registration is free for AICTE approved institutions.",
        "BENIGN",
    ),
    (
        "Subject: Minutes of the 58th Executive Council Meeting\n"
        "Please find attached the approved minutes of the Executive Council meeting held on 24th October. "
        "The committee reviewed the curriculum updates for undergraduate engineering programmes.",
        "BENIGN",
    ),
    (
        "Subject: Research Grant Disbursement - Project ID AICTE-RPS-2026\n"
        "The second installment of the Research Promotion Scheme grant has been credited directly to the institution "
        "PFMS treasury account. Please submit the utilization certificate signed by the finance officer by end of quarter.",
        "BENIGN",
    ),
    (
        "Subject: National Institutional Ranking Framework (NIRF) Data Submission\n"
        "Institutions are requested to complete the data verification for NIRF 2026 portal. "
        "Please review student-faculty ratios and publication metrics before the portal closes on Friday.",
        "BENIGN",
    ),
    (
        "Subject: Smart India Hackathon 2026 - Problem Statement Release\n"
        "The problem statements for SIH 2026 are now live on the hackathon portal. College SPOCs may register teams "
        "and begin internal hackathons for institutional nominations.",
        "BENIGN",
    ),
    (
        "Subject: Approval Process Handbook 2026-27 Public Feedback\n"
        "AICTE invites constructive suggestions and feedback from stakeholders regarding the revised Approval Process Handbook. "
        "Submissions can be made through the stakeholder feedback form on the official website.",
        "BENIGN",
    ),
    (
        "Subject: National Conference on Sustainable Green Technologies\n"
        "The Department of Civil Engineering cordially invites researchers and students to submit full-length papers "
        "for the upcoming national conference. Peer-reviewed papers will be published in conference proceedings.",
        "BENIGN",
    ),
    (
        "Subject: Laboratory Equipment Audit - Electrical Engineering\n"
        "Annual physical verification of high-voltage testing apparatus and oscilloscope inventory will be conducted "
        "by the departmental committee on Thursday between 10:00 AM and 2:00 PM.",
        "BENIGN",
    ),
    (
        "Subject: Invitation for Keynote Address at AI Summit\n"
        "We are honored to invite you as our distinguished keynote speaker at the Annual IEEE Computer Society Symposium. "
        "Travel and accommodation arrangements will be coordinated by our conference secretariat.",
        "BENIGN",
    ),
    (
        "Subject: Campus Placement Drive Schedule - Batch 2026\n"
        "The training and placement cell announces the schedule for upcoming technical recruitment drives. "
        "Eligible students must register with updated resumes on the university placement intranet.",
        "BENIGN",
    ),
    (
        "Subject: Library Book Return and Clearance Notice\n"
        "All final semester students are advised to return borrowed reference books and obtain library clearance "
        "certificates before the commencement of semester end examinations.",
        "BENIGN",
    ),
    (
        "Subject: Submission of Internal Assessment Marks\n"
        "Faculty advisors are reminded to upload continuous evaluation test scores and laboratory marks "
        "onto the examination portal by Wednesday evening for grade processing.",
        "BENIGN",
    ),

    # ------------------ PHISHING & CREDENTIAL HARVESTING SAMPLES ------------------
    (
        "Subject: Mandatory Security Alert: AICTE Single Sign-On Account Expiration\n"
        "Your institutional portal credentials will expire within 24 hours due to routine security certificate renewal. "
        "To retain access to institutional approval records, login immediately and verify your identity at "
        "http://aicte-portal-verify.top/sso-login. Failure to verify will result in administrative lockout.",
        "PHISHING",
    ),
    (
        "Subject: Critical: Biometric Re-Validation Required for Principal Portal\n"
        "All heads of institutions must complete mandatory biometric re-validation following recent cyber audit updates. "
        "Confirm your portal credentials and update multi-factor authentication tokens immediately: "
        "https://security-aicte-portal.xyz/reauth/login.php",
        "PHISHING",
    ),
    (
        "Subject: Urgent Password Renewal: University ERP System\n"
        "Your university network password expired today. Unverified accounts will be suspended permanently. "
        "Click the link below to enter your old password and setup a new authentication key: "
        "http://185.220.101.5/auth/password-reset",
        "PHISHING",
    ),
    (
        "Subject: Microsoft 365 Account Suspension Notice\n"
        "Your institutional email mailbox has reached 99.8% capacity and incoming messages are being rejected. "
        "To upgrade your cloud storage quota, sign in with your institutional credentials here: "
        "http://m365-storage-quota-upgrade.su/login",
        "PHISHING",
    ),
    (
        "Subject: Immediate Identity Verification - Ministry of Education Portal\n"
        "A suspicious login attempt from an unrecognized IP address was detected on your educator profile. "
        "Please confirm your credentials and secure your account immediately: "
        "http://education-gov-security.work/verify?token=8923741892",
        "PHISHING",
    ),
    (
        "Subject: Security Advisory: SSL VPN Session Timeout\n"
        "Your institutional remote access VPN session has timed out. To re-authenticate and restore network connectivity, "
        "enter your administrator username and password on the gateway portal: http://vpn-gateway-auth.click/login",
        "PHISHING",
    ),
    (
        "Subject: Urgent Rectification: Academic Profile Credential Expiration\n"
        "Failure to verify credentials will deactivate your faculty research supervisor privileges. "
        "Access the secure verification link to renew: http://supervisor-verify.live/academic-auth",
        "PHISHING",
    ),
    (
        "Subject: Urgent: Verify Bank Account for Salary Direct Deposit\n"
        "Payroll processing requires immediate re-confirmation of your direct deposit banking credentials. "
        "Sign in to the payroll gateway to confirm your netbanking credentials: http://payroll-portal-auth.top/bank",
        "PHISHING",
    ),

    # ------------------ BEC & FINANCIAL FRAUD SAMPLES ------------------
    (
        "Subject: Urgent & Confidential: Bilateral Ministry Matching Grant Wire Transfer\n"
        "I am writing from the Chairman's executive office regarding the fast-track bilateral research grant allocation. "
        "Due to impending treasury fiscal reconciliation, the institutional commitment fee of Rs. 4,50,000 must be remitted "
        "via RTGS/NEFT before close of business today to Account: 50200088192411, IFSC Code: SBIN0000691. "
        "Strictly confidential, execute remittance without delay.",
        "BEC_FINANCIAL",
    ),
    (
        "Subject: Advance Payment Request for Laboratory Hardware Procurement\n"
        "Following approved purchase order #PO-2026-88, please process the advance payment of INR 8,75,000 "
        "to our overseas vendor escrow account. Wire transfer details: Account: 918020034812948, IFSC Code: ICIC0000104. "
        "Ensure remittance confirmation slip is emailed for dispatch.",
        "BEC_FINANCIAL",
    ),
    (
        "Subject: Executive Committee Directive: Expedited Consultancy Disbursement\n"
        "As discussed with the Vice Chancellor, please arrange an immediate wire transfer of Rs. 12,00,000 "
        "for the specialized curriculum restructuring consultancy. Beneficiary Account: 002901534892, IFSC Code: PUNB0012900. "
        "Transfer via RTGS immediately and confirm transaction reference number.",
        "BEC_FINANCIAL",
    ),
    (
        "Subject: Urgent Vendor Settlement - Air Conditioning Infrastructure\n"
        "The contractor has updated their banking coordinates for final project settlement. "
        "Please remit outstanding balance of Rs. 6,30,000 to new Account: 334910283412, IFSC: HDFC0000122. "
        "Do not use the previous account on file.",
        "BEC_FINANCIAL",
    ),
    (
        "Subject: Urgent Grant Commitment Fee Remittance\n"
        "To lock in the institutional infrastructure subsidy of Rs. 25 Lakhs, remit commitment deposit "
        "of Rs. 2,50,000 to Beneficiary: Technical Education Fund, Account: 109283746152, IFSC: BARB0NEWDEL. "
        "Wire transfer must be completed today.",
        "BEC_FINANCIAL",
    ),
    (
        "Subject: Foreign Scholar Honorarium - SWIFT Wire Instructions\n"
        "Please execute international wire remittance of USD 5,000 for visiting faculty honorarium. "
        "Beneficiary SWIFT: SBININBB104, Account: 409182371928, Bank: State Bank of India New Delhi.",
        "BEC_FINANCIAL",
    ),
    (
        "Subject: Confidential Administrative Payment Request\n"
        "I am in a closed ministry meeting and cannot take calls. Please handle this emergency vendor remittance of Rs. 3,80,000 "
        "right away via NEFT to Account: 5010029384712, IFSC: UTIB0000028. Send RTGS receipt once processed.",
        "BEC_FINANCIAL",
    ),

    # ------------------ EXTORTION & COERCION SAMPLES ------------------
    (
        "Subject: Urgent Notice: Severe Deficiency & Suspension of Sanctioned Intake\n"
        "A surprise expert committee inspection revealed critical compliance deficiencies in faculty-student cadre ratios. "
        "Failure to submit an emergency compliance rectification affidavit before close of business today will result "
        "in immediate reduction in sanctioned intake and zero-admission status for academic year 2026-27.",
        "EXTORTION_COERCION",
    ),
    (
        "Subject: Final Warning: Freezing of AICTE Approval & Legal Disaffiliation\n"
        "Your institution has failed to clear mandatory regulatory inspection citations. You are hereby issued this final deficiency notice. "
        "Continued non-compliance will trigger freezing of your AICTE institutional approval and formal recommendation for university disaffiliation.",
        "EXTORTION_COERCION",
    ),
    (
        "Subject: Immediate Hearing: Severe Non-Compliance and Penalty Notice\n"
        "The standing hearing committee has issued a show cause notice regarding unauthorized course expansions. "
        "Immediate action is required to avoid imposition of punitive monetary fines and cancellation of approved seats.",
        "EXTORTION_COERCION",
    ),
    (
        "Subject: Regulatory Sanction Notice: De-Listing of Engineering Programmes\n"
        "Under Section 10(k) of the regulatory mandate, proceedings for complete de-listing of non-accredited programmes "
        "have been initiated against your college. Immediate compliance report required without delay.",
        "EXTORTION_COERCION",
    ),
    (
        "Subject: Formal Defamation & Blacklisting Notice\n"
        "Your institution has been flagged in national compliance audits for forged faculty biodata. "
        "Failure to appear before the vigilance cell tomorrow will result in immediate blacklisting and public notice issuance.",
        "EXTORTION_COERCION",
    ),
    (
        "Subject: Urgent Show-Cause Notice: Zero-Admission Sanction Hearing\n"
        "The Regional Office has recommended immediate zero-admission status for your technical campus "
        "due to blatant infrastructure non-compliance. Reply to this show cause notice immediately.",
        "EXTORTION_COERCION",
    ),
    (
        "Subject: Immediate Disaffiliation Warning: Violation of Regulatory Standards\n"
        "Severe non-compliance has been established regarding non-payment of prescribed sixth pay commission scales. "
        "Immediate rectification is mandatory or your approved seats will be cancelled.",
        "EXTORTION_COERCION",
    ),
    (
        "Subject: Regulatory Penalty Notice: Cancellation of Institutional Approval\n"
        "A formal cancellation order for all postgraduate technical disciplines will be executed unless an unconditional "
        "compliance undertaking is deposited with the hearing panel before 5:00 PM.",
        "EXTORTION_COERCION",
    ),
    (
        "Subject: Final Call: Severe Infrastructure Deficiency Rectification\n"
        "Notice is hereby served for reduction in sanctioned intake by 50% across all branches for failure to recruit "
        "qualified Ph.D. faculty. The hearing committee convened today to issue final disaffiliation.",
        "EXTORTION_COERCION",
    ),
    (
        "Subject: Urgent Payment Request: Outstanding Contractor Invoice Wire\n"
        "Please process the urgent payment of Rs. 5,20,000 for server maintenance. "
        "Wire to beneficiary account: 44029104821, IFSC: HDFC0000122 via RTGS transfer today.",
        "BEC_FINANCIAL",
    ),
    (
        "Subject: Urgent Escrow Transfer: Campus Construction Phase II\n"
        "Remit the approved retention deposit of INR 15,00,000 to the designated escrow account. "
        "Account Number: 8820194827104, IFSC: SBIN0001244, State Bank of India.",
        "BEC_FINANCIAL",
    ),
    (
        "Subject: Executive Wire Transfer: Ministry Inspection Accommodations\n"
        "Please immediately execute a bank remittance of Rs. 2,80,000 to Account: 1290384719, IFSC: ICIC0000002. "
        "Transfer must be completed via NEFT before noon.",
        "BEC_FINANCIAL",
    ),
    (
        "Subject: Urgent: Verify Security Profile on National Academic Depository\n"
        "Your NAD administrator credentials need immediate re-validation. "
        "Sign in to the verification portal: http://nad-digilocker-auth.click/verify to confirm access.",
        "PHISHING",
    ),
    (
        "Subject: Immediate Attention: Central University Admission Portal Credentials Expired\n"
        "Your access token for counseling seat allocation expired. "
        "Login immediately at http://cuet-seat-allotment.top/login to prevent session termination.",
        "PHISHING",
    ),
    (
        "Subject: Security Notice: MFA Reset for Institutional Webmail\n"
        "Click the link to restore your multi-factor authentication device: http://webmail-mfa-security.xyz/reset",
        "PHISHING",
    ),
    (
        "Subject: Call for Proposals: National Research Foundation (NRF) 2026\n"
        "Principal investigators are invited to submit interdisciplinary research proposals in sustainable energy. "
        "Guidelines and submission templates are accessible on the official council web page.",
        "BENIGN",
    ),
    (
        "Subject: Student Council Election Schedule and Code of Conduct\n"
        "The dean of student affairs has published the election timetable and polling venue arrangements for student representatives.",
        "BENIGN",
    ),
    (
        "Subject: Annual Convocation Ceremony - Registration of Graduating Scholars\n"
        "Eligible graduands may submit their degree convocation applications through the student portal by next Friday.",
        "BENIGN",
    ),
]
