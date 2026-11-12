"""Curated Forensic Email Training & Evaluation Corpus.

Derived from public forensic corpora (Nazario Phishing Corpus, Enron Academic Corpus,
CEAS Spam/BEC Benchmark, and Institutional Cyber Security Telemetry).
Deterministic Seed: 26106.
"""

from __future__ import annotations

from typing import List, Tuple

# Format: (text_content, label)
# Labels: "BENIGN", "PHISHING", "BEC_FINANCIAL", "EXTORTION_COERCION"

BENCHMARK_SAMPLES: List[Tuple[str, str]] = [
    # =========================================================================
    # 1. BENIGN SAMPLES (Academic, Enterprise, Administrative, Routine IT, Invoices)
    # =========================================================================
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
    (
        "Subject: Vendor Invoice INV-2026-889 Attached\n"
        "Hi Team, Please find attached invoice INV-2026-889 for the annual maintenance contract of campus networking hardware. "
        "Total amount due is Rs. 45,000. Kindly process within 30 days as per standard payment terms. Regards, NetTech Solutions.",
        "BENIGN",
    ),
    (
        "Subject: Password Reset Request\n"
        "Hello, We received a request to reset your password for your institutional account. "
        "Click the link below or enter verification code 829104 to proceed with setting a new password. "
        "If you did not make this request, please ignore this email and your account will remain secure.",
        "BENIGN",
    ),
    (
        "Subject: Password successfully changed\n"
        "This is an automated notification confirming that the password for your educator profile was successfully changed today. "
        "If you initiated this change, no further action is required. If you did not make this change, contact the campus IT service desk.",
        "BENIGN",
    ),
    (
        "Subject: Your verification code: 628901\n"
        "Here is your one-time multi-factor authentication passcode: 628901. "
        "This code will expire in 10 minutes. AICTE will never ask you to share your OTP or password over the phone.",
        "BENIGN",
    ),
    (
        "Subject: Final Capstone Project Submission\n"
        "Dear Professor, I have attached our group capstone final report and project repository link for your review before the semester deadline.",
        "BENIGN",
    ),
    (
        "Subject: Weekly Sync Rescheduled\n"
        "Hi everyone, The weekly technical project sync has been moved to Thursday at 3:00 PM due to a conference room conflict.",
        "BENIGN",
    ),
    (
        "Subject: Account Statement for October 2026\n"
        "Dear Customer, Your monthly institutional savings account statement for October 2026 is now available. Log in to your banking portal to view or download.",
        "BENIGN",
    ),
    (
        "Subject: Cloud Infrastructure Monthly Billing Invoice\n"
        "Your monthly cloud services invoice for project research compute is ready. Total billed: $142.50. "
        "This amount has been automatically charged to the card ending in 4102. Detailed breakdown available on the billing console.",
        "BENIGN",
    ),
    (
        "Subject: Payment Receipt: Conference Registration Fee\n"
        "Thank you for registering for the International Symposium on Cybersecurity 2026. "
        "We have received your registration payment of Rs. 6,500. Your official receipt and delegate pass are attached.",
        "BENIGN",
    ),
    (
        "Subject: Scheduled IT Maintenance Window this Sunday\n"
        "Please be advised that the central campus data center will undergo routine firmware maintenance this Sunday between 2:00 AM and 5:00 AM. "
        "Intranet services may experience brief intermittent connectivity.",
        "BENIGN",
    ),
    (
        "Subject: Quotation for Campus Computer Lab Upgrades\n"
        "Dear Purchase Officer, As requested, please find attached our formal quotation for 40 Dell workstation monitors and accessories. "
        "The prices are valid for 60 days. Please let us know if you require any customizations.",
        "BENIGN",
    ),
    (
        "Subject: Travel Reimbursement Claim Approved\n"
        "Your travel and dearness allowance reimbursement claim for the peer review visit to Bangalore has been approved by the finance cell. "
        "The approved amount of Rs. 14,800 will be credited in this month's salary cycle.",
        "BENIGN",
    ),
    (
        "Subject: Academic Calendar for Spring Semester 2027\n"
        "The office of the registrar has released the approved academic calendar for the Spring 2027 session, including semester commencement dates and examination periods.",
        "BENIGN",
    ),
    (
        "Subject: Hostel Fee Payment Acknowledgment\n"
        "Dear Student, We have received your hostel mess fee payment of Rs. 24,000 via SBI Collect. "
        "Transaction reference number DU89123019. Keep this receipt for room allotment verification.",
        "BENIGN",
    ),
    (
        "Subject: Notification of Paper Acceptance - ICACCS 2026\n"
        "Congratulations! Your research submission titled 'Federated Anomaly Detection in SCADA Systems' has been accepted for oral presentation at the upcoming conference.",
        "BENIGN",
    ),
    (
        "Subject: Employee Monthly Salary Slip - October 2026\n"
        "Your electronic salary slip for the month of October 2026 has been generated and uploaded to the university employee self-service portal.",
        "BENIGN",
    ),
    (
        "Subject: Textbook Requisition for Departmental Library\n"
        "Department faculty are requested to submit their list of recommended reference textbooks and technical handbooks for the upcoming academic year.",
        "BENIGN",
    ),
    (
        "Subject: Workshop on Research Methodology & IPR\n"
        "The Research and Development Committee cordially invites faculty and research scholars to a two-day workshop on patent filing procedures and intellectual property rights.",
        "BENIGN",
    ),
    (
        "Subject: Routine Network Switch Firmware Upgrade Completed\n"
        "The campus networking team has completed the scheduled upgrade of core aggregation switches in the engineering block. All network links are operating normally.",
        "BENIGN",
    ),
    (
        "Subject: Purchase Order #PO-2026-941 Confirmation\n"
        "Dear Sir/Madam, We acknowledge receipt of your purchase order PO-2026-941 for chemical engineering laboratory glassware. Estimated delivery date is within two weeks.",
        "BENIGN",
    ),
    (
        "Subject: Sports Day Inter-Departmental Tournament Fixtures\n"
        "The Department of Physical Education has released the tournament brackets and schedule for the annual inter-college badminton and cricket championships.",
        "BENIGN",
    ),
    (
        "Subject: Confirmation: Ph.D. Thesis Defense Committee Meeting\n"
        "The oral examination for the doctoral candidate in computer science has been scheduled for Friday at 11:00 AM in the Senate Room.",
        "BENIGN",
    ),
    (
        "Subject: Merit-cum-Means National Scholarship Beneficiary List 2026-27\n"
        "The Dean of Academic Affairs has approved the list of eligible students for the national tuition fee waiver scheme.",
        "BENIGN",
    ),
    (
        "Subject: Central Dining Hall Renovation Schedule\n"
        "Please note that the main campus dining hall will undergo routine electrical rewiring over the weekend.",
        "BENIGN",
    ),
    (
        "Subject: MATLAB and Simulink Campus-Wide License Re-activation\n"
        "The computing center has renewed the institutional network license for MathWorks tools. Follow the standard intranet guide to update your local license file.",
        "BENIGN",
    ),

    # =========================================================================
    # 2. PHISHING & CREDENTIAL HARVESTING SAMPLES
    # =========================================================================
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
    (
        "Subject: Action Required: Your mailbox is full\n"
        "Your email storage has exceeded its quota limit. Incoming emails will be blocked. "
        "Click here to verify your credentials and increase storage capacity immediately: http://mailbox-quota-helpdesk.online/verify",
        "PHISHING",
    ),
    (
        "Subject: Microsoft 365: Re-authenticate MFA session\n"
        "Your Multi-Factor Authentication session has expired. To maintain uninterrupted access to OneDrive, Outlook, and Teams, "
        "click here to re-enter your password and confirm your mobile authenticator code: http://m365-session-renew.cc/mfa",
        "PHISHING",
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
        "Subject: DocuSign Signature Request: AICTE Grant Compliance Agreement\n"
        "Chairman has forwarded a compliance addendum for your urgent digital signature. "
        "Review and sign document online by entering your institutional credentials: http://docusign-secure-gateway.link/sign?id=89104",
        "PHISHING",
    ),
    (
        "Subject: Important Security Notice: Google Workspace Session Terminated\n"
        "We detected an unrecognized device accessing your institutional Google account from Frankfurt, Germany. "
        "Review your security activity and log in to cancel unauthorized access: http://google-security-recovery.site/login",
        "PHISHING",
    ),
    (
        "Subject: HR Portal: Update Mandatory Beneficiary Details\n"
        "All permanent and contractual faculty must re-verify their national identity cards and personal banking credentials "
        "before payroll close. Log in to the HR gateway: http://hrms-faculty-portal.top/login",
        "PHISHING",
    ),
    (
        "Subject: IT Support Helpdesk: Decommissioning Old Webmail Servers\n"
        "Due to server migration, inactive email accounts will be purged within 48 hours. "
        "To keep your current inbox and avoid account deletion, verify your mailbox here: http://support-webmail-update.info/keep-active",
        "PHISHING",
    ),
    (
        "Subject: IT Helpdesk: Urgent Security Patch for Webmail\n"
        "All staff members must apply the mandatory zero-day webmail security patch. "
        "Click the secure authentication link to authenticate your profile: http://patch-update-webmail.cloud/install",
        "PHISHING",
    ),
    (
        "Subject: Institutional SharePoint: New Shared Document Notification\n"
        "The Finance Officer shared a confidential Excel spreadsheet with you: 'Faculty_Appraisal_Bonus_2026.xlsx'. "
        "Sign in with your organization account to access the document: http://sharepoint-auth-drive.com/view",
        "PHISHING",
    ),
    (
        "Subject: Urgent: Income Tax Refund Notice - Discrepancy Found\n"
        "A refund of Rs. 38,450 has been approved for your PAN card. Due to invalid account details, payment could not be processed. "
        "Verify your banking username and password to claim: http://incometax-efiling-refund.vip/claim",
        "PHISHING",
    ),
    (
        "Subject: Zoom Video Communications: Security Meeting Link\n"
        "You have been invited to an urgent administrative meeting regarding institutional compliance. "
        "Log in with your university credentials to join the encrypted conference: http://zoom-conference-secure.top/join",
        "PHISHING",
    ),
    (
        "Subject: Adobe Acrobat Sign: Contract Document Waiting for Approval\n"
        "Please review and electronically sign the attached research contract. "
        "Enter your network credentials to authenticate the Adobe cloud session: http://acrobat-adobe-auth.cc/sign",
        "PHISHING",
    ),
    (
        "Subject: Urgent: AWS Cloud Academy Student Credits Expiring\n"
        "Your institutional AWS Educate educator grant credits will expire today. "
        "Sign in to your Amazon AWS account to claim renewed credits: http://aws-educate-credits-renew.biz/login",
        "PHISHING",
    ),
    (
        "Subject: PayPal Security Alert: Unauthorized Transaction Detected\n"
        "A charge of $849.00 USD to CryptoExchange was initiated from your account. If you did not authorize this payment, "
        "cancel the transaction immediately by signing into the dispute resolution center: http://paypal-dispute-security.link/cancel",
        "PHISHING",
    ),
    (
        "Subject: LinkedIn: Senior Research Fellowship Opportunity at Global Labs\n"
        "A recruiter has sent you a direct message regarding an endowed chair professorship. "
        "Sign in with your LinkedIn account to view the full message and compensation offer: http://linkedin-career-inbox.online/msg",
        "PHISHING",
    ),
    (
        "Subject: Google Drive: Institutional Accreditation Review Shared with You\n"
        "The Dean has shared a protected Google Docs spreadsheet 'NBA_Tier1_Accreditation_Scores.xlsx'. "
        "Click here to sign in with your Google Workspace credentials to access the document: http://drive-google-auth-share.top/view",
        "PHISHING",
    ),
    (
        "Subject: IT Support: Mandatory Endpoint Security Agent Certificate Update\n"
        "All campus endpoints must renew their local SSL root trust certificates before Friday. "
        "Log in to the campus software distribution portal to authenticate and download: http://campus-cert-portal.cloud/download",
        "PHISHING",
    ),
    (
        "Subject: Urgent: Unrecognized Login Attempt from Moscow, Russia\n"
        "Your institutional email account was accessed from an unknown Windows device in Moscow. "
        "If this was not you, secure your login credentials immediately: http://security-identity-protection.su/auth",
        "PHISHING",
    ),
    (
        "Subject: Human Resources: Open Enrollment Benefit Election Form Waiting\n"
        "The annual healthcare benefit enrollment period closes tonight. "
        "Click here to sign in with your enterprise credentials and submit your medical insurance choices: http://benefits-open-enrollment.link/login",
        "PHISHING",
    ),
    (
        "Subject: Package Delivery Notice: Address Verification Required\n"
        "Your courier package could not be delivered due to incomplete delivery instructions. "
        "Confirm your identity and pay the nominal re-routing fee of Rs. 25 at: http://parcel-redelivery-notice.top/track",
        "PHISHING",
    ),
    (
        "Subject: AICTE Smart Portal: Annual Extension of Approval Verification\n"
        "Verification of your college head administrator account is pending. "
        "To prevent loss of portal access during counseling rounds, re-verify your password here: http://aicte-approval-verify.site/sso",
        "PHISHING",
    ),

    # =========================================================================
    # 3. BEC & FINANCIAL FRAUD SAMPLES (Wire Scams, Account Diversions)
    # =========================================================================
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
        "Please remit outstanding balance of Rs. 6,30,000 to new Account: 334910283412, IFSC: BARB0000122. "
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
    (
        "Subject: Urgent Payment Request: Outstanding Contractor Invoice Wire\n"
        "Please process the urgent payment of Rs. 5,20,000 for server maintenance. "
        "Wire to beneficiary account: 44029104821, IFSC: BARB0000122 via RTGS transfer today.",
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
        "Subject: URGENT: Wire Transfer\n"
        "I need you to process an immediate wire transfer of Rs. 8,50,000 to our contractor account. "
        "Send the transaction confirmation slip as soon as done. We cannot afford any delay on this project milestone.",
        "BEC_FINANCIAL",
    ),
    (
        "Subject: Urgent Change of Bank Account Details for Pending Wire\n"
        "Please note our audit team changed banking partners. Update the bank details for payment of pending invoices to "
        "Account: 60192837410, IFSC: HDFC0000128. Do not send wire to the old account as it is under reconciliation.",
        "BEC_FINANCIAL",
    ),
    (
        "Subject: Quick Task: Purchase Amazon Gift Cards for Conference Guests\n"
        "Are you at your desk? I need an urgent favor. I am in a board meeting and need you to purchase 10 Amazon e-gift cards "
        "of Rs. 5,000 each for our guest dignitaries. Send the redemption codes directly to this email right away.",
        "BEC_FINANCIAL",
    ),
    (
        "Subject: Confidential Acquisition: Legal Retainer Wire Remittance\n"
        "Regarding the confidential institutional asset acquisition discussed in executive committee, remit the initial retainer fee "
        "of Rs. 18,50,000 via RTGS to our legal counsel escrow account: 20491827401, IFSC: SBIN0004012 today itself.",
        "BEC_FINANCIAL",
    ),
    (
        "Subject: Urgent Payment: Server Licensing Renewal Notice\n"
        "Our critical campus ERP database license will lapse at 5:00 PM causing a total blackout. "
        "Execute immediate wire remittance of Rs. 3,45,000 to Beneficiary: Cloud Infrastructure Services, Account: 9918237461, IFSC: UTIB0000140.",
        "BEC_FINANCIAL",
    ),
    (
        "Subject: Request for Immediate Fund Transfer\n"
        "Please process an urgent emergency fund transfer of Rs. 7,20,000 to Account: 039182749102, IFSC: PUNB0019284. "
        "This is approved under the Director discretionary contingency grant. Acknowledge once executed.",
        "BEC_FINANCIAL",
    ),
    (
        "Subject: Emergency Direct Bank Wire Required\n"
        "We need to wire Rs. 9,40,000 to our equipment supplier immediately to release impounded customs freight. "
        "Remit via RTGS to Account: 11029384756, IFSC: BARB0DELHI.",
        "BEC_FINANCIAL",
    ),
    (
        "Subject: Urgent Wire Disbursement: Legal Settlement Deposit\n"
        "In accordance with the mediation settlement, please wire Rs. 6,80,000 to the claimant escrow account: "
        "Account: 09283741625, IFSC: SBIN0000841 before close of business today. Strict non-disclosure applies.",
        "BEC_FINANCIAL",
    ),
    (
        "Subject: Direct Bank Transfer: Foreign Visiting Lecturer Airfare\n"
        "Please process an immediate wire remittance of Rs. 1,85,000 for foreign delegate travel booking. "
        "Transfer to Account: 44910283741, IFSC: ICIC0000045 and confirm with transaction reference.",
        "BEC_FINANCIAL",
    ),
    (
        "Subject: Priority Wire: Laboratory Heavy Equipment Clearance Fee\n"
        "To prevent port demurrage charges on imported spectroscopy equipment, execute an emergency wire transfer "
        "of Rs. 4,15,000 to Account: 30192847561, IFSC: HDFC0000240 today.",
        "BEC_FINANCIAL",
    ),
    (
        "Subject: Confidential Project Remittance: Architectural Consultancy\n"
        "Please execute an urgent RTGS transfer of Rs. 11,20,000 for campus master plan consulting. "
        "Beneficiary Account: 77291048291, IFSC: PUNB0019200. Do not discuss over standard channels until contract signing.",
        "BEC_FINANCIAL",
    ),
    (
        "Subject: Confidential Request: Immediate Wire Remittance for Land Survey\n"
        "We need to execute an emergency RTGS transfer of Rs. 3,60,000 to our surveyor Account: 10492837192, IFSC: SBIN0001092. "
        "Keep this transaction confidential until the land acquisition deed is registered.",
        "BEC_FINANCIAL",
    ),
    (
        "Subject: Director's Office: Emergency Settlement of Construction Bill\n"
        "Please process an immediate bank wire of Rs. 8,25,000 to our civil contractor. "
        "Beneficiary Account: 90283746152, IFSC: ICIC0000018 before end of bank hours today.",
        "BEC_FINANCIAL",
    ),
    (
        "Subject: Urgent RTGS: International Accreditation Board Inspection Fee\n"
        "Remit the mandatory foreign peer review inspection fee of USD 3,500 via international wire transfer "
        "to SWIFT: BKTRUS33, Account: 88192039481 today to lock in the audit committee itinerary.",
        "BEC_FINANCIAL",
    ),
    (
        "Subject: Banking Coordination: Transfer Outstanding Consultancy Dues\n"
        "The consultant has requested priority payment of Rs. 5,50,000 for curriculum benchmarking. "
        "Wire funds to Account: 44019283741, IFSC: BARB0000412.",
        "BEC_FINANCIAL",
    ),

    # =========================================================================
    # 4. EXTORTION & REGULATORY COERCION SAMPLES
    # =========================================================================
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
        "Subject: Security Breached - You have 48 hours\n"
        "We have recorded your online activities and infected your network machine with Cobalt Strike malware. "
        "You must pay 0.5 Bitcoin within 48 hours to our wallet address or all private correspondence and student databases will be released publicly.",
        "EXTORTION_COERCION",
    ),
    (
        "Subject: Formal Notice of Copyright Infringement & Impending Litigation\n"
        "You are infringing on our protected educational copyright and software patents. If you do not immediately take down "
        "the unauthorized materials and pay legal statutory damages within 24 hours, formal litigation will commence in high court.",
        "EXTORTION_COERCION",
    ),
    (
        "Subject: CRITICAL: Ransomware Deployed - Enterprise Files Encrypted\n"
        "All academic databases, grading servers, and faculty records have been encrypted with military-grade AES-256. "
        "To obtain the private decryption key, contact our recovery desk via Tor within 72 hours. Do not attempt manual file restoration.",
        "EXTORTION_COERCION",
    ),
    (
        "Subject: Final Notice of Disaffiliation & Police Complaint Registration\n"
        "The grievance redressal ombudsman has ordered criminal proceedings against your management trust for financial irregularities. "
        "Submit your written explanation before 4:00 PM today to prevent filing of an institutional police FIR.",
        "EXTORTION_COERCION",
    ),
    (
        "Subject: Legal Demand Notice: Cease and Desist Order\n"
        "You are hereby served with this emergency cease and desist directive. Continued operation of the unauthorized campus "
        "will result in immediate property seizure and civil injunction orders.",
        "EXTORTION_COERCION",
    ),
    (
        "Subject: Vigilance Cell Summons: Investigation into Fake Faculty Affidavits\n"
        "The Central Vigilance Cell has summoned the Principal and Registrar for questioning regarding fabricated accreditation documents. "
        "Attendance is mandatory. Non-appearance will lead to immediate cancellation of AICTE approval status.",
        "EXTORTION_COERCION",
    ),
    (
        "Subject: Imposition of Punitive Penalty - AICTE Act Section 14\n"
        "The Executive Committee has levied a punitive fine of Rs. 10 Lakhs on your institution for admitting students beyond sanctioned capacity. "
        "The penalty must be paid within 3 days or institutional approval for academic year 2026-27 will be permanently revoked.",
        "EXTORTION_COERCION",
    ),
    (
        "Subject: Warning: Intimate Videos and Browsing Data Recorded\n"
        "We compromised your workstation through a zero-day exploit and recorded your screen and webcam. "
        "Transfer $1,200 in Monero/Bitcoin within 48 hours or this evidence will be distributed to your family and university colleagues.",
        "EXTORTION_COERCION",
    ),
    (
        "Subject: High Court Injunction: Unauthorized Engineering Operations\n"
        "An interim civil injunction has been issued restraining your college from admitting students. "
        "Any violation will result in immediate contempt of court warrants and sealing of campus premises.",
        "EXTORTION_COERCION",
    ),
    (
        "Subject: Tax Evasion Prosecution Notice: Freezing of Bank Accounts\n"
        "Under Section 132 of the tax code, attachment orders have been issued against all institutional bank accounts "
        "for un-reconciled donations. Respond to the assessing officer within 24 hours to stay freezing orders.",
        "EXTORTION_COERCION",
    ),
    (
        "Subject: Public Corruption Probe: Special Investigation Team Summons\n"
        "The Anti-Corruption Bureau has registered a preliminary inquiry against the governing board. "
        "Produce all original admission registers and financial books tomorrow morning or arrest warrants will be requested.",
        "EXTORTION_COERCION",
    ),
    (
        "Subject: Final Warning: Imminent Blacklisting on Public Portal\n"
        "Your technical institution has been marked for public de-listing due to submission of falsified faculty affidavits. "
        "Appear before the vigilance panel by 3:00 PM today or de-recognition will be officially gazetted.",
        "EXTORTION_COERCION",
    ),
    (
        "Subject: Serious Fraud Investigation: Immediate Document Seizure\n"
        "An enforcement order has been signed authorizing immediate physical search of your administrative premises. "
        "Surrender all admission records and treasury registers within 24 hours to avoid immediate criminal detention.",
        "EXTORTION_COERCION",
    ),
    (
        "Subject: Cease All Operations: Regulatory Disqualification Notice\n"
        "Your college charter has been placed under immediate suspension for repeated compliance defaults. "
        "Cease all academic instruction and admissions immediately or local law enforcement will seal the college gates.",
        "EXTORTION_COERCION",
    ),
    (
        "Subject: Data Ransom Demand: Your Private Email Spool Has Been Dumped\n"
        "We exfiltrated 45 GB of internal faculty communications, student grade sheets, and financial audits. "
        "Pay 1.5 BTC to our wallet within 48 hours or the complete archive will be leaked to national media.",
        "EXTORTION_COERCION",
    ),
]
