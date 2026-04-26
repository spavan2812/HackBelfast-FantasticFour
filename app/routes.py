from flask import Blueprint, render_template, send_from_directory, request, Response, jsonify, stream_with_context
import os
import json
import requests as http

OLLAMA = os.environ.get('OLLAMA_HOST', 'http://localhost:11434')

main = Blueprint('main', __name__)

# Load questions.json once at startup
_q_path = os.path.join(os.path.dirname(__file__), '..', 'logic', 'questions.json')
with open(_q_path) as _f:
    _assessment_data = json.load(_f)

QUESTIONS = _assessment_data['questions']
SCORING_MODEL = _assessment_data['scoring_model']
QUESTIONS_BY_ID = {q['id']: q for q in QUESTIONS}

# Sections that carry scoring weight (used for readiness check)
_SCORED_SECTIONS = {'ransomware', 'data_protection', 'network_security', 'incident_response', 'compliance'}
_CORE_SECTIONS = {'ransomware', 'data_protection', 'network_security'}

# Questions pre-populated from the onboarding profile — don't count toward the visible assessment cap
_SEEDED_IDS = {'CTX_001', 'CTX_002', 'CTX_003', 'CTX_004', 'CTX_005', 'CTX_006', 'CTX_007', 'COMP_001'}
MAX_ASSESSMENT_QUESTIONS = 20

# ---------------------------------------------------------------------------
# Business scoping — maps question IDs to the scope(s) they require.
# Questions absent from this map are universal (apply to every business).
#
# Scopes:
#   self_hosted_infra  — business manages its own servers / databases / network
#   cloud_managed_infra — business runs workloads on IaaS (AWS/Azure/GCP)
#   custom_software    — business writes its own software / has a dev team
# ---------------------------------------------------------------------------
_SCOPE_REQUIREMENTS = {
    # Own-infrastructure backup & network controls
    'RAN_001': ['self_hosted_infra'],   # do you back up critical systems?
    'RAN_002': ['self_hosted_infra'],   # when did you last test restoring?
    'RAN_003': ['self_hosted_infra'],   # backup frequency
    'RAN_004': ['self_hosted_infra'],   # where are backups stored?
    'RAN_005': ['self_hosted_infra'],   # are backups encrypted?
    'RAN_013': ['self_hosted_infra'],   # network segmentation
    'NET_001': ['self_hosted_infra'],   # firewall / perimeter
    'NET_005': ['self_hosted_infra'],   # IDS / IPS
    'NET_009': ['self_hosted_infra'],   # NAC / 802.1X
    'CHANGE_001': ['self_hosted_infra'],  # change management process
    'CHANGE_002': ['self_hosted_infra'],  # rollback procedures
    # Cloud IaaS management
    'CLOUD_002': ['cloud_managed_infra'],  # CSPM
    'CLOUD_003': ['cloud_managed_infra'],  # cloud workload protection
    'CLOUD_004': ['cloud_managed_infra'],  # IAM
    'CLOUD_005': ['cloud_managed_infra'],  # cloud data encryption
    'CLOUD_006': ['cloud_managed_infra'],  # IaC / config management
    'CLOUD_007': ['cloud_managed_infra'],  # cloud logging
    'CLOUD_008': ['cloud_managed_infra'],  # secrets management
    'CLOUD_009': ['cloud_managed_infra'],  # container security
    'CLOUD_010': ['cloud_managed_infra'],  # cloud backup / DR
    # Custom software development
    'APP_001': ['custom_software'],    # secure SDLC
    'APP_002': ['custom_software'],    # SAST/DAST code scanning
    'APP_003': ['custom_software'],    # dependency / supply chain scanning
    'APP_004': ['custom_software'],    # code review process
    'APP_005': ['custom_software'],    # API security testing
    'VULN_001': ['custom_software'],   # vulnerability disclosure program
    'SUPPLY_001': ['custom_software'], # software supply chain
    # Either devs or IaaS managers need this
    'CRYPTO_001': ['custom_software', 'cloud_managed_infra'],
    # Only relevant when the business actually handles sensitive data
    'DATA_005': ['sensitive_data'],   # encryption at rest
    'DATA_007': ['sensitive_data'],   # DLP
    'DATA_006': ['sensitive_data'],   # data classification policy
    'PRIVACY_001': ['sensitive_data'], # PIA / DPIA
}

# Labels shown to Ollama so it understands the business context
_SCOPE_LABELS = {
    'self_hosted_infra': 'manages own servers/databases/network',
    'cloud_managed_infra': 'runs workloads on IaaS (AWS/Azure/GCP)',
    'custom_software': 'builds its own software / has a dev team',
    'sensitive_data': 'handles sensitive data (PII, payment, health, or financial records)',
}


# ---------------------------------------------------------------------------
# Existing routes
# ---------------------------------------------------------------------------

@main.route('/')
def index():
    return render_template('index.html')


@main.route('/sw.js')
def service_worker():
    static_dir = os.path.join(os.path.dirname(__file__), 'static')
    response = send_from_directory(static_dir, 'sw.js')
    response.headers['Service-Worker-Allowed'] = '/'
    response.headers['Cache-Control'] = 'no-cache'
    return response


@main.route('/api/models')
def get_models():
    try:
        resp = http.get(f'{OLLAMA}/api/tags', timeout=5)
        models = [m['name'] for m in resp.json().get('models', [])]
        return jsonify(models)
    except Exception as e:
        return jsonify({'error': str(e)}), 502


@main.route('/api/chat', methods=['POST'])
def chat():
    body = request.get_json()
    model = body.get('model', 'llama3:latest')
    prompt = body.get('prompt', '')

    def generate():
        try:
            with http.post(
                f'{OLLAMA}/api/generate',
                json={'model': model, 'prompt': prompt},
                stream=True,
                timeout=120
            ) as resp:
                for line in resp.iter_lines():
                    if line:
                        chunk = json.loads(line)
                        yield f"data: {json.dumps(chunk)}\n\n"
                        if chunk.get('done'):
                            break
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e), 'done': True})}\n\n"

    return Response(
        stream_with_context(generate()),
        content_type='text/event-stream',
        headers={'X-Accel-Buffering': 'no', 'Cache-Control': 'no-cache'}
    )


# ---------------------------------------------------------------------------
# Assessment helpers
# ---------------------------------------------------------------------------

def _is_eligible(question, answers):
    """Return True if this question's conditional_on dependencies are satisfied."""
    cond = question.get('conditional_on')
    if not cond:
        return True
    for dep_id, required_values in cond.items():
        if answers.get(dep_id) not in required_values:
            return False
    return True


def _derive_scopes(answers):
    """
    Derive the set of active business scopes from profile/context answers.
    Always includes 'all'. Adds 'self_hosted_infra', 'cloud_managed_infra',
    and/or 'custom_software' based on industry, IT team, and cloud answers.
    """
    scopes = {'all'}

    industry = answers.get('CTX_001', '')
    it_team = answers.get('CTX_007', '')

    # self_hosted_infra: tech-heavy industries or orgs with in-house IT staff
    if industry in {'saas', 'fintech', 'healthcare', 'manufacturing', 'education'} \
            or it_team in {'it_no_security', 'security_person', 'security_team'}:
        scopes.add('self_hosted_infra')

    # custom_software: software businesses or orgs with dedicated security expertise
    if industry in {'saas', 'fintech'} \
            or it_team in {'security_person', 'security_team'}:
        scopes.add('custom_software')

    # cloud_managed_infra: determined once CLOUD_001 is answered
    cloud_ans = answers.get('CLOUD_001', [])
    iaas = {'aws', 'azure', 'gcp'}
    if isinstance(cloud_ans, list):
        if iaas.intersection(cloud_ans):
            scopes.add('cloud_managed_infra')
    elif cloud_ans in iaas:
        scopes.add('cloud_managed_infra')

    # sensitive_data: business handles PII, payment, health, or financial records
    data_types = answers.get('CTX_004', [])
    sensitive = {'basic_pii', 'payment_data', 'health_data', 'financial_records'}
    if isinstance(data_types, list):
        if sensitive.intersection(data_types):
            scopes.add('sensitive_data')
    elif data_types in sensitive:
        scopes.add('sensitive_data')

    return scopes


def _is_in_scope(question, active_scopes):
    """Return True if the question applies to the current business profile."""
    required = _SCOPE_REQUIREMENTS.get(question['id'])
    if not required:
        return True  # no restriction — universal question
    return any(s in active_scopes for s in required)


def _calculate_scores(answers):
    """
    Weighted score calculation matching the riskEngine.js logic.
    Returns (overall_score, category_scores_dict).
    Multi-select questions use the max points among selected options.
    """
    category_weights = SCORING_MODEL['category_weights']
    buckets = {sec: {'wp': 0.0, 'tw': 0.0} for sec in category_weights}

    for q in QUESTIONS:
        section = q['section']
        if section not in buckets:
            continue
        weight = q.get('weight', 0)
        if weight == 0:
            continue

        answer_val = answers.get(q['id'])
        if not answer_val or answer_val == 'na':
            continue  # unanswered or explicitly not applicable — excluded from denominator

        if isinstance(answer_val, list):
            # multi_select: credit the best option the user has selected
            pts = max(
                (opt.get('points', 0) for opt in q['options'] if opt['value'] in answer_val),
                default=None
            )
        else:
            opt = next((o for o in q['options'] if o['value'] == answer_val), None)
            pts = opt.get('points', 0) if opt else None

        if pts is None:
            continue

        buckets[section]['wp'] += (pts / 100.0) * weight
        buckets[section]['tw'] += weight

    category_scores = {}
    for section, w in category_weights.items():
        data = buckets.get(section, {'wp': 0.0, 'tw': 0.0})
        score = round((data['wp'] / data['tw']) * 100, 1) if data['tw'] > 0 else None
        category_scores[section] = {'score': score, 'weight': w}

    # Weighted overall across sections that have data
    ws, tw = 0.0, 0.0
    for section, d in category_scores.items():
        if d['score'] is not None and d['weight'] > 0:
            ws += d['score'] * d['weight']
            tw += d['weight']

    overall = round(ws / tw, 1) if tw > 0 else 0.0
    return overall, category_scores


def _identify_gaps(answers):
    """Return (critical_gaps, high_gaps) — top 5 each, sorted by weight descending."""
    critical, high = [], []
    for q in QUESTIONS:
        answer_val = answers.get(q['id'])
        if not answer_val or isinstance(answer_val, list) or answer_val == 'na':
            continue  # N/A is not a finding
        weight = q.get('weight', 0)
        opt = next((o for o in q['options'] if o['value'] == answer_val), None)
        if not opt:
            continue
        pts = opt.get('points', 0)
        entry = {
            'id': q['id'],
            'section': q['section'],
            'text': q['text'],
            'answer': opt['label'],
            'weight': weight,
            'breach_data': opt.get('breach_data', '')
        }
        if pts == 0 and weight >= 50:
            critical.append(entry)
        elif pts < 30 and weight >= 40:
            high.append(entry)

    critical.sort(key=lambda x: -x['weight'])
    high.sort(key=lambda x: -x['weight'])
    return critical[:5], high[:5]


def _get_eligible_unanswered(answers):
    """Return questions that are unanswered, whose conditions are met, and in scope for this business."""
    answered_ids = set(answers.keys())
    active_scopes = _derive_scopes(answers)
    return [
        q for q in QUESTIONS
        if q['id'] not in answered_ids
        and _is_eligible(q, answers)
        and _is_in_scope(q, active_scopes)
    ]


def _assessment_count(answers):
    """Number of questions the user has actually answered in the assessment UI (excludes profile-seeded IDs)."""
    return sum(1 for qid in answers if qid not in _SEEDED_IDS)


def _is_ready_for_report(answers):
    """
    True once the user has answered MAX_ASSESSMENT_QUESTIONS questions in the UI,
    OR all eligible scoped questions are exhausted.
    Hard cap enforced here so Ollama cannot push the assessment beyond 20 questions.
    """
    return _assessment_count(answers) >= MAX_ASSESSMENT_QUESTIONS


def _fallback_question(eligible):
    """Pick highest-weight eligible question deterministically."""
    scored = [q for q in eligible if q.get('weight', 0) > 0]
    pool = scored if scored else eligible
    return max(pool, key=lambda q: q.get('weight', 0))


def _build_next_question_prompt(answers, eligible):
    a_count = _assessment_count(answers)
    remaining_slots = MAX_ASSESSMENT_QUESTIONS - a_count
    active_scopes = _derive_scopes(answers)

    # Describe the business profile so Ollama understands context
    scope_desc = ', '.join(_SCOPE_LABELS[s] for s in sorted(active_scopes) if s in _SCOPE_LABELS)
    profile_line = f"Business profile: {scope_desc}" if scope_desc else "Business profile: managed/SaaS platform (no own infrastructure)"

    # Condensed answered summary — skip seeded and N/A answers to keep prompt tight
    answered_lines = []
    for qid, val in answers.items():
        if qid in _SEEDED_IDS or val == 'na':
            continue
        q = QUESTIONS_BY_ID.get(qid)
        if q:
            answered_lines.append(f"  {qid} [{q['section']}] = {val}")

    # Cap to top 15 highest-weight eligible questions — shorter prompt = faster Ollama response
    top_eligible = sorted(eligible, key=lambda q: q.get('weight', 0), reverse=True)[:15]
    eligible_lines = [
        f"  {q['id']} [section:{q['section']} weight:{q.get('weight', 0)}] {q['text']}"
        for q in top_eligible
    ]

    return f"""You are an expert cyber insurance risk assessor running an adaptive assessment.

{profile_line}
These questions have already been pre-filtered to only include those relevant to this business type.

Assessment progress: {a_count} of {MAX_ASSESSMENT_QUESTIONS} questions asked. {remaining_slots} slots remaining.

Answers so far:
{chr(10).join(answered_lines) if answered_lines else '  (none yet)'}

Top remaining questions (by insurance impact weight):
{chr(10).join(eligible_lines)}

Selection rules (apply in order):
1. Prefer questions with weight >= 60 — these drive the insurance score most.
2. Prioritise ransomware section (40% of score), then data_protection (30%), then network_security (15%).
3. With only {remaining_slots} questions left, choose the single highest-impact unanswered question.
4. Set ready_for_report to false — the system enforces the cap automatically.

Respond with valid JSON only — no markdown, no explanation:
{{"next_question_id": "<exact ID from the list above>", "ready_for_report": false, "reason": "<one sentence>"}}"""


# ---------------------------------------------------------------------------
# Assessment endpoints
# ---------------------------------------------------------------------------

@main.route('/api/assessment/next-question', methods=['POST'])
def next_question():
    """
    Body: { "model": "llama3:latest", "answers": { "RAN_001": "3_2_1", ... } }
    Returns the next question object from questions.json, chosen by Ollama.
    Falls back to deterministic highest-weight selection if Ollama fails.
    """
    body = request.get_json()
    model = body.get('model', 'llama3:latest')
    answers = body.get('answers', {})

    a_count = _assessment_count(answers)

    # Hard cap — stop immediately once MAX_ASSESSMENT_QUESTIONS are done
    if a_count >= MAX_ASSESSMENT_QUESTIONS:
        return jsonify({
            'ready_for_report': True,
            'question': None,
            'assessment_num': a_count,
            'max_questions': MAX_ASSESSMENT_QUESTIONS,
        })

    eligible = _get_eligible_unanswered(answers)

    if not eligible:
        return jsonify({
            'ready_for_report': True,
            'question': None,
            'assessment_num': a_count,
            'max_questions': MAX_ASSESSMENT_QUESTIONS,
        })

    prompt = _build_next_question_prompt(answers, eligible)

    question_obj = None
    try:
        resp = http.post(
            f'{OLLAMA}/api/generate',
            json={
                'model': model,
                'prompt': prompt,
                'format': 'json',
                'stream': False,
                'options': {'temperature': 0.1}
            },
            timeout=60
        )
        resp.raise_for_status()
        raw = resp.json().get('response', '{}')
        decision = json.loads(raw)
        qid = decision.get('next_question_id', '')
        question_obj = QUESTIONS_BY_ID.get(qid)
        answered_ids = set(answers.keys())
        if not question_obj or qid in answered_ids:
            question_obj = _fallback_question(eligible)
    except Exception:
        question_obj = _fallback_question(eligible)

    return jsonify({
        'question': question_obj,
        'ready_for_report': False,
        'assessment_num': a_count + 1,   # 1-based: "Question N of 20"
        'max_questions': MAX_ASSESSMENT_QUESTIONS,
    })


@main.route('/api/upload', methods=['POST'])
def upload_files():
    """Accepts multipart/form-data with key 'files'. Saves to app/static/uploads/."""
    import uuid
    upload_dir = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
    os.makedirs(upload_dir, exist_ok=True)

    ALLOWED_EXT = {'.pdf', '.doc', '.docx', '.png', '.jpg', '.jpeg', '.txt', '.csv', '.xlsx'}
    uploaded = []
    for f in request.files.getlist('files'):
        if not f or not f.filename:
            continue
        ext = os.path.splitext(f.filename)[1].lower()
        if ext not in ALLOWED_EXT:
            continue
        stored = str(uuid.uuid4()) + ext
        f.save(os.path.join(upload_dir, stored))
        uploaded.append({'original': f.filename, 'stored': stored})

    return jsonify({'uploaded': uploaded})


@main.route('/api/lead/capture', methods=['POST'])
def capture_lead():
    """
    Body: { "name", "email", "phone", "company", "score", "risk_band" }
    Sends a thank-you email (if SMTP is configured) and returns { success: true }.
    """
    body = request.get_json()
    email = (body.get('email') or '').strip()
    if not email:
        return jsonify({'error': 'Email required'}), 400

    name = (body.get('name') or 'there').strip()
    company = (body.get('company') or '').strip()
    score = body.get('score', 0)
    risk_band = body.get('risk_band', '')

    _send_thank_you_email(email, name, company, score, risk_band)
    return jsonify({'success': True})


def _send_thank_you_email(to_email, name, company, score, risk_band):
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    smtp_host = os.environ.get('MAIL_HOST', '')
    smtp_port = int(os.environ.get('MAIL_PORT', '587'))
    smtp_user = os.environ.get('MAIL_USER', '')
    smtp_pass = os.environ.get('MAIL_PASS', '')
    from_addr = os.environ.get('MAIL_FROM', 'noreply@cyberpath.io')

    subject = f"Your CyberPath Risk Assessment — {risk_band}"
    html_body = f"""
<html><body style="font-family:-apple-system,sans-serif;max-width:600px;margin:0 auto;padding:40px 20px;color:#1c1c1e">
  <div style="text-align:center;margin-bottom:32px">
    <div style="background:#000;display:inline-block;padding:12px 20px;border-radius:12px">
      <span style="color:#fff;font-weight:700;font-size:18px">CyberPath</span>
    </div>
  </div>
  <h1 style="font-size:28px;font-weight:700;margin-bottom:16px">Thank you, {name}!</h1>
  <p style="font-size:17px;color:#3a3a3c;line-height:1.6;margin-bottom:24px">
    We've received your cyber risk assessment for <strong>{company}</strong>.
    Your risk score is <strong>{score}/100</strong> — <strong>{risk_band}</strong>.
  </p>
  <p style="font-size:17px;color:#3a3a3c;line-height:1.6;margin-bottom:24px">
    Our team of cyber insurance specialists will review your assessment and reach out shortly
    to discuss how we can help you reduce your premiums and strengthen your security posture.
  </p>
  <div style="background:#f5f5f7;border-radius:12px;padding:24px;margin-bottom:24px">
    <h3 style="margin:0 0 8px;font-size:13px;color:#86868b;text-transform:uppercase;letter-spacing:.05em">WHAT HAPPENS NEXT</h3>
    <ul style="margin:0;padding-left:20px;font-size:15px;color:#3a3a3c;line-height:1.9">
      <li>A senior consultant will review your full assessment</li>
      <li>We'll identify the top 3 fixes for maximum premium reduction</li>
      <li>You'll receive a personalised remediation roadmap within 48 hours</li>
    </ul>
  </div>
  <p style="font-size:14px;color:#86868b">
    Questions? Reply to this email or call us directly.<br><br>
    — The CyberPath Belfast Team
  </p>
</body></html>"""

    if not smtp_host or not smtp_user:
        print(f"[EMAIL] Would send to {to_email}: {subject}")
        return

    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = from_addr
        msg['To'] = to_email
        msg.attach(MIMEText(html_body, 'html'))
        with smtplib.SMTP(smtp_host, smtp_port) as srv:
            srv.starttls()
            srv.login(smtp_user, smtp_pass)
            srv.sendmail(from_addr, to_email, msg.as_string())
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")


@main.route('/api/assessment/report', methods=['POST'])
def generate_report():
    """
    Body: { "model": "llama3:latest", "answers": {...}, "context": { "industry": "saas", ... } }
    Returns deterministic scores + Ollama-generated narrative.
    """
    try:
        body = request.get_json(force=True) or {}
    except Exception:
        body = {}
    model = body.get('model', 'llama3:latest')
    answers = body.get('answers', {})
    context = body.get('context', {})
    try:
        return _generate_report_inner(model, answers, context)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def _generate_report_inner(model, answers, context):

    overall_score, category_scores = _calculate_scores(answers)
    critical_gaps, high_gaps = _identify_gaps(answers)

    # Map score to risk band
    bands = SCORING_MODEL['risk_bands']
    if overall_score >= 85:
        band = bands['low_risk']
    elif overall_score >= 70:
        band = bands['medium_risk']
    elif overall_score >= 50:
        band = bands['medium_high_risk']
    else:
        band = bands['high_risk']

    # Build compact prompt for Ollama narrative
    cat_lines = '\n'.join(
        f"  {sec}: {d['score']}/100" if d['score'] is not None else f"  {sec}: not assessed"
        for sec, d in category_scores.items()
        if d['weight'] > 0
    )
    gap_lines = '\n'.join(
        f"  [CRITICAL] {g['text']} — current state: \"{g['answer']}\""
        + (f" ({g['breach_data']})" if g['breach_data'] else '')
        for g in critical_gaps
    ) + ('\n' if critical_gaps and high_gaps else '') + '\n'.join(
        f"  [HIGH] {g['text']} — current state: \"{g['answer']}\""
        for g in high_gaps
    )

    narrative_prompt = f"""You are a senior cyber insurance risk consultant preparing a concise report for a Belfast SME.

Company:
  Industry: {context.get('industry', 'unknown')}
  Employees: {context.get('companySize', 'unknown')}
  Revenue: {context.get('revenue', 'unknown')}
  Remote workforce: {context.get('remotePercentage', 'unknown')}

Assessment results:
  Overall risk score: {overall_score}/100
  Risk band: {band['label']}
  Estimated premium adjustment: {band['premium_adjustment']}

Category breakdown:
{cat_lines}

Security gaps identified:
{gap_lines if gap_lines.strip() else '  No critical or high gaps found.'}

Write a professional risk report with exactly these four sections:

## Executive Summary
(2-3 sentences: overall posture, biggest risk, headline recommendation)

## Key Risk Findings
(bullet per critical/high gap: what it is, why it matters, specific fix)

## Recommended Actions
(numbered, prioritised, concrete — e.g. "Deploy MFA on all accounts within 30 days")

## Insurance Premium Outlook
(what the score means for renewal, which gaps to fix first for maximum premium reduction)

Be direct and specific. Under 400 words total. No marketing language."""

    narrative = ''
    try:
        resp = http.post(
            f'{OLLAMA}/api/generate',
            json={
                'model': model,
                'prompt': narrative_prompt,
                'stream': False,
                'options': {'temperature': 0.3}
            },
            timeout=180
        )
        resp.raise_for_status()
        narrative = resp.json().get('response', '')
    except Exception as e:
        narrative = f'[Narrative generation failed: {e}]'

    return jsonify({
        'overall_score': overall_score,
        'risk_band': band,
        'category_scores': category_scores,
        'critical_gaps': critical_gaps,
        'high_gaps': high_gaps,
        'narrative': narrative,
        'answers_count': len(answers)
    })
