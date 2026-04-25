from flask import Blueprint, render_template, send_from_directory, request, Response, jsonify, stream_with_context
import os
import json
import requests as http

OLLAMA = 'http://localhost:11434'

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
        if not answer_val:
            continue

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
        if not answer_val or isinstance(answer_val, list):
            continue
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
    """Return questions that are unanswered and whose conditions are met."""
    answered_ids = set(answers.keys())
    return [
        q for q in QUESTIONS
        if q['id'] not in answered_ids and _is_eligible(q, answers)
    ]


def _is_ready_for_report(answers):
    """
    True once at least 20 questions answered and the three core sections have coverage.
    This is checked by the backend so Ollama can't skip questions too early.
    """
    answered_ids = set(answers.keys())
    if len(answered_ids) < 20:
        return False
    covered = {QUESTIONS_BY_ID[qid]['section'] for qid in answered_ids if qid in QUESTIONS_BY_ID}
    return _CORE_SECTIONS.issubset(covered)


def _fallback_question(eligible):
    """Pick highest-weight eligible question deterministically."""
    scored = [q for q in eligible if q.get('weight', 0) > 0]
    pool = scored if scored else eligible
    return max(pool, key=lambda q: q.get('weight', 0))


def _build_next_question_prompt(answers, eligible):
    answered_ids = set(answers.keys())
    can_finish = _is_ready_for_report(answers)

    # Condensed answered summary (section + value only, no full text — keeps prompt tight)
    answered_lines = []
    for qid, val in answers.items():
        q = QUESTIONS_BY_ID.get(qid)
        if q:
            answered_lines.append(f"  {qid} [{q['section']}] = {val}")

    # Eligible question list: id, section, weight, short text
    eligible_lines = [
        f"  {q['id']} [section:{q['section']} weight:{q.get('weight', 0)}] {q['text']}"
        for q in eligible
    ]

    ready_rule = (
        "You MAY set ready_for_report to true if you judge that ransomware, "
        "data_protection and network_security are sufficiently covered."
        if can_finish else
        "Set ready_for_report to false — the minimum threshold has not been reached yet."
    )

    return f"""You are an expert cyber insurance risk assessor running an adaptive assessment.

Answers collected so far ({len(answered_ids)} questions):
{chr(10).join(answered_lines) if answered_lines else '  (none yet)'}

Unanswered eligible questions:
{chr(10).join(eligible_lines)}

Selection rules (apply in order):
1. Prefer questions with weight >= 60 (these drive the insurance score most).
2. Cover the ransomware section first (40% of total score), then data_protection (30%), then network_security (15%).
3. After core sections have several answers, branch into incident_response and compliance.
4. Never repeat an answered question.
5. {ready_rule}

Respond with valid JSON only — no markdown, no explanation:
{{"next_question_id": "<exact ID from the list above>", "ready_for_report": <true or false>, "reason": "<one sentence>"}}"""


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

    eligible = _get_eligible_unanswered(answers)

    if not eligible:
        return jsonify({'ready_for_report': True, 'question': None, 'progress': {'answered': len(answers), 'remaining': 0}})

    prompt = _build_next_question_prompt(answers, eligible)

    decision = None
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
    except Exception:
        pass  # fall through to fallback

    ready_for_report = False
    question_obj = None

    if decision:
        qid = decision.get('next_question_id', '')
        question_obj = QUESTIONS_BY_ID.get(qid)
        # Guard: Ollama may invent an ID or pick an already-answered one
        answered_ids = set(answers.keys())
        if not question_obj or qid in answered_ids:
            question_obj = _fallback_question(eligible)
        # Respect the minimum threshold even if Ollama says ready
        ready_for_report = bool(decision.get('ready_for_report')) and _is_ready_for_report(answers)
    else:
        question_obj = _fallback_question(eligible)

    return jsonify({
        'question': question_obj,
        'ready_for_report': ready_for_report,
        'progress': {
            'answered': len(answers),
            'remaining': len(eligible)
        }
    })


@main.route('/api/assessment/report', methods=['POST'])
def generate_report():
    """
    Body: { "model": "llama3:latest", "answers": {...}, "context": { "industry": "saas", ... } }
    Returns deterministic scores + Ollama-generated narrative.
    """
    body = request.get_json()
    model = body.get('model', 'llama3:latest')
    answers = body.get('answers', {})
    context = body.get('context', {})

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
