'use strict';

const GROQ_API_KEY = process.env.GROQ_API_KEY || '';
const GROQ_API_URL = 'https://api.groq.com/openai/v1/chat/completions';
const MODEL        = 'llama-3.3-70b-versatile'; // best Groq model for structured output

if (!GROQ_API_KEY) console.warn('[ai-engine] GROQ_API_KEY not set — analysis will fail');

/* ── Main export ─────────────────────────────────────────────────────────── */
async function analyseEssay({ essayText, subject, wordCount, level, onProgress }) {

  if (!GROQ_API_KEY) throw new Error('API key not configured.');

  onProgress && onProgress('thinking', 'Reading your essay…');

  // Truncate to ~12,000 words to stay within Groq context limits
  const trimmed = essayText.slice(0, 48000);

  const systemPrompt = `You are an expert UK university academic marker with 20 years of experience.
You assess essays using the UK degree classification system (1st, 2:1, 2:2, 3rd, Fail).
You provide honest, specific, constructive feedback like a senior tutor would.
You MUST respond with valid JSON only — no markdown, no extra text, just the raw JSON object.`;

  const userPrompt = `Analyse this ${level} level essay${subject ? ' on the subject of ' + subject : ''}.

ESSAY:
"""
${trimmed}
"""

Respond with ONLY this JSON structure (no markdown, no backticks):
{
  "overall_score": <integer 0-100>,
  "grade_predicted": <"1st" | "2:1" | "2:2" | "3rd" | "Fail">,
  "subject_detected": <string — detected subject area>,
  "word_count_assessed": ${wordCount},
  "ai_detection_pct": <integer 0-100 — estimated % of AI-written content>,
  "summary": "<2-3 sentence overall summary of the essay quality>",
  "scores": {
    "argument":  { "score": <0-100>, "feedback": "<specific feedback>" },
    "evidence":  { "score": <0-100>, "feedback": "<specific feedback>" },
    "structure": { "score": <0-100>, "feedback": "<specific feedback>" },
    "style":     { "score": <0-100>, "feedback": "<specific feedback>" },
    "citations": { "score": <0-100>, "feedback": "<specific feedback>" }
  },
  "strengths": ["<strength 1>", "<strength 2>", "<strength 3>"],
  "improvements": ["<improvement 1>", "<improvement 2>", "<improvement 3>"],
  "line_feedback": [
    { "quote": "<exact short quote from essay, max 10 words>", "comment": "<specific comment>", "type": <"positive"|"negative"|"suggestion"> },
    { "quote": "<exact short quote from essay, max 10 words>", "comment": "<specific comment>", "type": <"positive"|"negative"|"suggestion"> },
    { "quote": "<exact short quote from essay, max 10 words>", "comment": "<specific comment>", "type": <"positive"|"negative"|"suggestion"> },
    { "quote": "<exact short quote from essay, max 10 words>", "comment": "<specific comment>", "type": <"positive"|"negative"|"suggestion"> },
    { "quote": "<exact short quote from essay, max 10 words>", "comment": "<specific comment>", "type": <"positive"|"negative"|"suggestion"> }
  ],
  "citation_issues": ["<issue 1 or empty array if none>"],
  "ai_detection_reason": "<brief explanation of AI detection score>"
}`;

  onProgress && onProgress('thinking', 'Analysing argument and structure…');

  let raw;
  try {
    const resp = await fetch(GROQ_API_URL, {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + GROQ_API_KEY,
        'Content-Type':  'application/json'
      },
      body: JSON.stringify({
        model:       MODEL,
        temperature: 0.3,
        max_tokens:  2048,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user',   content: userPrompt   }
        ]
      })
    });

    if (!resp.ok) {
      const errData = await resp.json().catch(() => ({}));
      const msg = errData?.error?.message || ('Groq API error: ' + resp.status);
      // Surface API key errors clearly
      if (resp.status === 401) throw new Error('API key invalid or not set.');
      if (resp.status === 429) throw new Error('AI service rate limit reached. Please try again in a moment.');
      throw new Error(msg);
    }

    const data = await resp.json();
    raw = data?.choices?.[0]?.message?.content || '';
  } catch (err) {
    // Re-throw network / fetch errors with clear message
    if (err.message.includes('API key') || err.message.includes('rate limit')) throw err;
    throw new Error('Could not reach AI service. Please try again.');
  }

  onProgress && onProgress('thinking', 'Generating feedback…');

  // Strip markdown fences if model wraps in ```json ... ```
  const cleaned = raw.replace(/^```json\s*/i, '').replace(/^```\s*/i, '').replace(/```\s*$/i, '').trim();

  let report;
  try {
    report = JSON.parse(cleaned);
  } catch {
    console.error('[ai-engine] JSON parse failed. Raw response:\n', raw.slice(0, 500));
    throw new Error('AI returned an unreadable response. Please try again.');
  }

  // Validate and sanitise all fields so the rest of server.js never gets undefined
  report.overall_score    = clamp(parseInt(report.overall_score)    || 60, 0, 100);
  report.ai_detection_pct = clamp(parseInt(report.ai_detection_pct) || 0,  0, 100);
  report.grade_predicted  = validGrade(report.grade_predicted);
  report.subject_detected = (report.subject_detected || subject || 'General').slice(0, 100);
  report.summary          = (report.summary || '').slice(0, 1000);
  report.strengths        = Array.isArray(report.strengths)    ? report.strengths.slice(0, 5)    : [];
  report.improvements     = Array.isArray(report.improvements) ? report.improvements.slice(0, 5) : [];
  report.line_feedback    = Array.isArray(report.line_feedback) ? report.line_feedback.slice(0, 10) : [];
  report.citation_issues  = Array.isArray(report.citation_issues) ? report.citation_issues : [];
  report.scores           = sanitiseScores(report.scores);
  report.ai_detection_reason = (report.ai_detection_reason || '').slice(0, 500);
  report.word_count_assessed = wordCount;

  onProgress && onProgress('done', 'Report ready!');
  return report;
}

/* ── Helpers ─────────────────────────────────────────────────────────────── */
function clamp(n, min, max) {
  return Math.min(Math.max(isNaN(n) ? min : n, min), max);
}

function validGrade(g) {
  const valid = ['1st', '2:1', '2:2', '3rd', 'Fail'];
  return valid.includes(g) ? g : '2:2';
}

function sanitiseScores(scores) {
  const keys = ['argument', 'evidence', 'structure', 'style', 'citations'];
  const out  = {};
  for (const k of keys) {
    const s = scores?.[k] || {};
    out[k] = {
      score:    clamp(parseInt(s.score) || 60, 0, 100),
      feedback: (s.feedback || 'No feedback provided.').slice(0, 500)
    };
  }
  return out;
}

module.exports = { analyseEssay };
