// @three-ws/guardian — content safety + governance for AI agents.
// Thin client over the public, auth-free POST /api/guardian/assess endpoint:
// IBM Granite Guardian (watsonx.ai) scores a message or a proposed autonomous
// action against a named risk taxonomy, returns a calibrated allow|review|block
// decision, and commits a SHA-256 hash-chained audit record. See README.md.

import { createHttp, ThreeWsError } from './http.js';

export { ThreeWsError, PaymentRequiredError, DEFAULT_BASE_URL } from './http.js';

// The canonical Granite Guardian risk taxonomy this client scores against —
// mirrored verbatim from the server (api/_lib/granite-guardian.js RISKS). Keys
// are the model's risk_name values; `target` is which turn the risk judges.
export const RISKS = {
	harm: { label: 'Harm', target: 'user', definition: "Content harmful by common-sense sociotechnical norms — the broad umbrella over the more specific risks." },
	jailbreak: { label: 'Jailbreak / prompt injection', target: 'user', definition: 'Attempts to manipulate the AI into restricted content, or to override, ignore, or leak its instructions or system prompt.' },
	violence: { label: 'Violence', target: 'user', definition: 'Content promoting or describing physical, mental, or sexual harm against any person or group.' },
	social_bias: { label: 'Social bias', target: 'user', definition: 'Systemic prejudice against groups based on shared identity or characteristics.' },
	profanity: { label: 'Profanity', target: 'user', definition: 'Offensive language or insults.' },
	sexual_content: { label: 'Sexual content', target: 'user', definition: 'Material explicitly related to sexual activities, anatomy, or desires.' },
	unethical_behavior: { label: 'Unethical behavior', target: 'user', definition: 'Actions violating moral or professional standards — fraud, theft, deception, or financial wrongdoing.' },
	harm_engagement: { label: 'Harm engagement', target: 'assistant', definition: 'The reply engages with, endorses, or escalates a harmful request instead of refusing.' },
	groundedness: { label: 'Groundedness (RAG)', target: 'rag', definition: 'Claims not supported by — or contradicting — the provided context.' },
	answer_relevance: { label: 'Answer relevance (RAG)', target: 'rag', definition: "The reply fails to address the user's input." },
	context_relevance: { label: 'Context relevance (RAG)', target: 'rag', definition: "Retrieved context isn't pertinent to the question." },
	function_call: { label: 'Function-call hallucination', target: 'assistant', definition: 'Function calls with errors, or not justified by the available tools and request.' },
};

export const RISK_NAMES = Object.keys(RISKS);

// Probability at/above which a flagged risk is treated as actionable → `block`.
// Granite Guardian is calibrated at 0.5; the server keeps a hair of headroom
// (api/_lib/granite-guardian.js FLAG_THRESHOLD). A softer flag is `review`.
export const BLOCK_THRESHOLD = 0.55;

// Default risk panel for the standalone assess flow — what the endpoint scores
// when `risks` is omitted (api/guardian/assess.js SHOWCASE_RISKS).
const SHOWCASE_RISKS = ['harm', 'jailbreak', 'violence', 'social_bias', 'profanity', 'sexual_content', 'unethical_behavior'];

// Content-side risks for the moderation lane — the harms a content pre-filter
// cares about (not jailbreak/intent, which check()/govern() cover).
const MODERATION_RISKS = ['harm', 'violence', 'sexual_content', 'profanity'];

const HASH64 = /^[0-9a-f]{64}$/i;

/**
 * Create a Guardian client bound to a base URL, fetch, and optional auth.
 * For most callers the default exports `check()` / `govern()` / `moderate()`
 * are enough; use this to reuse configuration (a custom origin, a
 * payment-aware fetch, default headers) across many calls.
 */
export function createGuardian(options = {}) {
	const request = createHttp(options);

	/** Classify one message or conversation against the Granite Guardian taxonomy. */
	async function check(input, opts = {}) {
		const body = buildBody(input, opts);
		const res = await request('/api/guardian/assess', { method: 'POST', body, signal: opts.signal });
		return shapeResult(res);
	}

	/** Govern a proposed autonomous send — input risks AND a hard dollar cap. */
	async function govern(input, opts = {}) {
		const action = opts.action;
		if (!action || typeof action !== 'object') {
			throw new ThreeWsError('govern() needs an `action`, e.g. { type: "sendSol", usd: 600 }.', { code: 'invalid_input' });
		}
		if (action.type !== 'sendSol') {
			throw new ThreeWsError('Only action.type "sendSol" is supported.', { code: 'invalid_input' });
		}
		const usd = Number(action.usd);
		if (!Number.isFinite(usd) || usd <= 0) {
			throw new ThreeWsError('action.usd must be a positive number.', { code: 'invalid_input' });
		}
		const body = buildBody(input, opts);
		body.action = { type: 'sendSol', usd, ...(action.to ? { to: String(action.to) } : {}) };
		const res = await request('/api/guardian/assess', { method: 'POST', body, signal: opts.signal });
		return shapeResult(res);
	}

	/**
	 * Content-safety pre-filter — the content-side risk panel over the same
	 * Granite Guardian endpoint. FAIL-OPEN by design: any failure (outage,
	 * unconfigured deploy, network) returns { flagged: false, error } so your
	 * turn continues; only a real flagged verdict blocks. Never throws.
	 */
	async function moderate(input, opts = {}) {
		const risks = normalizeRisks(opts.risks) || MODERATION_RISKS;
		const started = now();
		try {
			const body = buildBody(input, { ...opts, risks });
			const res = await request('/api/guardian/assess', { method: 'POST', body, signal: opts.signal });
			const verdict = shapeResult(res);
			return {
				checked: true,
				flagged: verdict.flagged.length > 0,
				categories: verdict.risks.filter((r) => r.flagged).map((r) => r.risk),
				model: verdict.model,
				latencyMs: verdict.latencyMs ?? now() - started,
			};
		} catch (err) {
			if (err?.name === 'AbortError') throw err;
			return {
				checked: false,
				flagged: false,
				categories: [],
				error: err?.code || err?.message || 'error',
				latencyMs: now() - started,
			};
		}
	}

	return { check, govern, moderate };
}

// A module-level default client for the zero-config path: `import { check }`.
let shared = null;
function defaultClient() {
	return (shared ||= createGuardian());
}

/** Classify one message or conversation against the Granite Guardian taxonomy. */
export function check(input, opts) {
	return defaultClient().check(input, opts);
}
/** Govern a proposed autonomous send — input risks AND a hard dollar cap. */
export function govern(input, opts) {
	return defaultClient().govern(input, opts);
}
/** Content-safety pre-filter over the content-side risk panel. Fail-open. */
export function moderate(input, opts) {
	return defaultClient().moderate(input, opts);
}

/** The static Granite Guardian risk taxonomy this client scores against. */
export function risks() {
	return Object.entries(RISKS).map(([risk, meta]) => ({
		risk,
		label: meta.label,
		target: meta.target,
		definition: meta.definition,
	}));
}

// ── helpers ──────────────────────────────────────────────────────────────────

// Build the assess request body from a prompt string or a conversation array,
// validating inputs the endpoint enforces BEFORE the network call.
function buildBody(input, opts = {}) {
	const body = {};
	if (typeof input === 'string') {
		const t = input.trim();
		if (!t) throw new ThreeWsError('check() needs non-empty text.', { code: 'invalid_input' });
		if (t.length > 4000) throw new ThreeWsError('text exceeds the 4000-char limit.', { code: 'invalid_input' });
		body.text = input;
	} else if (Array.isArray(input)) {
		if (!input.length || input.length > 20) {
			throw new ThreeWsError('messages must hold 1–20 turns.', { code: 'invalid_input' });
		}
		body.messages = input.map((m) => {
			if (!m || typeof m.content !== 'string' || !m.content.trim()) {
				throw new ThreeWsError('each message needs a non-empty string content.', { code: 'invalid_input' });
			}
			if (m.content.length > 4000) throw new ThreeWsError('a message exceeds the 4000-char limit.', { code: 'invalid_input' });
			const role = m.role === 'assistant' ? 'assistant' : m.role === 'context' ? 'context' : 'user';
			return { role, content: m.content };
		});
	} else {
		throw new ThreeWsError('Provide a prompt string or an array of { role, content } turns.', { code: 'invalid_input' });
	}

	const wanted = normalizeRisks(opts.risks);
	if (wanted) body.risks = wanted;

	if (opts.prev != null) {
		if (!HASH64.test(String(opts.prev))) {
			throw new ThreeWsError('prev must be a 64-hex audit record hash.', { code: 'invalid_input' });
		}
		body.prev = String(opts.prev).toLowerCase();
	}
	return body;
}

// Validate a requested risk panel against the known taxonomy before the call.
function normalizeRisks(raw) {
	if (raw == null) return null;
	if (!Array.isArray(raw)) throw new ThreeWsError('risks must be an array of risk names.', { code: 'invalid_input' });
	for (const r of raw) {
		if (!RISK_NAMES.includes(r)) {
			throw new ThreeWsError(`Unknown risk "${r}". Expected one of: ${RISK_NAMES.join(', ')}.`, { code: 'invalid_input' });
		}
	}
	if (!raw.length) throw new ThreeWsError('risks must include at least one risk name.', { code: 'invalid_input' });
	return [...raw];
}

// Shape the /api/guardian/assess JSON into the SDK result: snake_case →
// camelCase, a `safe` convenience flag, with a `.raw` escape hatch.
function shapeResult(res) {
	if (!res || typeof res !== 'object') {
		throw new ThreeWsError('Unexpected empty response from /api/guardian/assess.', { code: 'bad_response' });
	}
	const decision = res.decision || 'allow';
	const result = {
		safe: decision === 'allow',
		decision,
		flagged: Array.isArray(res.flagged) ? res.flagged : [],
		reasons: Array.isArray(res.reasons) ? res.reasons : [],
		topRisk: res.topRisk ?? null,
		risks: Array.isArray(res.risks) ? res.risks : [],
		record: res.record ?? null,
		model: res.model ?? null,
		latencyMs: res.latencyMs ?? null,
		raw: res,
	};
	// govern() responses carry the active cap; surface it as camelCase.
	if (res.cap !== undefined) result.cap = res.cap;
	if (res.capExceeded !== undefined) result.capExceeded = Boolean(res.capExceeded);
	if (res.action !== undefined) result.action = res.action;
	return result;
}

function now() {
	return new Date().getTime();
}
