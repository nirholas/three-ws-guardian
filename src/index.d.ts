// Type definitions for @three-ws/guardian

export declare class ThreeWsError extends Error {
	name: string;
	code: string;
	status: number | null;
	detail?: string;
	retryAfter?: number;
	body: unknown;
}

export declare class PaymentRequiredError extends ThreeWsError {
	accepts: unknown | null;
}

export declare const DEFAULT_BASE_URL: string;

export type RiskName =
	| 'harm'
	| 'jailbreak'
	| 'violence'
	| 'social_bias'
	| 'profanity'
	| 'sexual_content'
	| 'unethical_behavior'
	| 'harm_engagement'
	| 'groundedness'
	| 'answer_relevance'
	| 'context_relevance'
	| 'function_call';

export type RiskTarget = 'user' | 'assistant' | 'rag';
export type Decision = 'allow' | 'review' | 'block';
export type TurnRole = 'user' | 'assistant' | 'context';

export interface Turn {
	role: TurnRole;
	content: string;
}

/** Probability at/above which a flagged risk blocks (calibrated, 0.55). */
export declare const BLOCK_THRESHOLD: number;

export interface RiskMeta {
	label: string;
	target: RiskTarget;
	definition: string;
}

/** The static Granite Guardian risk taxonomy (keyed by risk name). */
export declare const RISKS: Record<RiskName, RiskMeta>;
export declare const RISK_NAMES: RiskName[];

export interface RiskVerdict {
	risk: RiskName;
	label: string;
	flagged: boolean;
	probability: number;
	confidence: 'high' | 'low' | null;
	estimated: boolean;
}

export interface Reason {
	risk: string;
	label: string;
	probability: number;
}

export interface AuditRecord {
	v: number;
	ts: string;
	model: string;
	inputDigest: string;
	action: { type: string; usd: number } | null;
	decision: Decision;
	flagged: string[];
	reasons: Reason[];
	risks: Array<{ risk: string; label: string; flagged: boolean; probability: number; confidence: string | null }>;
	prev: string;
	hash: string;
}

export interface GuardianResult {
	/** `true` when `decision === 'allow'`. */
	safe: boolean;
	decision: Decision;
	/** Risk names that tripped. */
	flagged: string[];
	/** The blocking risks. */
	reasons: Reason[];
	/** Highest-scoring risk, flagged or not. */
	topRisk: { risk: string; probability: number } | null;
	/** Per-risk verdicts. */
	risks: RiskVerdict[];
	/** Hash-chained audit entry — `record.hash`, `record.prev`. */
	record: AuditRecord | null;
	/** The Granite Guardian model id that scored it. */
	model: string | null;
	/** Server-side assessment time. */
	latencyMs: number | null;
	/** Escape hatch to the raw endpoint JSON. */
	raw: unknown;
}

export interface SendAction {
	type: 'sendSol';
	usd: number;
	to?: string;
}

export interface GovernResult extends GuardianResult {
	/** The active USD ceiling for autonomous sends. */
	cap: number;
	/** Whether `action.usd` exceeded the cap. */
	capExceeded: boolean;
	action: { type: string; usd: number };
}

export interface ModerationResult {
	/** Did a verdict actually come back? */
	checked: boolean;
	/** `true` only on a successful flagged verdict. */
	flagged: boolean;
	/** Named risk categories that flagged. */
	categories: string[];
	model?: string | null;
	latencyMs?: number;
	/** Reason the filter failed open, when applicable. */
	error?: string;
}

export interface CheckOptions {
	/** Which risks to score. Omit for the default showcase panel. */
	risks?: RiskName[];
	/** A prior `record.hash` (64-hex) to chain this verdict onto. */
	prev?: string;
	signal?: AbortSignal;
}

export interface GovernOptions extends CheckOptions {
	action: SendAction;
}

export interface ModerateOptions {
	/** Override the content-side risk panel. */
	risks?: RiskName[];
	signal?: AbortSignal;
}

export interface RiskTaxonomyEntry {
	risk: RiskName;
	label: string;
	target: RiskTarget;
	definition: string;
}

export interface GuardianClientOptions {
	baseUrl?: string;
	fetch?: typeof fetch;
	apiKey?: string;
	headers?: Record<string, string>;
}

export interface GuardianClient {
	check(input: string | Turn[], opts?: CheckOptions): Promise<GuardianResult>;
	govern(input: string | Turn[], opts: GovernOptions): Promise<GovernResult>;
	moderate(input: string | Turn[], opts?: ModerateOptions): Promise<ModerationResult>;
}

export declare function createGuardian(options?: GuardianClientOptions): GuardianClient;
export declare function check(input: string | Turn[], opts?: CheckOptions): Promise<GuardianResult>;
export declare function govern(input: string | Turn[], opts: GovernOptions): Promise<GovernResult>;
export declare function moderate(input: string | Turn[], opts?: ModerateOptions): Promise<ModerationResult>;
/** The static Granite Guardian risk taxonomy this client scores against. */
export declare function risks(): RiskTaxonomyEntry[];
