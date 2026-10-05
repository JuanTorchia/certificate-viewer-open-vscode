const DAY_MS = 24 * 60 * 60 * 1000;

/** Distinct days with a meaningful use required before asking for a rating. */
export const MIN_USE_DAYS = 5;

/** Days since the first meaningful use required before asking for a rating. */
export const MIN_DAYS_SINCE_FIRST_USE = 14;

/** Days a "Later" answer postpones the next prompt. */
export const SNOOZE_DAYS = 30;

/** Maximum number of times the prompt is ever shown. */
export const MAX_PROMPTS = 2;

/** Persisted rating prompt state, stored in `ExtensionContext.globalState`. */
export interface RatingPromptState {
  readonly firstUseAt?: number;
  readonly lastUseDay?: string;
  readonly useDays: number;
  readonly promptCount: number;
  readonly snoozedUntil?: number;
  readonly done: boolean;
}

/** Per-session facts that are not persisted. */
export interface RatingPromptSession {
  readonly isFirstSession: boolean;
  readonly promptedThisSession: boolean;
}

/** The user's answer to the prompt; `undefined` means the notification was dismissed. */
export type RatingPromptAnswer = "rate" | "later" | "never" | undefined;

/** State before any meaningful use has been recorded. */
export const INITIAL_RATING_PROMPT_STATE: RatingPromptState = {
  useDays: 0,
  promptCount: 0,
  done: false,
};

/**
 * Record a meaningful use, counting each local calendar day once.
 * @param state Current state.
 * @param now Current time.
 * @returns The updated state.
 */
export function recordUse(state: RatingPromptState, now: Date): RatingPromptState {
  const day = localDayKey(now);
  if (state.lastUseDay === day) return state;
  return {
    ...state,
    firstUseAt: state.firstUseAt ?? now.getTime(),
    lastUseDay: day,
    useDays: state.useDays + 1,
  };
}

/**
 * Decide whether the rating prompt should be shown now.
 * @param state Current state.
 * @param session Facts about the current session.
 * @param now Current time.
 * @returns `true` when the prompt should be shown.
 */
export function shouldPrompt(
  state: RatingPromptState,
  session: RatingPromptSession,
  now: Date
): boolean {
  if (session.isFirstSession || session.promptedThisSession) return false;
  if (state.done || state.promptCount >= MAX_PROMPTS) return false;
  if (state.firstUseAt === undefined || state.useDays < MIN_USE_DAYS) return false;
  if (now.getTime() - state.firstUseAt < MIN_DAYS_SINCE_FIRST_USE * DAY_MS) return false;
  return state.snoozedUntil === undefined || now.getTime() >= state.snoozedUntil;
}

/**
 * Apply the user's answer after the prompt was shown.
 * @param state State at the time the prompt was shown.
 * @param answer The selected action, or `undefined` when dismissed.
 * @param now Current time.
 * @returns The updated state.
 */
export function applyAnswer(
  state: RatingPromptState,
  answer: RatingPromptAnswer,
  now: Date
): RatingPromptState {
  const shown = { ...state, promptCount: state.promptCount + 1 };
  if (answer === "rate" || answer === "never") return { ...shown, done: true };
  return { ...shown, snoozedUntil: now.getTime() + SNOOZE_DAYS * DAY_MS };
}

/**
 * Marketplace review URL for an extension.
 * @param publisher Extension publisher ID.
 * @param name Extension name.
 * @returns The URL of the extension's review section.
 */
export function reviewUrl(publisher: string, name: string): string {
  const itemName = encodeURIComponent(`${publisher}.${name}`);
  return `https://marketplace.visualstudio.com/items?itemName=${itemName}&ssr=false#review-details`;
}

/**
 * Whether the host is Microsoft VS Code, whose Marketplace the review link targets.
 * @param appName `vscode.env.appName`.
 * @returns `true` for Microsoft VS Code builds.
 */
export function isMicrosoftVsCode(appName: string): boolean {
  return appName.includes("Visual Studio Code");
}

function localDayKey(date: Date): string {
  return `${date.getFullYear()}-${date.getMonth() + 1}-${date.getDate()}`;
}
