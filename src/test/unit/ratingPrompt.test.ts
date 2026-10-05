import * as assert from "assert";
import {
  applyAnswer,
  INITIAL_RATING_PROMPT_STATE,
  isMicrosoftVsCode,
  MAX_PROMPTS,
  RatingPromptSession,
  RatingPromptState,
  recordUse,
  reviewUrl,
  shouldPrompt,
} from "../../utils/ratingPrompt";

const START = new Date(2026, 0, 1, 10, 0, 0);
const LATER_SESSION: RatingPromptSession = { isFirstSession: false, promptedThisSession: false };

function daysAfter(days: number, hours = 0): Date {
  const date = new Date(START);
  date.setDate(date.getDate() + days);
  date.setHours(date.getHours() + hours);
  return date;
}

function stateWithUseDays(days: readonly number[]): RatingPromptState {
  return days.reduce((state, day) => recordUse(state, daysAfter(day)), INITIAL_RATING_PROMPT_STATE);
}

const ELIGIBLE = stateWithUseDays([0, 1, 2, 3, 4]);

suite("ratingPrompt — recordUse", () => {
  test("records the first use time and counts the first day", () => {
    const state = recordUse(INITIAL_RATING_PROMPT_STATE, START);
    assert.strictEqual(state.firstUseAt, START.getTime());
    assert.strictEqual(state.useDays, 1);
  });

  test("counts each calendar day once", () => {
    const sameDay = recordUse(recordUse(INITIAL_RATING_PROMPT_STATE, START), daysAfter(0, 5));
    assert.strictEqual(sameDay.useDays, 1);
    assert.strictEqual(recordUse(sameDay, daysAfter(1)).useDays, 2);
  });

  test("keeps the original first use time", () => {
    assert.strictEqual(stateWithUseDays([0, 3]).firstUseAt, START.getTime());
  });
});

suite("ratingPrompt — shouldPrompt", () => {
  test("prompts after 5 use days and 14 days since first use", () => {
    assert.strictEqual(shouldPrompt(ELIGIBLE, LATER_SESSION, daysAfter(14)), true);
  });

  test("waits for 14 days since first use", () => {
    assert.strictEqual(shouldPrompt(ELIGIBLE, LATER_SESSION, daysAfter(13)), false);
  });

  test("waits for 5 distinct use days", () => {
    assert.strictEqual(shouldPrompt(stateWithUseDays([0, 1, 2, 3]), LATER_SESSION, daysAfter(30)), false);
  });

  test("never prompts without any recorded use", () => {
    assert.strictEqual(shouldPrompt(INITIAL_RATING_PROMPT_STATE, LATER_SESSION, daysAfter(30)), false);
  });

  test("never prompts in the first session", () => {
    const session = { isFirstSession: true, promptedThisSession: false };
    assert.strictEqual(shouldPrompt(ELIGIBLE, session, daysAfter(14)), false);
  });

  test("prompts at most once per session", () => {
    const session = { isFirstSession: false, promptedThisSession: true };
    assert.strictEqual(shouldPrompt(ELIGIBLE, session, daysAfter(14)), false);
  });

  test("postpones for 30 days after \"Later\"", () => {
    const snoozed = applyAnswer(ELIGIBLE, "later", daysAfter(14));
    assert.strictEqual(shouldPrompt(snoozed, LATER_SESSION, daysAfter(43)), false);
    assert.strictEqual(shouldPrompt(snoozed, LATER_SESSION, daysAfter(44)), true);
  });

  test("treats a dismissed notification like \"Later\"", () => {
    const dismissed = applyAnswer(ELIGIBLE, undefined, daysAfter(14));
    assert.strictEqual(shouldPrompt(dismissed, LATER_SESSION, daysAfter(20)), false);
    assert.strictEqual(shouldPrompt(dismissed, LATER_SESSION, daysAfter(44)), true);
  });

  for (const answer of ["rate", "never"] as const) {
    test(`stops permanently after "${answer}"`, () => {
      const answered = applyAnswer(ELIGIBLE, answer, daysAfter(14));
      assert.strictEqual(shouldPrompt(answered, LATER_SESSION, daysAfter(400)), false);
    });
  }

  test(`shows the prompt at most ${MAX_PROMPTS} times`, () => {
    const once = applyAnswer(ELIGIBLE, "later", daysAfter(14));
    const twice = applyAnswer(once, "later", daysAfter(44));
    assert.strictEqual(twice.promptCount, 2);
    assert.strictEqual(shouldPrompt(twice, LATER_SESSION, daysAfter(400)), false);
  });
});

suite("ratingPrompt — reviewUrl", () => {
  test("links to the Marketplace review section", () => {
    assert.strictEqual(
      reviewUrl("gmm", "certview"),
      "https://marketplace.visualstudio.com/items?itemName=gmm.certview&ssr=false#review-details"
    );
  });
});

suite("ratingPrompt — isMicrosoftVsCode", () => {
  test("accepts Microsoft VS Code builds", () => {
    assert.strictEqual(isMicrosoftVsCode("Visual Studio Code"), true);
    assert.strictEqual(isMicrosoftVsCode("Visual Studio Code - Insiders"), true);
  });

  test("rejects other VS Code-based editors", () => {
    for (const appName of ["Cursor", "VSCodium", "Windsurf"]) {
      assert.strictEqual(isMicrosoftVsCode(appName), false);
    }
  });
});
