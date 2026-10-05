import * as vscode from "vscode";
import {
  applyAnswer,
  INITIAL_RATING_PROMPT_STATE,
  isMicrosoftVsCode,
  RatingPromptAnswer,
  RatingPromptState,
  recordUse,
  reviewUrl,
  shouldPrompt,
} from "../utils/ratingPrompt";

const STATE_KEY = "certview.ratingPrompt";
const RATE_ACTION = "Rate";
const LATER_ACTION = "Later";
const NEVER_ACTION = "Don't ask again";

const ANSWERS: Readonly<Record<string, RatingPromptAnswer>> = {
  [RATE_ACTION]: "rate",
  [LATER_ACTION]: "later",
  [NEVER_ACTION]: "never",
};

/** Called after a document was parsed and displayed without errors. */
export type SuccessfulViewListener = () => void;

/**
 * Counts days with a successfully displayed document and occasionally asks for a
 * Marketplace rating. Only active in Microsoft VS Code; elsewhere it does nothing.
 */
export function createRatingPrompt(context: vscode.ExtensionContext): SuccessfulViewListener {
  if (!isMicrosoftVsCode(vscode.env.appName)) return () => undefined;

  const isFirstSession = readState(context).firstUseAt === undefined;
  let promptedThisSession = false;

  const onSuccessfulView = async (): Promise<void> => {
    const now = new Date();
    const state = recordUse(readState(context), now);
    await context.globalState.update(STATE_KEY, state);

    if (!isEnabled() || !shouldPrompt(state, { isFirstSession, promptedThisSession }, now)) return;
    promptedThisSession = true;
    await showPrompt(context);
  };

  return () => {
    onSuccessfulView().catch(() => undefined);
  };
}

async function showPrompt(context: vscode.ExtensionContext): Promise<void> {
  const selected = await vscode.window.showInformationMessage(
    "Is CertView useful to you? A Marketplace rating helps other developers find it.",
    RATE_ACTION,
    LATER_ACTION,
    NEVER_ACTION
  );
  const answer = selected === undefined ? undefined : ANSWERS[selected];
  await context.globalState.update(STATE_KEY, applyAnswer(readState(context), answer, new Date()));

  if (answer === "rate") {
    const { publisher, name } = context.extension.packageJSON as { publisher: string; name: string };
    await vscode.env.openExternal(vscode.Uri.parse(reviewUrl(publisher, name)));
  }
}

function readState(context: vscode.ExtensionContext): RatingPromptState {
  return context.globalState.get<RatingPromptState>(STATE_KEY, INITIAL_RATING_PROMPT_STATE);
}

function isEnabled(): boolean {
  return vscode.workspace.getConfiguration("certview").get<boolean>("ratingPrompt.enabled", true);
}
