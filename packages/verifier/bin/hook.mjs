/**
 * A Claude Code PreToolUse hook.
 *
 * Claude Code hands this every tool call before it runs, and honours what it
 * answers: allow, deny, or ask, where ask puts the question to the person at
 * the keyboard. That last one is why this surface is worth having as well as
 * the MCP proxy: the proxy can only refuse, while here an escalation becomes a
 * real prompt someone can say yes to.
 *
 * Two rules shape everything below.
 *
 * It never fails open. A hook that exits non-zero lets the tool proceed, so a
 * missing policy or a broken rule would quietly stop guarding while looking
 * fine. Every failure here is turned into a deny with the reason attached.
 *
 * It only ever restricts. Answering "allow" would bypass Claude Code's own
 * permission prompts, so a policy that said yes would silently approve things
 * the person would otherwise have been asked about. By default an allowed call
 * gets no answer at all and the normal flow continues. Skipping the prompt is
 * opt in.
 */

import { checkAndHold, decide, toolRequest } from "../dist/index.js";

const EVENT = "PreToolUse";

/** Claude Code honours this shape; anything else is treated as plain text. */
function decisionOutput(permissionDecision, reason, extra = {}) {
  return {
    hookSpecificOutput: {
      hookEventName: EVENT,
      permissionDecision,
      ...(reason ? { permissionDecisionReason: reason } : {}),
      ...extra,
    },
  };
}

async function readAll(stream) {
  let text = "";
  for await (const chunk of stream) text += chunk;
  return text;
}

export async function runHook({
  policy,
  authority,
  ledger,
  receipts,
  signReceiptsWith,
  engagementId,
  skipPromptOnAllow = false,
  input = process.stdin,
  output = process.stdout,
} = {}) {
  const say = (value) => {
    if (value) output.write(`${JSON.stringify(value)}\n`);
    return 0;
  };
  // Saying nothing means "no opinion", and Claude Code carries on with its own
  // permission flow. That is the right answer for an allowed call, because the
  // guard is here to narrow what may happen, never to widen it.
  const defer = () => say(undefined);
  const deny = (reason) => say(decisionOutput("deny", reason));
  const ask = (reason) => say(decisionOutput("ask", reason));

  let event;
  try {
    const raw = await readAll(input);
    event = JSON.parse(raw);
  } catch (err) {
    return deny(`The Agent Passport hook could not read the tool call, so it refused it: ${err.message}`);
  }

  try {
    const name = event?.tool_name;
    if (typeof name !== "string" || !name) {
      return deny("The Agent Passport hook received a tool call with no name, so it refused it.");
    }

    const call = { name, args: event.tool_input };
    const mapping = toolRequest(call, policy.tools);

    if (!mapping.ok) {
      const [first] = mapping.errors;
      if (mapping.effect) {
        const reason = `${first.message}${first.hint ? ` ${first.hint}` : ""}`;
        return mapping.effect === "deny" ? deny(reason) : ask(reason);
      }
      if (first.code === "tool.unmatched") {
        const unmatched = policy.unmatched ?? "escalate";
        if (unmatched === "allow") return defer();
        const reason = `No rule in the policy "${policy.id}" covers ${name}.`;
        return unmatched === "deny" ? deny(reason) : ask(`${reason} Approve it yourself, or add a rule.`);
      }
      return deny(`${first.message}${first.hint ? ` ${first.hint}` : ""}`);
    }

    const decision = await decide(authority, mapping.request, { ledger, engagementId });
    const why = decision.reasons.map((r) => r.message).join(" ");

    if (decision.decision === "deny") {
      await checkAndHold(decision, mapping.request, { ledger, receipts, signReceiptsWith, engagementId });
      return deny(`Refused by the policy "${policy.id}": ${why}`);
    }

    // An allowed call is counted here, before it runs, because nothing tells
    // this hook afterwards whether it did. That over-counts a tool that fails
    // and a prompt the person declines, which is the safe direction: counting
    // spending that did not happen only makes the next decision more cautious,
    // while missing spending that did raises the ceiling.
    const gate = await checkAndHold(decision, mapping.request, {
      ledger,
      receipts,
      signReceiptsWith,
      engagementId,
      humanApproved: decision.decision === "escalate",
    });
    if (!gate.ok) {
      return deny(`Refused by the policy "${policy.id}": ${gate.reasons.map((r) => r.message).join(" ")}`);
    }
    await gate.hold.commit();

    if (decision.decision === "escalate") {
      const contact = decision.escalation ? ` The policy names ${decision.escalation.to}.` : "";
      return ask(`${why}${contact}`);
    }
    return skipPromptOnAllow
      ? say(decisionOutput("allow", undefined, { additionalContext: `Allowed by the policy "${policy.id}".` }))
      : defer();
  } catch (err) {
    // Anything unforeseen is a refusal, not a shrug. A guard that throws is a
    // guard that stopped guarding, and nothing would have said so.
    return deny(`The Agent Passport hook failed, so it refused the call: ${err?.message ?? err}`);
  }
}
