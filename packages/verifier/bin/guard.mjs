/**
 * A guard that sits between an AI agent and the MCP server it is using.
 *
 *   agent [stdio] <-> guard <-> upstream MCP server [stdio]
 *
 * Every tools/call is decided against a local policy before it is forwarded.
 * A call that fails the policy never reaches the upstream server at all, which
 * is the difference between a limit and a suggestion: the agent cannot route
 * around it, because the tools are only reachable through here.
 *
 * Everything else is passed through untouched, so the guard is invisible to
 * both sides apart from the refusals and a note on each governed tool.
 */

import { spawn } from "node:child_process";
import { createInterface } from "node:readline";

import {
  buildApprovalRequest,
  checkAndHold,
  checkApproval,
  decide,
  describeRule,
  ruleFor,
  toolRequest,
} from "../dist/index.js";

/** A short line describing the money limits, for the note on each tool. */
function limitsSummary(authority) {
  const ceilings = authority.ceilings ?? [];
  if (!ceilings.length) return undefined;
  const period = (w) => (w === "engagement" ? "per engagement" : w === "total" ? "in total" : `per ${w}`);
  return `Limits: ${ceilings.map((c) => `${c.amount.toLocaleString("en-US")} ${c.currency} ${period(c.window)}`).join(", ")}.`;
}

export async function runGuard({
  policy,
  authority,
  ledger,
  receipts,
  signReceiptsWith,
  engagementId,
  approvals,
  command,
  commandArgs = [],
  input = process.stdin,
  output = process.stdout,
  errorOutput = process.stderr,
  spawnFn = spawn,
} = {}) {
  const upstream = spawnFn(command, commandArgs, { stdio: ["pipe", "pipe", "pipe"] });
  const send = (message) => output.write(`${JSON.stringify(message)}\n`);
  const toUpstream = (message) => upstream.stdin.write(`${JSON.stringify(message)}\n`);
  const log = (text) => errorOutput.write(`[agent-passport guard] ${text}\n`);

  /** Calls we let through and still owe a settlement for. */
  const inFlight = new Map();
  /** tools/list requests, so their answers can be annotated on the way back. */
  const listRequests = new Set();
  const unmatched = policy.unmatched ?? "escalate";
  const limits = limitsSummary(authority);

  const refuse = (id, lines) =>
    send({
      jsonrpc: "2.0",
      id,
      result: { content: [{ type: "text", text: lines.filter(Boolean).join("\n") }], isError: true },
    });

  async function guardCall(message) {
    const name = message.params?.name;
    const args = message.params?.arguments;
    const mapping = toolRequest({ name, args }, policy.tools);

    if (!mapping.ok) {
      const [first] = mapping.errors;
      if (mapping.effect) {
        // The proxy has nobody to ask, so a rule wanting a person is a refusal
        // here, with the reason, rather than a prompt.
        log(`${name}: ${first.code}`);
        return refuse(message.id, [
          `Refused by the local policy: ${name}`,
          first.message,
          first.hint,
          mapping.effect === "ask" ? "A person has to approve this one." : undefined,
        ]);
      }
      if (first.code === "tool.unmatched") {
        if (unmatched === "allow") return toUpstream(message);
        log(`${name}: no rule covers this tool, and unmatched is "${unmatched}"`);
        return refuse(message.id, [
          `Refused: no rule in the local policy covers "${name}".`,
          unmatched === "escalate"
            ? `A person has to decide whether this tool may be used${authority.humanInLoop ? ` (${authority.humanInLoop.escalation})` : ""}.`
            : "This policy refuses tools it does not name.",
        ]);
      }
      log(`${name}: ${first.code}`);
      return refuse(message.id, [`Refused: ${first.message}`, first.hint]);
    }

    const decision = await decide(authority, mapping.request, { ledger, engagementId });

    // A proxy has nobody to ask, so an escalation is answered out of band: it
    // leaves a request behind, somebody says yes, and the same call comes back.
    // The decision digest is what ties the two together, so an approval buys
    // exactly the call it was given and nothing else.
    let approved;
    if (decision.decision === "escalate" && approvals) {
      const found = await checkApproval(approvals.state(), decision.binding.digest, {
        approvers: policy.approvers,
      });
      if (found.ok) {
        approved = found.answer;
      } else {
        const waiting = [...approvals.state().values()].find(
          (s) => s.request.digest === decision.binding.digest && s.status === "pending",
        );
        const pending = waiting?.request ?? buildApprovalRequest(decision, mapping.request);
        if (!waiting) approvals.ask(pending);
        log(`${name}: waiting for an answer, request ${pending.id}`);
        return refuse(message.id, [
          `Waiting for a person: ${name}`,
          ...decision.reasons.map((r) => r.message),
          ...found.errors.filter((e) => e.code !== "approval.none").map((e) => e.message),
          `Request ${pending.id} is recorded. Someone can answer it with:`,
          `  agent-passport approve ${pending.id} --approvals ${approvals.path}`,
          "This call was not sent to the server.",
        ]);
      }
    }

    const gate = await checkAndHold(decision, mapping.request, {
      ledger,
      receipts,
      signReceiptsWith,
      engagementId,
      humanApproved: Boolean(approved),
    });

    if (!gate.ok) {
      const why = decision.reasons.map((r) => `${r.code}: ${r.message}${r.hint ? ` (${r.hint})` : ""}`);
      log(`${name}: ${decision.decision}, ${decision.reasons.map((r) => r.code).join(", ")}`);
      return refuse(message.id, [
        `Refused by the local policy: ${name}`,
        ...why,
        decision.escalation
          ? `A person must confirm this: ${decision.escalation.to}, within ${decision.escalation.slaHours}h.`
          : undefined,
        "This call was not sent to the server.",
      ]);
    }

    inFlight.set(message.id, { hold: gate.hold, name, approved, digest: decision.binding.digest });
    toUpstream(message);
  }

  /** Tell the model which tools are governed, and by what. */
  function annotate(result) {
    if (!Array.isArray(result?.tools)) return result;
    return {
      ...result,
      tools: result.tools.map((tool) => {
        const rule = ruleFor(policy.tools, tool.name);
        const note = rule
          ? describeRule(rule, limits)
          : unmatched === "allow"
            ? undefined
            : `Not covered by the local policy, so calling it will be refused (unmatched: ${unmatched}).`;
        return note ? { ...tool, description: [tool.description, note].filter(Boolean).join(" ") } : tool;
      }),
    };
  }

  const fromClient = createInterface({ input, crlfDelay: Infinity });
  const fromUpstream = createInterface({ input: upstream.stdout, crlfDelay: Infinity });
  const upstreamErrors = createInterface({ input: upstream.stderr, crlfDelay: Infinity });
  upstreamErrors.on("line", (line) => errorOutput.write(`${line}\n`));

  const clientDone = (async () => {
    for await (const line of fromClient) {
      if (!line.trim()) continue;
      let message;
      try {
        message = JSON.parse(line);
      } catch {
        send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
        continue;
      }
      if (message?.method === "tools/call" && message.id !== undefined) {
        try {
          await guardCall(message);
        } catch (err) {
          // One call the guard could not work out must not take the guard down
          // with it, and must not be forwarded either. Refuse it and carry on.
          log(`${message.params?.name}: ${err?.message ?? err}`);
          refuse(message.id, [
            `Refused: the guard could not decide this call.`,
            String(err?.message ?? err),
            "This call was not sent to the server.",
          ]);
        }
      } else {
        if (message?.method === "tools/list" && message.id !== undefined) listRequests.add(message.id);
        toUpstream(message);
      }
    }
    upstream.stdin.end();
  })();

  const upstreamDone = (async () => {
    for await (const line of fromUpstream) {
      if (!line.trim()) continue;
      let message;
      try {
        message = JSON.parse(line);
      } catch {
        errorOutput.write(`${line}\n`);
        continue;
      }
      const owed = message?.id !== undefined ? inFlight.get(message.id) : undefined;
      if (owed) {
        inFlight.delete(message.id);
        // An explicit error means the server is telling us it did not act, so
        // the held amount goes back. A connection that dies instead is handled
        // on exit, where the outcome is genuinely unknown.
        const refused = message.error !== undefined || message.result?.isError === true;
        await (refused ? owed.hold.release() : owed.hold.commit());
        // An approval buys one call. Spend it only when the call actually ran.
        if (owed.approved && !refused && approvals) {
          approvals.answer({
            context: owed.approved.context,
            kind: "answer",
            id: owed.approved.id,
            digest: owed.digest,
            status: "used",
            at: new Date().toISOString(),
          });
        }
      }
      if (message?.id !== undefined && listRequests.has(message.id) && message.result) {
        listRequests.delete(message.id);
        message.result = annotate(message.result);
      }
      send(message);
    }
  })();

  const exitCode = await new Promise((resolve) => {
    upstream.on("close", (code) => resolve(code ?? 0));
    upstream.on("error", (err) => {
      log(`could not start "${command}": ${err.message}`);
      resolve(127);
    });
  });

  await Promise.allSettled([clientDone, upstreamDone]);
  // Anything still in flight was sent and never answered. The effect may have
  // happened, so the amount is committed rather than handed back.
  for (const [, owed] of inFlight) {
    log(`${owed.name}: the server exited before answering, so the amount stays committed`);
    await owed.hold.commit();
  }
  return exitCode;
}
