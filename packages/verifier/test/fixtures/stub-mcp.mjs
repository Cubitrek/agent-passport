#!/usr/bin/env node
/**
 * A stand-in MCP server for testing the guard. It records every tools/call it
 * receives to the file named by STUB_LOG, so a test can assert not merely that
 * the guard said no, but that this server never heard about it.
 */
import { appendFileSync } from "node:fs";
import { createInterface } from "node:readline";

const LOG = process.env.STUB_LOG;
const TOOLS = [
  { name: "stripe.create_charge", description: "Charge a customer.", inputSchema: { type: "object", properties: { amount: { type: "number" }, customer: { type: "string" } } } },
  { name: "stripe.list_charges", description: "List charges.", inputSchema: { type: "object", properties: {} } },
  { name: "stripe.refund", description: "Refund a charge.", inputSchema: { type: "object", properties: {} } },
];

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of rl) {
  if (!line.trim()) continue;
  const message = JSON.parse(line);
  const reply = (result) => process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id: message.id, result })}\n`);
  if (message.method === "initialize") {
    reply({ protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "stub", version: "1" } });
  } else if (message.method === "tools/list") {
    reply({ tools: TOOLS });
  } else if (message.method === "tools/call") {
    if (LOG) appendFileSync(LOG, `${JSON.stringify({ name: message.params.name, args: message.params.arguments })}\n`);
    if (message.params.name === "stripe.refund") {
      reply({ content: [{ type: "text", text: "refund failed at the provider" }], isError: true });
    } else if (message.params.arguments?.ask === true && message.params.inputResponses === undefined) {
      // MCP 2026-07-28: ask the client for more input instead of acting. The
      // client retries the same call, under a new id, carrying inputResponses.
      reply({
        resultType: "input_required",
        inputRequests: {
          confirm: {
            method: "elicitation/create",
            params: { mode: "form", message: "Confirm?", requestedSchema: { type: "object", properties: { ok: { type: "boolean" } }, required: ["ok"] } },
          },
        },
        requestState: "stub-state",
      });
    } else {
      reply({ content: [{ type: "text", text: `did ${message.params.name}` }] });
    }
  } else if (message.id !== undefined) {
    reply({});
  }
}
