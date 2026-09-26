/**
 * fileSpendLedger needs node:fs, so it must not be reachable from the main
 * entry: the package promises to run in Workers and browsers. @ts-expect-error
 * fails the build if it ever becomes exported there.
 */
// @ts-expect-error fileSpendLedger belongs to the "/node" subpath, not the main entry.
import { fileSpendLedger } from "../../dist/index.js";
void fileSpendLedger;
