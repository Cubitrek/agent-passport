import { decide, localPolicy } from "../../dist/index.js";
async function broken(): Promise<void> {
  const a = localPolicy({ id: "x", scope: ["y"] });
  // decide() returns a promise, so this is a type error on purpose.
  const n: number = decide(a, { scope: "y" });
  void n;
}
void broken;
