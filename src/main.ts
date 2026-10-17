import { parseArgs } from "node:util";
import { ApiClient } from "./client.js";
import { loadConfig } from "./config.js";
import { ScamGuard } from "./guard.js";

async function main(): Promise<void> {
  const { values } = parseArgs({ options: { config: { type: "string", default: "config.yaml" }, help: { type: "boolean" } } });
  if (values.help) {
    console.info("NekoGuard：node dist/main.js [--config config.yaml]\n先套用 LINE.js 管理員 API 擴充，再設定 NEKOGUARD_API_TOKEN 或 api.token。");
    return;
  }
  let config;
  try {
    config = await loadConfig(values.config);
  } catch (error) {
    // loadConfig deliberately produces diagnostics without YAML source, URLs, or credentials.
    console.error(error instanceof Error ? error.message : "CONFIG_FAILED");
    process.exitCode = 1;
    return;
  }
  const client = new ApiClient(config.api.url, config.api.token);
  const guard = new ScamGuard(client, { thresholdPercent: config.detection.thresholdPercent });
  let stopped = false;
  const shutdown = (exitCode: number) => {
    if (stopped) return;
    stopped = true;
    clearTimeout(helloDeadline);
    process.exitCode = exitCode;
    guard.stop();
    client.close();
  };
  const helloDeadline = setTimeout(() => {
    console.error("LINEJS_HELLO_TIMEOUT");
    shutdown(1);
  }, 25_000);
  client.on("frame", (frame) => {
    if (stopped) return;
    if (frame.type === "hello") clearTimeout(helloDeadline);
    guard.handle(frame);
  });
  client.on("fault", (code: string) => {
    console.error(code);
    shutdown(1);
  });
  client.on("disconnected", () => {
    if (!stopped) console.error("WS_DISCONNECTED：監測已停止；請檢查 LINE.js 與 Token 後重新啟動。");
    shutdown(1);
  });
  guard.on("notice", (code: string) => console.info(code));
  guard.on("fatal", (code: string) => { console.error(code); shutdown(1); });
  guard.on("alert", ({ probability, mentioned, total }) => {
    console.info(`SCAM_ALERT_SENT probability=${probability * 100}% admins=${mentioned}/${total}`);
  });
  process.once("SIGINT", () => shutdown(0));
  process.once("SIGTERM", () => shutdown(0));
  try {
    await client.connect();
    if (!stopped) console.info(`NekoGuard 已連線，詐騙判定門檻 ${config.detection.thresholdPercent}%。`);
  } catch {
    if (!stopped) console.error("WS_CONNECT_FAILED");
    shutdown(1);
  }
}

await main().catch(() => {
  console.error("STARTUP_FAILED：請檢查啟動參數與設定。");
  process.exitCode = 1;
});
