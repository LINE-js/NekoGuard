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
  let stopped = false;
  let retryTimer: NodeJS.Timeout | undefined;
  let closeSession = () => {};
  const shutdown = (exitCode: number) => {
    if (stopped) return;
    stopped = true;
    clearTimeout(retryTimer);
    process.exitCode = exitCode;
    closeSession();
  };
  process.once("SIGINT", () => shutdown(0));
  process.once("SIGTERM", () => shutdown(0));

  const connect = async () => {
    if (stopped) return;
    const client = new ApiClient(config.api.url, config.api.token);
    const guard = new ScamGuard(client, { thresholdPercent: config.detection.thresholdPercent });
    let closed = false;
    const helloDeadline = setTimeout(() => retry("LINEJS_HELLO_TIMEOUT"), 25_000);
    closeSession = () => {
      if (closed) return;
      closed = true;
      clearTimeout(helloDeadline);
      guard.stop();
      client.close();
    };
    const retry = (code: string) => {
      if (closed || stopped) return;
      closeSession();
      console.error(`${code}：10 秒後重新連線。`);
      retryTimer = setTimeout(() => { void connect(); }, 10_000);
    };
    client.on("frame", frame => {
      if (closed || stopped) return;
      if (frame.type === "hello") clearTimeout(helloDeadline);
      guard.handle(frame);
    });
    client.on("fault", retry);
    client.on("disconnected", () => retry("WS_DISCONNECTED"));
    guard.on("notice", code => { if (!closed) console.info(code); });
    guard.on("fatal", code => {
      if (closed) return;
      console.error(code);
      shutdown(1);
    });
    guard.on("alert", ({ probability, mentioned, total }) => {
      if (!closed) console.info(`SCAM_ALERT_SENT probability=${probability * 100}% admins=${mentioned}/${total}`);
    });
    try {
      await client.connect();
      if (!closed && !stopped) console.info(`NekoGuard 已連線，詐騙判定門檻 ${config.detection.thresholdPercent}%。`);
    } catch {
      retry("WS_CONNECT_FAILED");
    }
  };
  await connect();
}

await main().catch(() => {
  console.error("STARTUP_FAILED：請檢查啟動參數與設定。");
  process.exitCode = 1;
});
