import { parseArgs } from "node:util";
import { ApiClient } from "./client.js";
import { loadConfig } from "./config.js";
import { ScamGuard, type AlertEvent } from "./guard.js";
import { CrownChecker } from "./jev.js";
import { IntentReviewer } from "./review.js";

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
  const crownChecker = config.jev ? new CrownChecker(config.jev) : undefined;
  const reviewer = config.review ? new IntentReviewer(config.review) : undefined;
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
    const guard = new ScamGuard(client, {
      thresholdPercent: config.detection.thresholdPercent,
      crownThresholdPercent: config.detection.crownThresholdPercent,
      ...(crownChecker ? { crown: (hash: string) => crownChecker.check(hash) } : {}),
      ...(reviewer ? { review: (text: string, probability: number) => reviewer.isScam(text, probability) } : {}),
    });
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
    guard.on("alert", (event: AlertEvent & { mentioned: number; total: number }) => {
      if (closed) return;
      // Codes and numbers only: never the member's name or message text.
      if (event.kind === "scam") console.info(`SCAM_ALERT_SENT probability=${event.probability * 100}% admins=${event.mentioned}/${event.total}`);
      else console.info(`JOIN_ALERT_SENT crown=${typeof event.crown === "number" ? `${event.crown * 100}%` : event.crown === null ? "none" : "unknown"} name=${event.nameHit} admins=${event.mentioned}/${event.total}`);
    });
    guard.on("review", (event: { probability: number; scam: boolean }) => {
      if (!closed) console.info(`SCAM_REVIEWED probability=${event.probability * 100}% intent=${event.scam ? "scam" : "dismissed"}`);
    });
    guard.on("join", (event: { chatId: string; memberId: string; crown: number | null | undefined; nameHit: boolean; alert: boolean }) => {
      if (closed) return;
      // No picture means no crown (0%); "unknown" only when a picture could not be judged.
      const crown = event.crown === undefined ? "unknown" : `${(event.crown ?? 0) * 100}%`;
      console.info(`JOIN_CHECKED chat=${event.chatId} member=${event.memberId} fake_crown=${crown} name=${event.nameHit} alert=${event.alert}`);
    });
    try {
      await client.connect();
      if (!closed && !stopped) console.info(`NekoGuard 已連線，詐騙判定門檻 ${config.detection.thresholdPercent}%，皇冠判定門檻 ${config.detection.crownThresholdPercent}%。`);
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
