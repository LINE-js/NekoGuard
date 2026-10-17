import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const [target, ...extra] = process.argv.slice(2);
if (!target || extra.length) {
  console.error('用法：npm run patch:linejs -- /path/to/LINE.js');
  process.exitCode = 1;
} else {
  const patch = fileURLToPath(new URL('../integrations/linejs-admins.patch', import.meta.url));
  try {
    const manifest = JSON.parse(await readFile(new URL('../integrations/linejs-base.json', import.meta.url), 'utf8'));
    const cwd = resolve(target);
    const revision = spawnSync('git', ['rev-parse', 'HEAD'], { cwd, encoding: 'utf8' });
    if (revision.status !== 0 || revision.stdout.trim() !== manifest.commit) {
      throw new Error(`LINE.js 必須使用補丁基準版本 ${manifest.commit}；不會自動切換版本或覆寫修改。`);
    }
    const check = spawnSync('git', ['apply', '--check', patch], { cwd, encoding: 'utf8' });
    if (check.status !== 0) throw new Error('補丁無法完整套用（可能已套用或與本機修改衝突）；未修改檔案。');
    const apply = spawnSync('git', ['apply', patch], { cwd, encoding: 'utf8' });
    if (apply.status !== 0) throw new Error('補丁套用失敗，請檢查 LINE.js 工作目錄。');
    console.info('已套用管理員 API 擴充。請在 LINE.js 執行 npm ci、npm run build，再重新啟動服務。');
  } catch (error) {
    console.error(error instanceof Error ? error.message : 'PATCH_FAILED');
    process.exitCode = 1;
  }
}
