# SecBaseline

SecBaseline 是一个面向 Linux 基线审计的 CLI 工具，支持本机/远程扫描、快照漂移分析、持续监控告警、自动修复（安全子集）和可视化面板。

## 主要功能

- 基线扫描：Linux / SSH / HTTP 头
- 目标模式：`local`、`remote`（SSH）
- 规则包：`full`（linux+ssh+http）、`host`（linux+ssh）、`web`（http）
- 报告格式：`json` / `md` / `sarif`
- 快照管理：保存快照、当前 vs 历史、历史 vs 历史 Diff
- 持续监控：定时扫描 + 回归阈值告警
- 告警输出：本地 `alerts/*.jsonl` + webhook（含 Slack 兼容）
- 自动修复：`--fix`（本机安全修复集，含回滚脚本）
- 可视化面板：`--dashboard` 生成风险趋势与热力图

## 安装

```bash
python -m pip install -r requirements.txt
```

## 常用命令

1. 本机基础扫描（默认 full）

```bash
python main.py --target local
```

2. 本机主机侧扫描（strict + host）

```bash
python main.py --target local --profile strict --rule-pack host
```

3. 仅 Web 规则包（HTTP 头）

```bash
python main.py --target local --rule-pack web --url https://example.com
```

4. 远程主机扫描（SSH）

```bash
python main.py --target remote --host 10.0.0.12 --user root --port 22 --rule-pack host
```

5. 保存快照

```bash
python main.py --target local --save --name baseline_v1
```

6. 漂移对比（历史快照 vs 历史快照）

```bash
python main.py --target local --diff-from baseline_v1.json --diff-to baseline_v2.json --diff-view regressions --diff-top 5
```

7. 持续监控 + 告警 + webhook（短参数）

```bash
python main.py --target local --interval 60 --count 3 --alert 1 --alert-file alerts --alert-webhook https://your-webhook-url
```

8. 自动修复 + 面板

```bash
python main.py --target local --profile strict --rule-pack host --fix --dashboard
```

## 参数速览

| 参数 | 说明 | 默认 |
|---|---|---|
| `--target` | 扫描目标：`local` / `remote` | `local` |
| `--host --user --port` | 远程 SSH 目标参数（`target=remote` 时必填 host/user） | `22` |
| `--rule-pack` | 规则包：`full` / `host` / `web` | `full` |
| `--profile` | 规则档位：`basic` / `strict` | `basic` |
| `--url` | HTTP 检查目标 URL | 空 |
| `--http-timeout` | HTTP 超时（秒） | `10` |
| `--remote-timeout` | 远程命令超时（秒） | `10` |
| `--format` | 报告格式：`both` 或 `json,md,sarif` | `both` |
| `--save` / `--name` | 保存快照 / 指定快照名 | 关闭 / 时间戳 |
| `--diff-from --diff-to` | 漂移对比输入快照（`snapshots/` 下文件名） | 空 |
| `--diff-view` | `all` / `changes` / `regressions` | `changes` |
| `--diff-module` | 漂移模块过滤：`linux,ssh,http` | 空 |
| `--diff-top` | 漂移 Top 回归数量 | `10` |
| `--interval --count` | 监控间隔秒 / 扫描次数（0=无限） | `0` / `1` |
| `--alert` | 回归告警阈值 | `1` |
| `--alert-file` | 告警文件名（固定写入 `alerts/`，自动补 `.jsonl`） | `alerts` |
| `--alert-webhook` | 告警回调地址 | 空 |
| `--fix` | 本机自动修复（安全子集） | 关闭 |
| `--dashboard` | 生成 `dashboard.html` | 关闭 |

## 输出目录说明

- 普通扫描：
  - 无 `--url` -> `output/`
  - 有 `--url` -> `output_url/`
- Diff 输出：
  - 默认 `output_diff/`
  - Diff-only + `--output-dir` 时写入自定义目录
- 快照：`snapshots/*.json`
- 告警：`alerts/*.jsonl`
- 自动修复：`output/fixes/fix_summary.json` 与 `rollback_*.sh`
- 面板：`output/dashboard.html`

## 约束说明

- `--fix` 仅支持 `--target local`
- `--fix` 不能与 Diff-only 或 monitor 同时使用
- `--dashboard` 不能与 Diff-only 同时使用
- 在 Windows 上运行 Linux 基线规则时，部分项会因环境不匹配出现 `fail`/`error`，建议在 Linux 环境执行正式审计

## 测试

```bash
python -m unittest discover -s tests -v
```
