# SecBaseline 设计架构说明

## 1. 目标与定位

SecBaseline 是一个面向 Linux 安全基线的 CLI 工具，核心目标是：

- 以最小依赖完成可解释的基线审计
- 支持本机与远程主机的统一扫描入口
- 支持快照、漂移对比、持续监控与告警
- 提供安全子集自动修复和可视化风险面板

设计原则：

- KISS：优先简单可维护
- 可解释：每条结果都有证据与建议
- 可回溯：通过快照与 drift 跟踪变化
- 可扩展：规则、合规映射、告警通道可持续增强

## 2. 功能范围

### 2.1 已支持功能

- 扫描目标
  - `--target local`
  - `--target remote --host --user --port`
- 检查模块
  - `linux`
  - `ssh`
  - `http`（需 `--url`）
- 规则包
  - `full` = linux + ssh + http
  - `host` = linux + ssh
  - `web` = http
- 报告输出
  - `json` / `md` / `sarif`
- 快照与漂移
  - `--save --name`
  - `--diff-from --diff-to`
  - `--diff-view --diff-module --diff-top`
- 持续监控与告警
  - `--interval --count --alert`
  - `--alert-file`（固定写入 `alerts/`，自动 `.jsonl`）
  - `--alert-webhook`（含 Slack 兼容发送）
- 自动修复（安全子集）
  - `--fix`（仅本机）
  - 输出回滚脚本和修复结果
- 可视化面板
  - `--dashboard` 生成 `dashboard.html`

### 2.2 当前边界

- 不做漏洞扫描（CVE/Nmap）
- 不做 agent 常驻服务
- 自动修复仅覆盖有限规则
- `--fix` 不支持 remote / monitor / diff-only 组合

## 3. CLI 入口与模式

统一入口：

```bash
python main.py [参数]
```

核心模式：

1. 普通扫描模式（默认）
- 执行规则并输出报告
- 可选 `--save`、`--dashboard`

2. Diff-only 模式
- 条件：`--diff-from` + `--diff-to`
- 仅做历史快照对比，不执行新扫描

3. 监控模式
- 条件：`--interval > 0`
- 定时扫描、自动快照、自动 drift、阈值告警

4. 自动修复模式
- 条件：`--fix`
- 流程：扫描 -> 修复 -> 复扫 -> 生成 fix_summary

## 4. 架构分层

```text
main.py
  ├─ collectors/
  │   ├─ linux.py
  │   ├─ ssh.py
  │   ├─ http.py
  │   └─ remote.py
  └─ core/
      ├─ engine.py
      ├─ reporter.py
      ├─ drift.py
      ├─ fixer.py
      ├─ dashboard.py
      └─ models.py
```

各层职责：

- `main.py`
  - 参数解析、模式路由、流程编排
  - 参数冲突校验与错误提示
- `collectors/*`
  - 采集本机/远程原始数据
  - 采集失败时返回 `__error`
- `core/engine.py`
  - 加载规则、规则包过滤、合规映射注入
  - 执行规则计算结果
- `core/reporter.py`
  - 报告结构化输出（json/md/sarif）
  - 附带 evidence bundle
- `core/drift.py`
  - 快照差异计算
  - 回归/改善统计、优先级与趋势视图
- `core/fixer.py`
  - 安全子集自动修复
  - 回滚脚本生成
- `core/dashboard.py`
  - 风险总览、热力图、趋势图 HTML 输出

## 5. 规则模型与合规映射

规则来源：`rules/*.yaml`

支持规则类型（当前已使用）：

- `exists`
- `config_equals`
- `config_not_equals`
- `command_check`
- `regex_match`
- `numeric_compare`
- `value_in`
- `value_not_in`

规则关键字段：

- `id / name / module / type / severity`
- `profiles`（`basic` / `strict`）
- `recommendation`

合规映射：

- 文件：`rules/compliance_map.yaml`
- 将 `rule_id` 映射到控件（如 CIS / NIST）
- 最终写入结果的 `compliance` 字段

## 6. 数据与结果模型

状态集固定：

- `pass | fail | warn | skipped | error`

单条结果字段：

- `rule_id`
- `name`
- `module`
- `status`
- `severity`
- `message`
- `evidence`
- `compliance`
- `recommendation`

报告主结构：

- `meta`
- `summary`
- `results`
- `evidence`（采集上下文）

## 7. 输出目录规范

- 普通扫描：
  - 无 `--url` -> `output/`
  - 有 `--url` -> `output_url/`
- 漂移输出：`output_diff/`（或 Diff-only 时自定义输出目录）
- 快照：`snapshots/*.json`
- 告警：`alerts/*.jsonl`
- 自动修复：`output/fixes/`
  - `fix_summary.json`
  - `rollback_<timestamp>.sh`
- 面板：`output/dashboard.html`

## 8. 自动修复设计

修复目标规则（安全子集）：

- `LNX-007` `/etc/passwd` 去 world-write
- `LNX-009` `kernel.randomize_va_space`
- `LNX-010` `net.ipv4.ip_forward`
- `SSH-002/003/005/006`（写入 `sshd_config`）

修复流程：

1. 从扫描结果中筛选 `fail` 且可修复规则
2. 执行修复动作
3. 生成回滚脚本
4. 自动复扫并计算修复前后状态差异

权限说明：

- 若没有系统写权限（如非 root），修复会失败并在 `fix_summary.json` 给出错误原因

## 9. 监控与告警设计

监控参数：

- `--interval`：扫描间隔秒
- `--count`：扫描次数（`0` 表示无限）
- `--alert`：回归阈值

告警机制：

- 本地落盘：`alerts/*.jsonl`
- webhook 回调：`--alert-webhook`
- Slack 兼容：自动发送 `text` payload

中断处理：

- `Ctrl+C` 优雅退出，返回码 `130`

## 10. 可视化面板设计

`--dashboard` 输出单文件 HTML：

- 当前风险总览
- 模块热力图（linux/ssh/http x status）
- Top 风险项
- 风险趋势（基于历史 snapshots）

## 11. 质量与测试

测试框架：`unittest`

覆盖范围：

- 参数解析与边界
- 规则引擎类型覆盖
- 报告格式输出
- 漂移计算
- webhook 行为
- 自动修复与 dashboard

## 12. 已知限制与后续方向

已知限制：

- `sshd_config` 的 `Match` 语义不展开，仅给 `warn`
- 自动修复规则覆盖有限
- dashboard 当前为静态 HTML（无后端）

可演进方向：

- 扩展可修复规则并做分级审批
- 增加更细粒度的风险评分策略
- 多主机批量调度与汇总视图
- 规则包签名与版本治理
