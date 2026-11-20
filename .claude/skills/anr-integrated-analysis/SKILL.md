---
name: anr-integrated-analysis
description: Comprehensive Android ANR analysis combining ANR type classification, trace parsing, system-wide performance analysis, thermal/CPU throttling detection, Binder thread pool exhaustion diagnosis, and rigorous quality control framework. Use when analyzing ANR trace files, bugreports, or any ANR/performance issue.
version: 2.1.0
---

# Android ANR 综合分析技能

> **本 skill 是以下 4 个 skill 的融合：**
> - `anr-analysis-tian` — ANR 类型区分 + 阻塞模式检测
> - `anr-analyzer-kui` — Python 脚本自动化 + bugreport 综合扫描
> - `framework-anr-analyzer` — 质量控制框架（证据分级 / 多假设博弈 / Gate 机制）
> - `android-anr-thermal-load-analysis` — 温控限频 + Binder 线程池耗尽深度分析
>
> **设计原则：** framework-anr-analyzer 的质量规则和 Phase 流程为骨架，其余三个 skill 的领域知识、分析策略、执行脚本分层注入各 Phase。

---

## 质量原则（5 条底层约束）

> **以下 5 条贯穿分析全流程，违反任一条的分析结论无效。**

### Rule 1: Evidence Tiering (Anti-Hallucination)

```
[FACT]       Directly quoted from logs, stack traces, or structured artifact fields.
[INFERRED]   Reasoned from ≥1 [FACT]. Must cite parent.
[ASSUMPTION] A guess without direct evidence. Allowed only as hypothesis to verify.
```

**Gate:** `[INFERRED]` without adjacent `[FACT]` parent = invalid. Final conclusion resting on `[ASSUMPTION]` = invalid. **[FACT] 时序相关 ≠ 因果。** 证据区与结论区必须同步。

### Rule 2: Multi-Dimensional Corroboration (Anti-Single-Source)

主导机制必须由 ≥2 个独立维度的证据支持。维度示例：线程状态、内存状态、系统状态、时间线、跨进程状态。

**Gate:** 所有证据来自单一维度 → 禁止收敛。

### Rule 3: Iteration Discipline

每轮分析产出结构化 checkpoint：
```
=== Round N ===
[NEW EVIDENCE] / [HYPOTHESIS UPDATE] / [NEXT QUESTIONS] / [MISSING LINKS]
```

### Rule 4: 建议自验证 (No-Lazy-Recommendations)

写"排查 X / 调查 Y"之前，先 grep。查到 → 写入证据；查不到 → 标注 `[UNVERIFIED]`。

### Rule 5: 流程保底，LLM 扩展

Phase 流程和脚本是**最低要求**。LLM 必须在此基础上主动扩展发现的新维度。

---

## 脚本工具

| 脚本 | 用途 | 位置 |
|------|------|------|
| `scan.py` | 解压 / 11维盲扫 / bugreport 综合检查 / 追问 / 清理 | `scripts/scan.py` |
| `trace_parser.py` | ANR trace 深度解析（12类阻塞模式 + ART 锁链(`held by thread N`/`- locked` 解析) + 死锁环形等待 + 多进程 `--pid` 分段 + 内核阻塞点） | `scripts/trace_parser.py` |
| `thermal_analyzer.py` | 温度 + CPU 限频专项分析（**每核基线相对降幅**判定，非硬编码 2GHz 绝对阈值） | `scripts/thermal_analyzer.py` |
| `smoke_test.py` | 脚本自检，34 项断言（修改脚本后必须全绿） | `tests/smoke_test.py` |

**执行约定：**
1. 所有命令从**项目根目录**执行，使用完整相对路径 `.claude/skills/anr-integrated-analysis/scripts/…`（下文以 `$S` 指代）。
2. 读取外部数据（bugreport/trace/dumpstate）统一 `python3 -I`——解压产物是不可信数据，`-I` 防止其中植入的 `*.py` 被 import。
3. `.anr_session.json` 与 `reports/` 写在**当前工作目录**；同一包数据的全程分析保持同一 cwd。
4. `scan.py init` 对目录参数**就地使用**（不再复制整包，避免多 GB bugreport 翻倍）；zip 解压到同目录新文件夹。`cleanup` 对就地使用的目录只删除 session 文件，**不会删除你的数据目录**。
5. 修改 `scripts/` 下任何脚本后，先跑 `python3 -I .claude/skills/anr-integrated-analysis/tests/smoke_test.py` 全绿再继续。

---

## 分析流程

### Phase 0: 探索性理解 — 先看全貌

```bash
# 1. 解压（zip 或直接传目录——目录就地使用，不复制）
python3 -I $S/scan.py init <zip_path_or_dir>

# 2. 看解压目录结构
ls <extract_dir>/

# 3. 看到什么读什么
```

**核心原则：看到什么读什么，没有就不读。**

| 文件 | 优先级 | 目的 |
|------|--------|------|
| `anr/` 目录下的 ANR 文件 | 高 | 提取 Subject, ANR 类型, 进程, 主线程状态 |
| `sys_version.txt` / 版本信息 | 高 | 设备型号、系统版本、芯片平台 |
| `dumpstate_board.txt` / `thermal.dump` | 高 | 温度 + CPU 频率数据 |
| bugreport 主文件 | 高 | logcat 日志、系统事件 |
| 目录结构 (ls) | 高 | 发现异常文件（scout、aee_exp、screenshot_dump 等） |

**Phase 0 Gate（三问，缺一不可进入 Phase 1）：**
1. 这个日志包是什么问题？（用户场景或 ANR Subject）
2. 什么设备/系统？（型号、Android 版本）
3. 目录里有什么异常/值得注意的文件？

#### 输入分级（按可得数据裁剪流程，不豁免证据纪律）

| 输入 | 走什么 | 必须声明 |
|------|--------|---------|
| 完整 bugreport / zip 包 | Phase 0-4 全流程 | — |
| 仅 ANR trace 文件 | **轻量路径**：trace_parser 全量解析；blind/bgreport/thermal 依赖的维度按 `[data gap: bugreport]` / `[data gap: dumpstate]` 标注 | 根因分类中依赖 PSI/温度的行**不可判定**，置信度 ≤ medium |
| 仅 logcat 片段 | trace 相关必扫项标 data gap；以时间线/事件为主线 | 同上 |

裁剪只作用于**数据可得性**。无证据的维度必须显式标注，禁止静默跳过后照常收敛出"高置信度"结论。

---

### Phase 1: 入口 — 必扫 + 盲扫 + 假设博弈

```bash
# 必扫项：直接读 ANR trace、CPU dump、PSI 等数据文件（无脚本命令，LLM 直接读取）
# 盲扫项（11 维）——时间窗口格式：'HH' / 'HH:M'（十分钟段，如 19:4 = 19:40-19:49）/ 'HH:MM' / 'HH:MM:SS'
# 格式错误立即报错退出，不会静默过滤掉全部结果
python3 -I $S/scan.py blind "<时间窗口>" [extract_dir]

# Bugreport 14项综合检查：
python3 -I $S/scan.py bgreport [extract_dir]

# ANR trace 深度解析（多进程 trace 用 --pid 指定目标进程段）：
python3 -I $S/trace_parser.py <anr_file> --json [--pid <目标pid>]

# 温度专项分析（--time-window 尽量必带，否则统计被全程记录稀释）：
python3 -I $S/thermal_analyzer.py <dumpstate_board.txt> --json -t "<ANR时刻 HH:MM>"
```

#### 必扫项：ANR 核心数据（11 类）

| 类别 | 必看内容 | 说明 |
|------|---------|------|
| **ANR 类型判定** | Subject 行 → 分类为 input / broadcast / service / content_provider / no_focus / waiting_previous_event | **不同 ANR 类型有不同分析路径（见下方 ANR 类型策略表）** |
| **设备全局状态** | Android 版本、开机时长、OTA 记录、MemTotal/MemAvailable、电量、磁盘空间 | 系统基线，判断设备是否本身处于异常状态 |
| ANR trace | 主线程状态、堆栈、锁竞争（waiting to lock / 持有者链）、12 类阻塞模式匹配 | ANR 的直接证据 |
| Input dispatch | InputDispatcher 等了什么事件、多久、哪个窗口没响应 | ANR 触发条件 |
| CPU usage | ANR 前后 CPU 占用，目标进程 vs 系统进程 | 判断 CPU 竞争 |
| PSI | cpu/memory/io pressure（avg10/avg60/avg300） | 系统压力量化，统一阈值 70% |
| 内存 | MemAvailable、swap 使用、LMK kill 记录 | 内存是否紧张 |
| I/O | iowait、FUSE 阻塞、page fault | I/O 是否瓶颈 |
| 进程生命周期 | am_proc_start、am_kill、forceStop、DeadObject | 进程是否被杀/重启 |
| system_server | GC 暂停、锁链、binder 线程池状态 | 系统进程是否异常 |
| **ANR/Crash 统计** | am_anr 和 am_crash 按包名归类 | 判断是否多进程连锁 ANR |

#### ANR 类型差异化分析策略

| ANR 类型 | 分析重点 |
|----------|---------|
| **input** | 主线程阻塞点定位 + InputDispatcher 事件队列 + 窗口焦点状态 |
| **broadcast** | 广播接收器 onReceive 耗时 + 广播派发队列是否阻塞 + system_server AMS 广播处理 |
| **service** | Service.onCreate/onStartCommand 耗时 + system_server 启动服务流程 + ANR timeout 是否为 20s(前台)/200s(后台) |
| **content_provider** | Provider.onCreate 耗时 + 依赖的其他 Provider + 是否有 Provider 级联超时 |
| **no_focus** | 窗口焦点切换日志 + Keyguard/锁屏状态 + 如果有焦点问题则重点分析窗口；否则分析应用启动流程 |
| **waiting_previous_event** | 前一输入事件处理耗时 + 多份 trace 是否卡在同一位置（必现）还是分散（偶现/系统负载） |

#### 盲扫项（11 维）

| 维度 | 查询模式 | 说明 |
|------|---------|------|
| am_anr | `am_anr` | 同窗口其他 ANR → 多进程 ANR 通常是系统级问题 |
| system_server_gc | `system_server.*GC\|Pause` | 系统进程 GC 暂停 |
| binder_starved | `IPCThreadState.*starved` | binder 线程池耗尽 ≥10s 为严重 |
| lmk_kill | `lmkd.*kill\|Killing.*adj` | LMK 低内存杀进程 |
| dead_object | `DeadObjectException\|binderDied` | binder 死亡通知 |
| background_procs | `SmartPower.*background\|am_proc_start\|am_proc_died\|RecentTasks` | ANR 窗口内活跃进程 + 最近任务 |
| thermal | `SS-CPU\|VIRTUAL-SENSOR` (搜 dumpstate_board.txt) | 温升限频 |
| **binder_thread_pool** | 7 个 MIUI 关键字（见 Binder 专项） | Binder 线程池耗尽检测 |
| **binder_lock_contention** | `dvm_lock_sample.*Locked\|LockPerfImpl\|monitor contention` | Binder 锁竞争详情 |
| **miui_specific** | `MiuiEmbeddingWindow\|MiuiClone\|GreezeManager\|SubDisplay` 等 | MIUI 特有机制（投屏/双开/冻结/子窗口） |
| **app_blocking** | 12 类阻塞模式关键字 | 应用层主线程阻塞模式匹配 |

**blind 输出纪律：**
- 每维先看 `hits` 条数与 `warnings`/`note`。出现 `grep timeout` / `grep error` / `全部落在时间窗外` 时，该维度"无结果"**不可信**，必须手动 grep 复核后才能写入证据（Rule 1/4 要求，非可选优化）。
- `miui_specific`、`binder_thread_pool` 中的 MIUI 关键字、P5 的 MiSight 等维度**仅适用于 Xiaomi/Redmi/POCO**。其他厂商设备这些维度标注 `N/A（非 MIUI）` 即视为已执行，可通过 Phase 1 Gate。

#### 假设博弈

始终保持 ≥3 个互斥的根因假设。每轮证据后更新：

| Hypothesis | Support | Evidence |
|------------|---------|----------|
| `<hypothesis A>` | ↑ / ↓ / — | `[FACT] ...` or `no new evidence` |
| `<hypothesis B>` | ↑ / ↓ / — | |
| `<hypothesis C>` | ↑ / ↓ / — | |

**Phase 1 Gate（完成性）：** 必扫 11 项已逐项检查 + 盲扫 11 维全部执行 + 假设表 ≥3 互斥假设
**Phase 1 Gate（收敛性）：** 除一个假设外其余被明确排除（需 `[FACT] that contradicts`，不能仅 "no evidence found"）

---

### Phase 2: Gate — 验证 + 追问（含 3 个专项模块）

Phase 1 完成后，必须完成**步骤 1（验证）+ 步骤 2（追问 + 专项模块）**，缺少任一步禁止写报告。

#### 步骤 1：验证

**必扫项验证：**

| 必扫项 | 验证要点 |
|--------|---------|
| ANR 类型判定 | 类型已确定 + 对应分析路径已明确 |
| 设备全局状态 | 型号/版本/内存配置/可用率/电量/磁盘 已记录 |
| ANR trace | 主线程状态 + 堆栈 + 锁竞争 + 12 类阻塞模式 已提取 |
| Input dispatch | 等待事件类型 + 时长 + 未响应窗口 已记录 |
| CPU usage | dump 覆盖 ANR 时刻 + 目标进程 vs 系统 已对比 |
| PSI | avg10/avg60/avg300 已记录，统一用 70% 阈值 |
| 内存 | MemAvail + swap + LMK kill 已记录 |
| I/O | iowait + FUSE + page fault 已记录 |
| 进程生命周期 | am_proc_start/kill/forceStop/DeadObject 已搜索 |
| system_server | GC + 锁链 + binder 线程池 已检查 |
| ANR/Crash 统计 | 按包名归类 + 多进程连锁判断 |

**盲扫覆盖验证：**
```
- [ ] thermal: 是否搜了 dumpstate_board.txt？（不是 bugreport logcat）
- [ ] binder_thread_pool: 7 个 MIUI 关键字是否全部搜到？（非 MIUI 设备标 N/A）
- [ ] miui_specific: 是否搜索了全部 12 个关键字？（非 MIUI 设备标 N/A）
- [ ] background_procs: 是否搜了 bugreport 主文件？（不是 ANR trace）
- [ ] logcat 时间范围: head/tail 确认覆盖 ANR 时间窗口
- [ ] warnings 复核: blind 中带 timeout/error/全窗外 warning 的维度是否已手动 grep 重查？
```

**Gate：** 任一必扫验证要点未完成 → 回 Phase 1 补充。

#### 步骤 2：追问 + 专项模块

**有结果维度清单**（列出所有命中维度和无结果维度），每个命中维度执行追问。

#### 专项模块 A：温控限频深度分析（thermal 命中时触发）

```bash
python3 -I $S/thermal_analyzer.py <dumpstate_board.txt> --json -t "<ANR时刻 HH:MM>"
```

**分析要点：**
1. 温度状态：用 VIRTUAL-SENSOR 数值 / 1000 得到 °C
2. 温度分级：< 35°C 正常 / 35-38°C 偏高 / ≥ 38°C 高温 / ≥ 40°C 严重（与脚本常量、bgreport 判定一致）
3. CPU 频率：**每核基线相对降幅**——基线取该核在 <38°C 冷态记录里的最高频，当前频率较基线降幅 ≥ 30% = 确认限频（低频 SoC 恒低于 2GHz 不代表限频）
4. `baseline_missing: true` 时（整段抓不到冷态记录）：基线退化为全程最大值，降幅只是**下限**，结论置信度必须降级
5. 温度时间线与 ANR 时间对齐（不带 `-t` 时统计被全程稀释）
6. 脚本 verdict：`高温限频主导` / `高温（未显著限频）` / `限频（非温度原因）` / `温度正常`——只回答温度维度；`高负载主导` / `复合型` / `应用自身问题` 需叠加 PSI 与主线程证据后在 Phase 3 判定

#### 专项模块 B：Binder 线程池耗尽 6 步定位（binder 相关维度命中时触发）

**触发条件（任一满足即启动）：**
- ANR Reason 含 system_server 相关
- 主线程阻塞在 `binder_ioctl` / `binder_thread_read` / `binder_transaction`
- system_server CPU > 50%
- 多个应用同时 ANR

**Step 1: 确认线程池状态**
搜索 `binder thread pool` → 确认 total/idle/pending/active
- `idle=0` 且 `pending > 0` = **确认耗尽**

**Step 2: 定位高频/长耗时 Binder 调用**
搜索 `PerfMonitor binderTransact` → 统计各进程调用频次和耗时
```bash
python3 -I $S/scan.py why binder_lock <dir>
```

**Step 3: 定位锁竞争源**
搜索 `dvm_lock_sample: [system_server` → 找 Locked 状态的 Binder 线程
搜索 `Long monitor contention with owner binder` → 确认 Binder 线程持锁

**Step 4: 定位长时间持锁方法**
搜索 `LockPerfImpl: Long locked method event` → 提取 holder/method/duration/thread
- `duration > 500ms` = 高优先级可疑源

**Step 5: 检查服务泄漏**
搜索 `bindService exceeded max service` → 记录调用方/目标服务

**Step 6: 构建阻塞链并输出结论**

| 字段 | 内容 |
|------|------|
| **阻塞源进程** | 进程名和 PID |
| **阻塞源线程** | 具体线程名 |
| **阻塞方法** | 持锁或耗时方法名 |
| **阻塞时长** | 持锁/耗时持续时间 |
| **影响范围** | 受影响的进程列表 |
| **Binder 子分类** | 线程池耗尽-外部进程 / 线程池耗尽-系统服务 / 调用超时 / 锁竞争 / 服务泄漏 |

#### 专项模块 C：ANR 类型专项追问（始终触发）

根据 Phase 1 确定的 ANR 类型执行对应追问：

| ANR 类型 | 必须追问 |
|----------|---------|
| input | InputDispatcher 等待的具体 MotionEvent/KeyEvent + 窗口名 + focus 状态；主线程 MessageQueue 中排队的消息 |
| broadcast | 广播 Intent 内容 + 接收者数量 + 顺序广播队列中排在前面的接收者 + 是否有 `BOOT_COMPLETED` 等耗时广播 |
| service | Service 组件名 + 是前台(20s)还是后台(200s)超时 + system_server 中 `bringUpServiceLocked` 或 `realStartServiceLocked` 是否有异常 |
| content_provider | Provider 组件名 + 依赖的其他 Provider 是否已发布 + `ContentProviderHelper.getProvider` 耗时 |
| no_focus | `setFocusedApp` / `wm_set_focused_app` 日志 + 锁屏状态 + 如果焦点有问题则深入窗口日志，否则分析 `am_proc_start` → `wm_create_activity` 的应用启动链路 |
| waiting_previous_event | 前一个事件是什么 + 处理耗时 + 多份 trace 是否指向同一位置（必现=应用问题，分散=系统负载问题） |

#### 数据缺失处理

| 缺失数据 | 处理 |
|----------|------|
| MemAvail 无数据 | 标注 `[data gap: MemAvail]`，用 LMK kill 间接推断 |
| CPU dump 只有 ANR 进程 | 标注 `[data gap: CPU breakdown]`，结论置信度降级 |
| debuggerd 附加失败无 Java 堆栈 | 标注 `[data gap: Java stack]`，用内核等待通道 + logcat 推断 |
| dumpstate_board.txt 未找到 | 标注 `[data gap: dumpstate]`，温度/限频无法验证 |
| logcat 不覆盖 ANR 时间窗口 | 标注 `[data gap: logcat coverage]`，仅用 ANR trace 自带数据 |

---

### Phase 3: 因果链分析

根因必须表达为 ≥3 个环节的因果链：

```
Trigger → Amplifier → Direct Blocker → Symptom
```

每环节需 `[FACT]` 级证据。短于 3 环节 → confidence: incomplete。

**根因追问：** 每锁定一个中间层，必须搜索上游来源——"什么导致了这个状态？" 禁止停在中间层。

**根因分类（5 类）：**

| 类别 | 判定条件 |
|------|----------|
| **高温限频主导** | VIRTUAL-SENSOR ≥ 40°C 且 CPU 相对每核基线降幅 ≥ 30%（thermal_analyzer verdict） |
| **高负载主导** | PSI mem/cpu ≥ 70% 且温度 < 38°C |
| **复合型** | 温度 ≥ 38°C 且 PSI ≥ 70%（最常见） |
| **应用自身问题** | 温度正常、负载正常，但主线程 D 状态（IO 阻塞等）或锁竞争 |
| **Binder 阻塞** | 主线程阻塞在 binder 通信，system_server 线程池异常 |

---

### Phase 4: 报告生成

**前置条件：** Convergence Checklist 4 项全部勾选：
- [ ] Evidence from ≥2 independent dimensions
- [ ] Zero [INFERRED] claims without a parent [FACT]
- [ ] Dominant mechanism is a causal description (not a label like "GC" or "binder")
- [ ] 结论自洽：量化表述与设备参数逻辑一致；因果链触发条件与数据可对账

**报告生成步骤：**
1. 读取 `templates/report.html`
2. 替换所有 `{{PLACEHOLDER}}` 占位符
3. 保留所有 section 和 analysis 内 card（因果链、假设博弈、排除的竞争机制）
4. 有价值信息以额外 `.card` 形式插入对应 section
5. 保存到 `reports/<包名>_<ANR类型>_<根因分类>_<YYYYMMDD>.html`
6. 清理：`python3 -I $S/scan.py cleanup`（就地使用的目录只删 session 文件，不动数据目录）

**报告 section 清单（所有必须保留）：**
- `#info` — 设备全局状态 + ANR 概览 + 系统负载 + PSI
- `#device-status` — 设备状态卡（型号/版本/温度/PSI 快照；模板占位符 `DEVICE_CHECK_ROWS`）
- `#root-cause` — 根因总结
- `#timeline` — 事件时间线
- `#evidence` — 所有证据卡片
- `#analysis` — 因果链 + 假设博弈 + 排除的竞争机制
- `#recommendations` — App 侧 + 系统侧修复建议
- `#checklist` — Convergence Checklist
- `#appendix` — 关键文件 + 额外分析 card

---

## Pitfalls（从实际分析失败中积累）

### P1: 脚本和模板在 skill 目录内

`scripts/` 和 `templates/` 位于 `.claude/skills/anr-integrated-analysis/` 下。`scan.py init` 自动保存 `.anr_session.json`。

### P2: 模板是最小集合，可增不可删

`templates/report.html` 定义的 section 和 card 是报告必须包含的最小集合。但模板只是底线，LLM 发现的有价值信息必须以额外 `.card` 形式插入对应 section。

### P3: MIUI 特有机制的盲扫

AOSP 标准盲扫不覆盖 MIUI 特有风险，必须追加搜索：投屏/镜像、应用双开、应用冻结、子窗口管理。

### P4: 应用切换场景的完整验证

ANR 发生在应用切换期间时，完整追踪目标进程生命周期：
1. `ResumedActivity=X` ≠ 进程已启动，必须验证 am_proc_start 存在
2. wm_create_activity → am_proc_start 应 < 3s，> 5s 异常
3. 中间是否有 forceStop / kill / DeadObject 打断
4. 因果链最底层 Trigger 应为**系统框架/平台层面**；只落在 ANR 进程内部时必须追问上游

### P5: ANR 时系统可用内存查 MiSight 事件

搜索 `MiSight.*MemAvail`，比 bugreport 抓取时的 meminfo 更接近 ANR 真实状态。

### P6: 温度值必须 /1000

VIRTUAL-SENSOR / backlight_therm / battery 的原值是毫摄氏度（如 41976 → 41.976°C），必须除以 1000 再使用。Board Sensor Temperature 同理。

### P7: PSI 阈值统一为 70%

`some avg10 ≥ 70%` 才算高负载。低于此值属于正常波动，不应标记为高负载。PSI 是滑动窗口均值，avg10 高 ≠ 这个 10 秒内的事件造成了它——可能是之前累积的结果。

### P8: Binder 线程池耗尽必须定位到阻塞源

不能仅停留在"线程池耗尽"层面。必须输出：阻塞源进程名(PID)、线程名、阻塞方法、持锁时长。

### P9: 锁竞争分析优先级

`LockPerfImpl` 中 `duration > 500ms` 为高优先级；`dvm_lock_sample` 中 `Locked` 状态的 Binder 线程为直接阻塞源。

### P10: 多应用同时 ANR

多应用同时 ANR 是 Binder 线程池耗尽的典型特征，应优先排查。

### P11: 时间窗口格式与"带 warning 的零结果"

`blind` / `thermal_analyzer` 的窗口接受 `HH` / `HH:M` / `HH:MM` / `HH:MM:SS`，格式错误**立即报错退出**。历史版本把 `19:4` 当字面量匹配 → 全维度假性"无结果"。同理，任何带 `grep timeout` / `grep error` / `命中全部在窗外` warning 的维度，其"无结果"未经验证——手动 grep 复核前禁止当作证据（Rule 1）。

### P12: 脚本输出先看计数，再按维度精读

blind 11 维单次输出可能很大。执行顺序：先看每维 `hits` 条数与 `warnings`/`note` → 只精读命中维度；命中 >3 维时逐维处理，避免一次性吞掉全部输出撑爆上下文，或因截断漏读关键行。

---

## Growth Rule

本 skill 保持精简。每次真实分析中 LLM 犯错后，将纠正追加到 Pitfalls 中。Skill 从失败中成长，不从预设推测中膨胀。
