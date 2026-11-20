# ANR Integrated Analysis

Android ANR 综合分析 Claude Skill：ANR 类型区分、trace 解析、系统级性能分析、温控限频检测、
Binder 线程池耗尽诊断，以及以证据分级为基础的质量控制框架。

本仓库是以下 4 个 skill 的融合版本：

- `anr-analysis-tian` — ANR 类型区分 + 阻塞模式检测
- `anr-analyzer-kui` — Python 脚本自动化 + bugreport 综合扫描
- `framework-anr-analyzer` — 质量控制框架（证据分级 / 多假设博弈 / Gate 机制）
- `android-anr-thermal-load-analysis` — 温控限频 + Binder 线程池耗尽深度分析

## 目录结构

```
.claude/skills/anr-integrated-analysis/
├── SKILL.md                    # 技能主文档：质量原则、Phase 流程、分析策略
├── scripts/
│   ├── scan.py                 # bugreport 综合扫描
│   ├── trace_parser.py         # ANR trace 解析
│   └── thermal_analyzer.py     # 温控限频 / CPU 负载分析
├── templates/
│   └── report.html             # 分析报告模板
└── tests/
    └── smoke_test.py           # 冒烟测试
```

## 使用方式

1. 将 `.claude/skills/anr-integrated-analysis/` 放到项目的 `.claude/skills/` 下（或 Claude 的
   skills 目录）。
2. 提供 ANR trace / bugreport，按 SKILL.md 中的 Phase 流程执行；脚本可直接运行：

```bash
python3 scripts/scan.py <bugreport 或解压目录>
python3 scripts/trace_parser.py <anr trace 文件>
python3 scripts/thermal_analyzer.py <bugreport 目录>
```

3. 自检：

```bash
python3 tests/smoke_test.py
```

## 核心约束

分析结论遵循证据分级（[FACT] / [INFERRED] / [ASSUMPTION]）、多维交叉验证、迭代收敛等 Gate 规则，
细节见 `SKILL.md` 的「质量原则」章节。
