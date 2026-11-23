# 特征工坊 · 特征工程与标注数据管理平台

面向特征注册与检索、衍生特征工程、时间窗口计算、特征回溯填充、样本分层抽取、标注任务派发、标注质量审核、特征血缘追踪与在线/离线特征服务的数据特征工程与标注管理平台。

这是一个前后端分离的管理平台：前端 Vue 3 + Vite + TypeScript，后端 FastAPI（Python）。
两边各自独立启动，前端 dev server 已关掉自动打开页面，启动后按终端打印的地址手工打开。

## 目录结构

```text
.
├── frontend/                 Vue 3 + Vite + TypeScript 前端
│   ├── src/views/WorkbenchView.vue|tsx  全部模块共享工作台
│   ├── src/data/modules.ts              18个业务模块配置
│   ├── src/api/              统一请求封装
│   └── vite.config.ts        dev server 配置（open: false）
├── backend/                  FastAPI（Python） 后端
│   ├── app/routers/resource.py  通用查询/导出/登记/动作接口
│   ├── app/services/<key>.py    每个模块独立领域逻辑
│   ├── app/services/base.py     共享服务骨架
│   └── app/store.py          内存数据仓库与示例数据
├── .gitignore
└── docker-compose.yml
```

## 启动

### 后端

```bash
cd backend
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
./run.sh
```

健康检查：`curl http://127.0.0.1:8000/api/health`

### 前端

```bash
cd frontend
npm ci
npm run dev
```

前端默认监听 `http://127.0.0.1:5173/`，dev server 不会自动打开浏览器，
需要自己访问。`/api` 由 vite 代理到后端 `http://127.0.0.1:8000`。

### 测试

```bash
cd backend
.venv/bin/pip install -r requirements-dev.txt   # 测试额外需要 httpx
.venv/bin/python -m unittest discover -s tests -t .
```

## 业务模块

| 模块 | 目录 | 业务对象 | 主要字段 |
| --- | --- | --- | --- |
| 特征注册 | `feature_reg` | 特征定义 | 特征编号、特征名称、数据类型 |
| 衍生工程 | `derive_rule` | 衍生规则 | 规则编号、输入特征、衍生函数 |
| 时间窗口 | `time_window` | 窗口模板 | 模板编号、窗口类型、窗口宽度 |
| 特征回溯 | `backfill_job` | 回溯任务 | 任务编号、目标特征、起始日期 |
| 样本分层 | `sample_strata` | 分层策略 | 策略编号、特征范围、分层字段 |
| 标注派发 | `label_task` | 标注任务 | 任务编号、样本范围、标注类型 |
| 标注审核 | `label_review` | 审核批次 | 批次编号、标注任务、审核人 |
| 一致性计算 | `consent_calc` | 一致性报告 | 报告编号、标注任务、评估指标 |
| 特征存储 | `feature_store` | 存储配置 | 配置编号、特征列表、存储引擎 |
| 在线服务 | `online_serv` | 服务端点 | 端点编号、特征列表、QPS上限 |
| 离线导出 | `offline_exp` | 导出管道 | 管道编号、特征范围、导出格式 |
| 特征血缘 | `feature_line` | 血缘链路 | 链路编号、上游特征、下游特征 |
| 目录血缘 | `catalog_lineage` | 目录血缘索引 | 同源组、输出、核查状态、目录包 |
| 特征监控 | `feature_mon` | 监控规则 | 规则编号、目标特征、监控类型 |
| 版本管理 | `version_mgr` | 特征版本 | 版本编号、关联特征、版本标签 |
| 数据切分 | `data_split` | 切分配置 | 配置编号、数据集、切分方式 |
| 特征目录 | `feat_catalog` | 目录索引 | 索引编号、目录名称、父目录 |
| 质量规则 | `quality_rule` | 质量检查 | 规则编号、目标特征、检查类型 |
| 标注词典 | `label_dict` | 标注项 | 词典编号、标签名称、标签值 |
| 批量接入 | `batch_load` | 接入任务 | 任务编号、数据源、目标特征 |
| 特征报告 | `report_task` | 分析报表 | 报告编号、报告类型、特征范围 |
| 调度编排 | `schedule_job` | 调度计划 | 计划编号、任务类型、关联对象 |
| 治理审计 | `govern_audit` | 审计记录 | 记录编号、审计对象、审计类型 |

## 约定

- 全部模块共享`frontend/src/views/WorkbenchView.vue|tsx`和一套资源路由。
- 每个模块仍保留独立`backend/app/services/<模块>.py`；纯前端保留
  `frontend/src/domain/<模块>.ts`，用于承载真实业务差异并维持36题位容量。
- 列表接口统一返回 `{ items, total, page, size }`，动作接口统一返回 `{ ok, message }`。
- 状态流转只允许在 `app/services` 里改，路由层不做业务判断。

## 目录血缘

多域共用的来源，消费域看不到源表名和映射值，需要另一种认「同源输出」的办法。
`catalog_lineage` 把跨域血缘边转换成带权限过滤的目录索引：

- **同源组**：来源身份取归属域 + 归属方 + 表 + 列（及映射、输出、共享范围）的
  不可逆指纹。两个输出落在同一 `source_group` 即同源；异域同名来源指纹不同，
  身份独立，核查也互不顶替。索引只给指纹和映射摘要，不带源表名和映射值。
- **来源核查**：目录维护员从索引提交核查，一次可覆盖同一来源的多个输出，
  记录签字人、审计批次和有效期；每条核查带可校验的签字。
- **第二版发布**：只撤下乙的边时，甲的主题摘要没有变化，可以沿用第一版的签字
  （`basis=carried_over`），报告里能看到原签发范围、审计批次和核查编号。
  已撤权的证据不会进入新版目录包和报告。
- **消费域关联**：只能拿已签发的目录包关联，且核查必须在有效期内。补签甲以后
  再次关联，会按新核查记录新的来源与有效期，旧关联作为历史保留。
- **一次性签发**：发布和共享范围变更共用一把锁，同一版本号只会生成一个
  归属明确的目录包；相同 `request_id` 的重复提交按幂等返回同一个包。

接口前缀 `/api/catalog-lineage`：`index`、`sources/{source_no}`、`attestations`、
`packages`、`packages/{version}/report`、`bindings`、`events`。角色通过 `role`
参数或 `X-Role` 头传入（`maintainer` / `consumer`），未声明时按权限最小的
消费域视图处理。前端入口在 `/catalog_lineage`。

领域：数据工程
子方向：数仓与数据湖
