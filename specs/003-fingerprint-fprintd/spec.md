# Feature Specification: 基于 fprintd 的本地指纹识别认证

**Feature Branch**: `003-fingerprint-fprintd`

**Created**: 2026-09-04

**Status**: Draft（规划中，供 spec-kit 落地实现）

**Input**: 以系统 **fprintd** 作为本仓库**唯一**指纹录入与认证实现，**替换**原进程内 libfprint 直连代码。原规格 `002-fingerprint-recognition` **保留**作 as-built 对照，不再作为交付路径。设备侧不链入 `libfprint.so`，通过开源 fprintd 栈（D-Bus 服务 `net.reactivated.Fprint` + 官方工具 `fprintd-enroll` / `fprintd-verify` / `fprintd-list` / `fprintd-delete`）完成采集、落库与比对；控制面板仍走「身份认证 → 指纹」页；登录/锁屏经 PAM → daemon → 设备管理服务完成识别。不走远端比对方案。

**替换范围**: 删除 `plugins/driver/fingerprint/`（libfprint 插件）及相关 CMake/装载逻辑；指纹设备适配改为 fprintd 驱动。对外仍暴露 `DEVICE_TYPE_FINGERPRINT` / `KAD_AUTH_TYPE_FINGERPRINT`，面板与 PAM 契约形状尽量不变。原 FeatureDB 中 libfprint serialize blob 特征**不迁移**（需用户用新路径重新录入，见 FR-018）。`specs/002-fingerprint-recognition/` 文档保留不删。

## Clarifications

### Session 2026-09-04（规划裁决）

- Q: 为什么用 fprintd 替换 libfprint 直连？ → A: 复用发行版已维护的 fprintd/libfprint 组合与 Polkit 策略；避免认证服务进程直接链接 libfprint，降低 ABI/传感器驱动耦合；可用官方 CLI 做独立排障。只保留一条指纹实现路径，避免双后端维护成本。
- Q: 「开源工具」指什么？ → A: 以 **fprintd D-Bus API** 为服务内正式集成面；以 **fprintd-enroll / fprintd-verify / fprintd-list / fprintd-delete** 为开发验证与运维排障面。禁止 shell 拼接用户输入调用 CLI 作为生产认证路径。
- Q: 特征存在哪里？ → A: **生物模板由 fprintd 持久化**（通常 `/var/lib/fprint/`）。KAS FeatureDB 只存元数据映射（featureID ↔ 用户 ↔ finger_name ↔ 设备信息），供面板列表、上限、matchUser 使用；不保存 fprintd 私有序列化 blob。
- Q: featureID 如何生成？ → A: 稳定映射键，建议 `md5("fprintd:" + userName + ":" + finger_name)`（或等价规范字符串）；删除时按映射调用 fprintd `DeleteEnrolledFinger`。
- Q: 录入由谁采图？ → A: fprintd 驱动指纹仪多阶段按压；面板只展示进度与提示，不传图像。
- Q: 重复录入如何判定？ → A: 由 fprintd `EnrollStart` 过程中的 `enroll-duplicate` 判定（跨用户同指也会拒绝，一指一用户）。KAS 不再做录入前 Verify 查重；面板提示「该指纹可能已由当前用户或其他用户录入」。
- Q: 识别比对范围？ → A: 不可切换用户：`Claim(user_name)` + `VerifyStart("any")`，仅验证该用户。可切换用户：优先对输入 `user_name` 做 Verify；失败后再按本机已登记用户列表尝试 Identify/逐用户 Verify（以实现时 research 定稿的策略为准），命中后由 daemon `matchUser` 决定登录用户。
- Q: 识别是持续窗口还是单次扫描？ → A: 对齐 fprintd Verify/Enroll 一次会话：`done=true` 即结束（MATCH/NOT_MATCH 或错误）。
- Q: 每账户特征上限？ → A: 沿用 daemon `FEATURE_COUNT_MAXIMUN=10`，且不得超过 fprintd 单用户可录入 finger 槽位（通常 10 指命名）。
- Q: 缺 fprintd 时构建？ → A: `BUILD_FINGERPRINT_DRIVER`（或等价选项）默认 ON，指向 fprintd 插件；无 QtDBus 时跳过并 WARNING，不影响 pam/daemon 等核心组件构建。
- Q: 原 libfprint 直连代码是否保留？ → A: **实现代码不保留**（删除进程内 libfprint 插件）。规格目录 `specs/002-fingerprint-recognition/` **保留**作历史/对照，交付与运行仅走 fprintd。

## User Scenarios & Testing *(mandatory)*

### User Story 1 - 控制面板指纹录入 (Priority: P1)

用户在控制面板「身份认证 → 指纹」页点击录入并通过密码验证后进入录入页；按界面提示在指纹仪上多次按压，服务经 fprintd 完成多阶段采集、模板落库（fprintd）与元数据落库（FeatureDB）并回报进度（重复由 fprintd `enroll-duplicate` 拒绝）；完成后新特征出现在列表，可立即用于登录/锁屏认证。失败、重复或取消时给出明确提示且不留无效元数据/半成品映射。

**Why this priority**: 无录入特征则无法认证，是主链路前提。

**Independent Test**: 插入受支持的指纹仪且 `fprintd` 服务正常，打开控制面板指纹页完成一次录入；亦可用 `fprintd-list` 对照确认模板已写入。

**Acceptance Scenarios**:

1. **Given** 指纹仪已连接且 fprintd 可枚举到设备, **When** 用户在指纹页点击录入并通过密码验证, **Then** 进入录入页并提示按压手指
2. **Given** 该手指已在本机任一用户下由 fprintd 录入, **When** 再次录入同一手指, **Then** fprintd 上报 enroll-duplicate，面板提示可能已由当前或其他用户录入，不写入 FeatureDB 映射
3. **Given** 手指未被占用, **When** 用户按提示完成多阶段按压, **Then** 进度递增至 100%，特征以「ID + 名称」出现在列表；`fprintd-list <user>` 可见对应 finger；可立即参与认证
4. **Given** 扫描质量不佳, **When** fprintd 上报 enroll-retry-*, **Then** 面板提示质量相关文案，用户可继续按压，不产生残留 FeatureDB 映射
5. **Given** 录入进行中, **When** 用户取消或关闭页面, **Then** 流程终止、调用 EnrollStop/Release；FeatureDB 无新映射；若 fprintd 未完成则无新 finger
6. **Given** 当前用户特征数已达上限（10）, **When** 再次发起录入, **Then** 被拒绝并提示数量上限相关错误
7. **Given** fprintd 未运行或 Claim 被 Polkit 拒绝, **When** 发起录入, **Then** 明确失败提示（服务不可用/权限不足），不假成功

---

### User Story 2 - 登录/锁屏指纹识别认证 (Priority: P1)

用户在登录、锁屏解锁等场景选择指纹认证，在指纹仪上按压；本人（或可切换模式下匹配到其他合法用户特征）则认证通过，否则拒绝并提示。

**Why this priority**: 识别认证是本功能最终价值。

**Independent Test**: 已录入后锁屏选指纹：本人通过、他人/错误手指拒绝、切换密码时停止无阻塞；可切换用户场景按 FR-012 验证。亦可用 `fprintd-verify` 对照硬件与 fprintd 本身是否正常。

**Acceptance Scenarios**:

1. **Given** 当前用户已录入指纹且不可切换用户, **When** 用本人手指识别, **Then** 认证通过
2. **Given** 当前用户已录入指纹且不可切换用户, **When** 用未登记或其他用户手指识别, **Then** 认证失败并提示
3. **Given** 锁屏允许切换用户且已输入用户 A, **When** 使用仅登记在用户 B 下的手指, **Then** 可命中 B 的特征，认证成功并以用户 B 登录
4. **Given** 锁屏允许切换用户且已输入用户 A, **When** 用户 A 与用户 B 对同一手指均有模板, **Then** 优先匹配用户 A
5. **Given** 指纹设备正忙（本服务或 fprintd AlreadyInUse）, **When** 发起新的录入/识别, **Then** 明确拒绝并提示「设备忙」
6. **Given** 识别进行中, **When** 用户停止或切换其他认证方式, **Then** 进行中结果被丢弃，不误报成功

---

### User Story 3 - 指纹特征管理 (Priority: P2)

用户在指纹页查看已录入特征，可重命名与删除；删除后不再参与认证；服务重启后元数据与 fprintd 模板保持一致（或可自愈同步）。

**Why this priority**: 日常管理需求，不阻塞「录入 → 认证」主链路。

**Independent Test**: 已有特征时独立完成列表、重命名、删除；删除后 `fprintd-list` 对应 finger 消失；重启后列表一致。

**Acceptance Scenarios**:

1. **Given** 已有录入特征, **When** 打开指纹页, **Then** 列表展示全部特征（名称及设备信息）
2. **Given** 选中某特征, **When** 重命名, **Then** 立即生效且重启后保持（仅改 FeatureDB 显示名，不改 fprintd finger_name）
3. **Given** 选中某特征, **When** 删除, **Then** 列表移除；fprintd 对应 finger 删除；此后不再参与认证
4. **Given** FeatureDB 与 fprintd 列表不一致（例如曾用 CLI 直接删除）, **When** 打开指纹页或发起识别, **Then** 服务应能发现并收敛（清理孤儿映射或重新同步列表），不得因脏数据误报成功

---

### User Story 4 - 开源工具排障与对照 (Priority: P3)

运维/开发者在不启动控制面板的情况下，用 fprintd 官方工具验证硬件与守护进程是否可用，并与 KAS 路径对照。

**Why this priority**: 降低「是 KAS 问题还是 fprintd/硬件问题」的排查成本。

**Independent Test**: 仅依赖系统 fprintd 包与 USB 设备，不依赖本仓库 UI。

**Acceptance Scenarios**:

1. **Given** fprintd 正常, **When** 执行 `fprintd-enroll` / `fprintd-verify` / `fprintd-list`, **Then** 可完成独立录入与验证
2. **Given** 用 CLI 录入后, **When** 走 KAS 同步/导入策略（若实现）或重新在面板录入, **Then** 文档说明如何与 FeatureDB 对齐，避免双源混乱

---

### Edge Cases

- 未插入指纹仪或 fprintd `GetDevices` 为空
- fprintd 服务未启动、崩溃或 D-Bus 名丢失
- Polkit：enroll/verify/setusername 未授权
- Claim/Release 未成对：异常路径必须 Release，避免永久 AlreadyInUse
- 热插拔：插入后 fprintd 枚举到设备；拔出时进行中操作应可取消/结束
- 录入与识别并发：本服务忙拒绝；亦映射 fprintd AlreadyInUse
- 录入中服务异常或面板断连：终止且不残留半成品映射
- 未录入任何指纹时发起识别：不匹配/失败提示
- 重复录入同一手指（当前用户）：拒绝
- 可切换模式下空特征库：识别失败
- 同一手指多用户模板：可切换时优先当前输入用户
- 每账户特征达 10 个后再录入：拒绝
- 升级前 FeatureDB 中仍有旧 libfprint blob 特征：视为无效/需清理，须重新录入（不自动迁移）
- 用户用 CLI 增删指纹导致与 FeatureDB 漂移：需同步/自愈策略

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: 指纹采集、录入与比对必须在本机完成，依赖本机指纹仪与 fprintd 本地模板库，不依赖远端比对服务
- **FR-002**: 认证服务必须通过既有设备接口向控制面板提供录入启动/停止能力，录入过程持续上报进度、状态与结果（成功时返回可供 daemon 落库的 FeatureData **元数据**，特征 blob 可为空或占位）
- **FR-003**: 录入成功后：fprintd 侧模板持久化；KAS FeatureDB 写入映射元数据；服务重启后仍可查询并参与认证
- **FR-004**: 认证服务必须提供特征查询接口，返回当前用户已录入指纹列表（特征 ID、名称等）
- **FR-005**: 认证服务必须提供特征重命名与删除接口；删除须同时清理 FeatureDB 与 fprintd 对应 finger；重命名仅影响展示名
- **FR-006**: 认证服务必须提供识别接口；一次 fprintd 校验会话结束后返回匹配、不匹配或失败及可读原因
- **FR-007**: 设备处于录入/识别进行中时，新请求必须被明确拒绝并提示「设备忙」
- **FR-008**: 识别/录入停止请求发出后，进行中结果必须丢弃，不得误报成功；并释放 fprintd Claim
- **FR-009**: 质量不佳、取消、打开失败、无特征、fprintd 不可用、Polkit 拒绝等场景必须给出明确可读提示
- **FR-010**: 录入重复检测由 fprintd `enroll-duplicate` 完成（含跨用户同指）；命中则拒绝并提示可能已由当前或其他用户录入；KAS 不做录入前 Verify 查重
- **FR-011**: 不可切换用户时，识别仅验证 daemon 指定的目标用户（Claim 该用户 + Verify）
- **FR-012**: 可切换用户时，优先验证输入 `user_name`；未命中再按约定策略扩展到其他已登记用户；命中 finger/用户后映射为 featureID，由 daemon `matchUser` 反查并校验合法性
- **FR-013**: 设备装载基于 fprintd Manager 枚举（可与 USB 热插拔事件协同）；出现设备后创建并 Claim 就绪；消失时卸载并取消进行中操作
- **FR-014**: 每个操作系统账户最多可录入 10 个指纹特征（与现有 daemon 上限一致）；达上限须拒绝并提示
- **FR-015**: 缺 fprintd/D-Bus 客户端依赖时构建可跳过本插件，不得导致核心组件无法编译
- **FR-016**: 特征 ID 由稳定映射键唯一确定（用户 + finger_name），供列表与管理；**不**依赖 libfprint serialize blob 的 MD5
- **FR-017**: 控制面板指纹页复用既有录入进度展示（阶段进度图 + 文案），不要求摄像头预览
- **FR-018**: 必须移除进程内 libfprint 指纹**实现代码**及对其的装载/构建入口；运行时指纹认证**仅**走 fprintd。`specs/002-fingerprint-recognition/` 可保留作对照文档。旧 FeatureDB 中基于 serialize blob 的指纹记录不保证可用，交付须提供清理或提示重新录入的策略
- **FR-019**: 生产路径必须通过 D-Bus 调用 fprintd；CLI 仅用于 quickstart/排障文档，不得作为 daemon 热路径
- **FR-020**: 必须处理 Claim/Release 生命周期与 fprintd 错误（NoSuchDevice、ClaimDevice、AlreadyInUse、PermissionDenied 等）并映射为既有设备错误语义
- **FR-021**: FeatureDB 与 fprintd 列表不一致时，须具备检测与收敛策略（启动时或列表查询时），避免认证误用孤儿数据

### Key Entities *(include if feature involves data)*

- **指纹特征映射 (Fingerprint Feature Mapping)**: FeatureDB 中的一条元数据；关键属性：特征 ID（稳定映射键）、iid、显示名称、所属用户、finger_name（fprintd 标准名）、关联 VID/PID/设备类型；feature blob 可为空
- **fprintd 模板 (Fprintd Print)**: 由 fprintd 管理的真实生物模板；按 username + finger_name 索引
- **指纹设备 (Fingerprint Device)**: 绑定 fprintd Device 对象路径的设备对象；关键属性：设备 ID、fprintd object path、状态（空闲/录入中/识别中）、是否已 Claim
- **指纹驱动 (Fprintd Fingerprint Driver)**: 通过 D-Bus 访问 fprintd 的插件实现；负责枚举、Claim/Release、Enroll/Verify、List/Delete
- **认证请求 (Auth Request)**: 一次认证会话；含发起用户、是否可切换用户、认证方式、feature_ids / user_name、结果

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 指纹识别不得阻塞现有 PAM 认证链路：识别中可切换其他方式或停止，响应与现有体验一致
- **SC-002**: 本人已录入手指连续 20 次识别，通过不少于 19 次（≥95%）
- **SC-003**: 未录入手指/他人手指在不可切换场景下不得误通过当前用户认证（抽样交叉测试，交付时记录实测）
- **SC-004**: 正常条件下首次完整录入成功率不低于 90%（20 次中成功不少于 18 次）
- **SC-005**: 特征增删改查完成后即时生效，无需重启服务
- **SC-006**: 断网后录入、管理与识别全流程仍可用
- **SC-007**: 可切换用户场景下，用仅属于其他用户的手指可成功切换登录到该用户
- **SC-008**: 拔掉网络、仅本机 fprintd + 硬件可用时，`fprintd-verify` 与 KAS 锁屏指纹路径结论一致（同用户同手指）
- **SC-009**: 异常取消或进程崩溃后，再次录入/识别不会因未 Release 而长期 AlreadyInUse（可恢复）

## Assumptions

- 运行环境已安装并启用 `fprintd`（及发行版匹配的 libfprint），USB 指纹仪须被 fprintd/libfprint 支持
- 控制面板指纹页（finger-page）既有流程可复用：点录入 → 密码验证 → 进度页按压；跨仓库仅需保证与本服务 EnrollStatus 语义兼容
- 认证场景沿用现有 PAM/会话链路，指纹为可选认证方式之一
- 系统 Polkit 策略允许认证相关系统服务完成 enroll/verify（必要时提供配套 rules，写入 research/plan）
- ZKTeco 等私有 SDK 设备仍不在本需求范围
- 本期不做独立活体/防伪算法层；依赖采集器与 fprintd/libfprint 自身能力
- 从旧 libfprint 直连版本升级时，用户需重新录入指纹；不要求跨引擎模板迁移
