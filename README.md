# Account Enum Detector

一个仅依赖 Python 标准库的**授权安全测试工具**，用于检测登录、找回密码、注册等接口是否可通过状态码、响应正文、响应头或响应时间差异枚举账号。

> 仅可在已获得明确书面授权的系统上使用。请优先使用甲方提供的测试账号或你自己控制的账号；不要用真实用户账号反复尝试错误密码，也不要把它用于撞库、密码爆破或绕过验证码/限流。

## 特性

- 自动构造：
  - 调用方提供的“已知存在”账号样本；
  - 每个样本唯一的“不存在”账号，避免负缓存/重复数据干扰；
  - 一个重复请求的“不存在”账号，作为热缓存对照。
- 交错随机发送 existing / unique-nonexisting / cached-nonexisting，降低时间漂移和缓存偏差。
- 比对：
  - HTTP 状态码；
  - 归一化后的 JSON / HTML / 文本正文及 unified diff；
  - 稳定响应头，区分 `Content-Length`、缓存头和独立头部差异；
  - TTFB 与总耗时的中位数、MAD、分位数、bootstrap 95% CI、rank permutation p 值、Cliff's delta。
- 保守结论：
  - `enumerable`
  - `likely_enumerable` / `likely_enumerable_timing_side_channel`
  - `no_reliable_evidence_detected`
  - `inconclusive_insufficient_samples`
  - `blocked_by_rate_limit_or_challenge`
  - `blocked_account_lockout_signal`
- 安全控制：
  - 实际发包必须显式提供 `--i-am-authorized`（或 `AEA_I_AM_AUTHORIZED=1`）；
  - 登录、找回密码或复用已知账号时，还必须提供 `--confirm-known-accounts-safe`（或 `AEA_CONFIRM_KNOWN_ACCOUNTS_SAFE=1`），确认这些是测试/授权账号，不会锁定真实用户；
  - 串行请求，无并发；
  - 默认 1 秒间隔 + 0–0.75 秒随机抖动；
  - 默认每组 5 个样本，含缓存对照和 warm-up 共 16 个请求；
  - 单次运行硬上限 100 个请求；
  - 默认每个已知账号只探测 1 次；显式复用时，每个已知账号硬上限 3 次；
  - 遇到 429、Retry-After、限流、验证码/人机验证、账号锁定等信号立即停止；
  - 不包含验证码绕过、代理池、爆破或撞库功能。
- 输出终端报告、JSON 和 Markdown；报告默认脱敏账号。

## 运行环境

- Python 3.10+
- 无第三方依赖。

## 30 秒本地验证

启动内置模拟靶场：

```bash
python3 lab/mock_targets.py --port 18080
```

另开终端，运行“不同提示文案”的登录检测：

```bash
python3 -m account_enum_detector scan \
  --url http://127.0.0.1:18080/login-message \
  --mode login \
  --known-file examples/known_accounts.example.txt \
  --password 'Invalid-Test-Password-Only' \
  --samples-per-class 5 \
  --delay 0 --jitter 0 \
  --seed 42 \
  --i-am-authorized --confirm-known-accounts-safe
```

也可以检测：

```bash
# 状态码差异
python3 -m account_enum_detector scan \
  --url http://127.0.0.1:18080/login-status \
  --mode login \
  --known-file examples/known_accounts.example.txt \
  --password 'Invalid-Test-Password-Only' \
  --delay 0 --jitter 0 --seed 7 --i-am-authorized --confirm-known-accounts-safe

# 注册接口
python3 -m account_enum_detector scan \
  --url http://127.0.0.1:18080/register \
  --mode register \
  --known-file examples/known_accounts.example.txt \
  --delay 0 --jitter 0 --seed 8 --i-am-authorized --confirm-known-accounts-safe

# 稳定时间差
python3 -m account_enum_detector scan \
  --url http://127.0.0.1:18080/timing \
  --mode login \
  --known-file examples/known_accounts.example.txt \
  --password 'Invalid-Test-Password-Only' \
  --delay 0 --jitter 0 --seed 99 --i-am-authorized --confirm-known-accounts-safe
```

运行自动化测试：

```bash
python3 -m unittest tests.test_detector -v
```

## 推荐真实授权测试流程

1. 向目标系统负责人确认授权范围、测试时间窗、限流/锁定策略和 IP 白名单。
2. 准备至少 3–5 个专用测试账号，最好 5 个以上；不要使用真实员工或用户账号。
3. 登录接口只使用一个固定的、故意错误的密码，每个测试账号默认只发一次失败请求。
4. 优先在预发/测试环境或加白后的来源 IP 测试。
5. 先执行 `--dry-run` 检查请求体、字段名和请求数量。
6. 先用低样本、保守速率运行；如果触发防护，立即停止并联系负责人，不要尝试绕过。
7. 时间侧信道建议在低网络抖动环境、同地域代理或测试环境中多次复测。

## 常用用法

### 先预览请求计划，不发送任何包

```bash
python3 -m account_enum_detector scan \
  --url 'https://target.example/api/login' \
  --mode login \
  --known-file ./known_test_accounts.txt \
  --password-env AEA_TEST_PASSWORD \
  --body '{"account":"{{account}}","password":"{{password}}","device":"cli"}' \
  --dry-run
```

### JSON 登录接口

建议通过环境变量提供一个固定的错误密码，避免密码进入 shell 历史：

```bash
export AEA_TEST_PASSWORD='A-fixed-invalid-password-for-safe-enum-test'

python3 -m account_enum_detector scan \
  --url 'https://target.example/api/login' \
  --mode login \
  --known-file ./known_test_accounts.txt \
  --password-env AEA_TEST_PASSWORD \
  --body '{"username":"{{account}}","password":"{{password}}"}' \
  --header 'Content-Type: application/json' \
  --samples-per-class 5 \
  --delay 1.5 \
  --jitter 1.0 \
  --out-dir ./enum-report \
  --i-am-authorized --confirm-known-accounts-safe
```

### 表单登录接口

如果不传 `--body`，工具会根据 `--account-field`、`--password-field` 和 `--field` 自动构造表单：

```bash
AEA_TEST_PASSWORD='invalid-test-password' \
python3 -m account_enum_detector scan \
  --url 'https://target.example/login' \
  --mode login \
  --known-file ./known_test_accounts.txt \
  --content-type application/x-www-form-urlencoded \
  --account-field email \
  --password-field passwd \
  --field remember=0 \
  --password-env AEA_TEST_PASSWORD \
  --i-am-authorized --confirm-known-accounts-safe
```

### 找回密码接口

找回密码接口不要对同一真实账号重复提交，以免发送多封邮件或短信。默认“一个已知账号一次”最合适：

```bash
python3 -m account_enum_detector scan \
  --url 'https://target.example/api/password/reset' \
  --mode password-reset \
  --known-file ./owned_reset_test_accounts.txt \
  --body '{"email":"{{account}}","channel":"email"}' \
  --samples-per-class 3 \
  --delay 2 \
  --jitter 1 \
  --markdown-out ./reset-enum.md \
  --json-out ./reset-enum.json \
  --i-am-authorized --confirm-known-accounts-safe
```

### 注册接口

```bash
python3 -m account_enum_detector scan \
  --url 'https://target.example/api/register/check' \
  --mode register \
  --known-file ./known_test_accounts.txt \
  --body '{"username":"{{account}}","scene":"register"}' \
  --nonexistent-pattern 'enum_probe_{{uuid}}' \
  --i-am-authorized --confirm-known-accounts-safe
```

如果已知账号是邮箱，默认不存在样本会使用相同域名：

```text
ae-enum-<uuid>@<known-domain>
```

也可以显式指定：

```bash
--nonexistent-pattern 'security-probe-{{uuid}}@example.invalid'
```

### GET 接口，账号在 query/path 中

URL 中的 `{{account}}` 会自动 URL 编码：

```bash
python3 -m account_enum_detector scan \
  --url 'https://target.example/api/user?name={{account}}' \
  --method GET \
  --mode generic \
  --known-file ./known_test_accounts.txt \
  --i-am-authorized --confirm-known-accounts-safe
```

### 经过 Burp 或其他代理

```bash
python3 -m account_enum_detector scan \
  --url 'https://target.example/api/login' \
  --mode login \
  --proxy http://127.0.0.1:8080 \
  --insecure \
  --known-file ./known_test_accounts.txt \
  --body '{"username":"{{account}}","password":"{{password}}"}' \
  --password-env AEA_TEST_PASSWORD \
  --i-am-authorized --confirm-known-accounts-safe
```

## 请求模板占位符

请求体和 URL 支持：

- `{{account}}`：当前账号；
- `{{password}}`：`--password` 或 `--password-env` 中的固定测试密码；
- `{{uuid}}` / `{{shortuuid}}`；
- `{{timestamp}}`；
- `{{index}}`。

不存在账号模式 `--nonexistent-pattern` 推荐使用 `{{uuid}}`，也兼容 `{uuid}` 写法。

## 时间检测如何降低误报

原始耗时不能直接比较几十毫秒的均值。工具采用以下方法：

1. 先发送一个不存在账号的 warm-up 请求，预热 DNS/TLS/连接和 WAF 路径；该请求不进入统计。
2. existing、唯一 nonexisting、重复 cached-nonexisting 在每轮内随机排序并交错发送。
3. 对两组报告中位数、MAD、p25/p75/p90、均值和标准差。
4. 使用 bootstrap 重采样估计“中位数差”的 95% CI。
5. 使用 rank-based permutation / Mann-Whitney 风格检验和 Cliff's delta 衡量分布分离程度。
6. 默认要求同时满足：
   - 中位数差至少 `30ms`，可用 `--min-timing-diff-ms` 按基线延迟和抖动校准；
   - 中位数比值至少 `1.15`；
   - `|Cliff's delta| >= 0.55`；
   - bootstrap CI 不跨 0；
   - rank permutation `p <= 0.05`；
   - 每组至少 4–5 个有效样本才给强结论。
7. 缓存对照：
   - 唯一不存在账号通常是冷查询；
   - 重复不存在账号从第 2 次起作为热缓存对照；
   - 如果 existing vs unique 的差异与 cold vs hot 的缓存效应一致，而 existing vs hot 不稳定，工具会标记 `cache_confounder_warning`，不会把它判定为可靠枚举。

即便如此，时间侧信道仍容易受网络、TLS、HTTP 连接复用、服务端 GC、数据库缓存和负载均衡影响。时间结论应视为线索，需要在低抖动环境或本地/预发环境复测。

## 响应归一化

为了避免把每次变化的 request ID、CSRF token、时间戳等误判成内容差异，工具会尝试：

- 解析并规范化 JSON；
- 删除/替换动态字段值，如 token、nonce、timestamp、request-id、trace-id、session/signature 等；
- 替换 UUID、JWT、长 hex/base64、常见时间格式；
- 替换本次使用的账号字符串；
- 规范化常见 CSRF hidden input；
- 对响应头做小写化和动态值处理；
- 保留 `Content-Length`、业务 code、错误文案、`Location` 等可能构成枚举预言机的信息。

如果所有响应的归一化签名都唯一，工具只会给出“动态内容不稳定”的信息，不会草率判定为正文枚举。

## 输出与退出码

终端会打印结论、证据、diff 和逐请求时间表。可选：

```bash
--json-out report.json
--markdown-out report.md
--out-dir ./report-dir   # 同时写 report.json 和 report.md
```

JSON 中包含完整统计和逐请求记录。默认不输出未脱敏账号；只有在你明确加 `--include-accounts` 时，JSON 的 `account` 字段才保留原值。

退出码适合在 CI 或批量授权检测中使用：

| 退出码 | 含义 |
|---:|---|
| `0` | 完成检测，未发现可靠证据 |
| `10` | 发现可稳定复现的枚举差异 |
| `11` | 可能可枚举或可疑时间侧信道 |
| `2` | 证据不足、被限流/验证码/锁定信号阻断 |
| `1` | 参数、模板、文件或其他运行错误 |
| `130` | 用户中断 |

## 安全边界

本工具不会：

- 对密码字典做撞库或爆破；
- 并发打接口；
- 自动绕过验证码、人机验证、IP 限流或账号锁定；
- 对大量真实用户账号进行扫描；
- 隐藏授权确认门槛。
- 在登录/找回密码模式下，还要求显式确认已知账号是测试账号或客户批准可探测的账号。

如果接口的锁定阈值未知，最安全的方式是：

- 只使用甲方创建的测试账号；
- 每个账号只发 1 个固定错误密码请求；
- 增加样本数量时增加测试账号，而不是重复真实账号；
- 对找回密码接口尤其保守，避免触发邮件/短信轰炸。

## 目录结构

```text
account_enum_detector/
  cli.py          # 参数、授权门槛、输出入口
  runner.py       # 安全计划、交错调度、停止条件
  requestor.py    # HTTP/HTTPS/代理、TTFB/total 计时
  payload.py      # 账号生成与 JSON/form/raw 模板
  normalize.py    # 动态响应和响应头归一化
  stats.py        # 无依赖统计检验
  analyzer.py     # 状态/正文/头/时间综合判定
  report.py       # 终端/JSON/Markdown 报告
lab/
  mock_targets.py # 本地安全模拟靶场
tests/
  test_detector.py
examples/
  known_accounts.example.txt
```

## 后续可扩展方向

- 增加可选的原始 HTTP 请求文件（Burp/Repeater 格式）导入；
- 增加多字段账号路径和签名请求模板；
- 增加 HTTP/2 或连接复用传输后端以降低 TLS 抖动；
- 增加更多语言的防护/锁定关键词；
- 在授权实验环境中加入已知正/负样本校准阈值。
