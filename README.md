# 账号枚举差异检测工具

一个仅依赖 Python 标准库的授权安全测试工具，用于比较指定接口对“已知存在账号”和“同形态不存在账号”的响应差异，覆盖：

- HTTP 状态码；
- JSON/HTML/文本响应体、业务 `code/message` 字段、稳定指纹和 Diff；
- 稳定响应头（自动忽略 `Date`、Trace ID 等噪声头，`Set-Cookie` 只比较 Cookie 名）；
- 响应时间的配对统计：中位数、MAD、Cliff’s δ/AUC、Bootstrap 95% CI、配对符号翻转检验；
- 限流、验证码、账号锁定、连续网络错误熔断；
- JSON + Markdown 证据报告，默认脱敏账号和敏感字段。

> 仅可在已获得明确书面授权的系统、范围和时间窗内使用。优先使用专门申请的测试账号；不要用真实员工/用户账号做重复失败登录。本工具不提供验证码绕过、代理池、IP 轮换或锁定绕过能力。

## 1. 为什么默认设计得很保守

账号枚举验证最容易造成的次生风险不是“没测出来”，而是：

1. 对同一个真实账号连续发送错误密码，触发账号锁定；
2. 对找回密码接口连续请求，给真实用户发送大量邮件/短信；
3. 对注册接口提交完整合法表单，真的创建账号；
4. 触发 IP 限流/WAF 后继续请求，导致测试 IP 或租户被封；
5. 把网络抖动、TLS 握手、缓存命中造成的几十毫秒差异误报为时序枚举。

因此工具默认：

- 串行请求，不并发；
- 每次请求间隔 `2s + 0~1.5s` 随机抖动；
- 每个已知账号最多请求 **1 次**；如需重复，显式设置 `--max-requests-per-existing`，硬上限为 5；
- 总请求数默认不超过 40；
- 一个已知账号样本配一个同形态不存在样本，随机决定谁先发送；
- 不自动重试超时请求，因为超时请求可能已被服务端处理；
- 遇到 `423/429/503` 或“验证码/频繁/锁定”等文本立即停止；
- 不跟随 3xx，保留原始状态码和 `Location`；
- 报告默认账号脱敏，密码、Token、Cookie、验证码等字段不写入报告。

没有任何客户端工具能保证“绝对不会触发锁定”。正式测试前仍应向系统负责人确认锁定阈值、限流维度、告警和通知策略，最好将测试账号/来源 IP 加入测试白名单，或在预发/隔离环境复测。

## 2. 快速体验：本地安全靶场

需要 Python 3.10+（代码使用了新版类型注解；实际在 Python 3.15 验证）。无需安装第三方依赖。

终端 A：

```bash
python3 examples/mock_target.py --port 18765
```

终端 B，先空跑检查请求：

```bash
python3 account_enum_detector.py \
  --url http://127.0.0.1:18765/api/message \
  --field username \
  --param password='Dummy-Probe-Password-123!' \
  --existing-file examples/accounts.existing.txt \
  --pairs 8 \
  --dry-run
```

确认请求结构后正式检测：

```bash
python3 account_enum_detector.py \
  --url http://127.0.0.1:18765/api/message \
  --field username \
  --param password='Dummy-Probe-Password-123!' \
  --existing-file examples/accounts.existing.txt \
  --pairs 8 \
  --seed 20261127 \
  --delay 0.02 --jitter 0.05 --start-delay 0 \
  --i-am-authorized \
  --test-accounts-are-dedicated
```

时序侧信道靶场：

```bash
python3 account_enum_detector.py \
  --url http://127.0.0.1:18765/api/timing \
  --field username \
  --param password='Dummy-Probe-Password-123!' \
  --existing-file examples/accounts.existing.txt \
  --pairs 8 \
  --seed 1 \
  --delay 0.02 --jitter 0.05 --start-delay 0 \
  --i-am-authorized \
  --test-accounts-are-dedicated
```

安全统一响应靶场：`/api/safe`。熔断靶场：`/api/blocked`，可验证工具收到 429/验证码文本后只发一个请求即停止。

## 3. 真实接口用法

### 3.1 JSON 登录接口

```bash
python3 account_enum_detector.py \
  --url 'https://target.example.com/api/login' \
  --endpoint-kind login \
  --method POST --format json \
  --field username \
  --param password='A-deliberately-invalid-test-password' \
  --header 'X-Test-Client: authorized-enum-check' \
  --existing-file ./test-accounts.txt \
  --pairs 8 \
  --delay 3 --jitter 2 \
  --i-am-authorized \
  --test-accounts-are-dedicated \
  --json-output ./results/login.json \
  --markdown-output ./results/login.md
```

`test-accounts.txt` 每行一个专门测试账号，`#` 开头为注释。建议准备 8–10 个已确认存在、不会影响真实用户的测试账号；这比反复请求同一个账号更安全，统计功效也更好。

如果只有一个已知测试账号，也可以设置 `--pairs 3 --max-requests-per-existing 3`（硬上限 5）进行少量重复，但这会增加该账号的失败计数，且时序样本独立性更差；优先方案永远是申请多个专用账号。

### 3.2 表单登录

```bash
python3 account_enum_detector.py \
  --url 'https://target.example.com/login' \
  --format form \
  --field username \
  --param password='invalid-test-password' \
  --existing-file ./test-accounts.txt \
  --i-am-authorized \
  --test-accounts-are-dedicated
```

### 3.3 GET 查询参数 / 找回密码接口

```bash
python3 account_enum_detector.py \
  --url 'https://target.example.com/api/password/forgot' \
  --method GET --format query \
  --field email \
  --endpoint-kind password-reset \
  --existing-file ./dedicated-inboxes.txt \
  --pairs 5 \
  --delay 5 --jitter 3 \
  --i-am-authorized \
  --test-accounts-are-dedicated
```

找回密码接口可能真的发送邮件/短信。即使账号属于测试人员，也应控制数量并确认收件箱/短信接收方案。

### 3.4 嵌套 JSON、图形验证码或额外字段

创建 `login-template.json`：

```json
{
  "tenant": "cn",
  "principal": {
    "account": "{{account}}",
    "type": "email"
  },
  "credential": {
    "password": "deliberately-invalid-test-password",
    "captcha": {
      "id": "use-a-valid-captcha-id-if-required",
      "code": "do-not-bypass"
    }
  },
  "device": {
    "fingerprint": "authorized-test-device"
  }
}
```

运行：

```bash
python3 account_enum_detector.py \
  --url 'https://target.example.com/api/v2/auth/login' \
  --format json \
  --body-template-file ./login-template.json \
  --existing-file ./test-accounts.txt \
  --pairs 6 \
  --i-am-authorized \
  --test-accounts-are-dedicated
```

如果接口强制校验一次性验证码，工具不应尝试绕过。更安全的方式是请业务方在测试环境关闭/固定验证码，或提供授权测试通道；否则工具会在识别到“验证码错误/请完成验证码”后熔断。

需要经 Burp 观察请求时，可加：

```bash
--proxy http://127.0.0.1:8080 --insecure
```

`--insecure` 只应在本机代理/授权实验环境使用。

### 3.5 注册接口

注册测试可能创建真实账号。请先构造一个“会在账号可用性检查之后、最终创建之前失败”的模板，例如两次密码不一致、缺少必选协议字段、使用无效测试租户等，并由接口负责人确认不会落库：

```bash
python3 account_enum_detector.py \
  --url 'https://target.example.com/api/register' \
  --endpoint-kind register \
  --body-template-file ./register-validation-only.json \
  --existing-file ./test-accounts.txt \
  --pairs 5 \
  --i-am-authorized \
  --test-accounts-are-dedicated \
  --register-template-cannot-create-account
```

## 4. 不存在样本怎么来

工具支持两种控制样本：

1. **自动同形态生成（默认）**：根据已知账号生成相同长度、相同字符形态和邮箱域名的随机样本。例如 `probe01@example.com` 可能生成 `bqx94@example.com`。手机号/纯数字 ID 不会自动生成，避免随机到真实号码。
2. **显式高可信控制样本**：通过 `--nonexisting` 或 `--nonexisting-file` 提供已确认未注册的账号。对手机号、工号、租户 ID 等强格式标识，建议始终使用显式样本。

如果提供的显式样本数少于 `--pairs`，工具会停止，避免重复使用同一控制样本造成缓存偏差。

## 5. 结论和退出码

报告中的结论代码：

| 退出码 | 结论 | 含义 |
|---:|---|---|
| `0` | `NOT_DETECTED` | 本次样本和统计门槛下未发现稳定差异 |
| `3` | `ENUMERABLE` / `LIKELY_ENUMERABLE` | 高置信确定性差异，或中置信/强时序差异 |
| `4` | `SUSPECTED` / `INCONCLUSIVE` | 有弱信号或样本不足，不能直接确证 |
| `2` | `ABORTED_*` | 触发限流/验证码/锁定/连续网络错误，已中止 |
| `1` | 用法或文件错误 | 未开始或未完成正常分析 |

高置信确定性差异要求至少 3 个存在样本和 3 个不存在样本，并且状态码、稳定响应体字段或非 `Content-Length` 响应头完全/高度稳定分离。

时序高置信门槛较严格：

- 至少 8 个完整配对；
- 配对符号翻转检验 `p < 0.01`；
- Bootstrap 95% 中位数差 CI 不跨 0，且区间低端超过 `--min-timing-effect-ms`（默认 10ms）；
- `|Cliff’s δ| >= 0.60`；
- 至少 75% 配对同向；
- 配对内“存在先请求/不存在先请求”的顺序基本平衡，避免首轮连接/TLS/缓存效应与账号类别混杂；
- 去掉任意一个配对后方向仍稳定。

这是有意保守：几十毫秒差异在公网、HTTPS、WAF、缓存和不同后端连接上很容易不稳定。若工具给出 `SUSPECTED`，应增加专用测试账号、在低延迟授权网络/预发环境复测，并交叉验证响应字段，而不是直接写成“可利用”。

## 6. 建议的人工复核

1. 打开 Markdown 报告中的“稳定不同字段”和 Diff，确认差异不是 `request_id/timestamp` 等动态字段。
2. 用浏览器/Burp 手工重放 2–3 次，确认差异稳定。
3. 间隔一段时间、更换 `--seed` 再跑一次；必要时从另一授权网络位置复测。
4. 对时序问题，确认报告中的顺序漂移、缓存头和 CI；不要只看平均值。
5. 检查是否出现 `429/验证码/锁定`。如果出现，本次结果只能作为中止前线索，不能作为完整证据。
6. 保存 JSON 报告和授权记录，避免报告中加入真实用户敏感信息。

## 7. 报告文件

默认输出：

- `account_enum_report.json`：完整机器可读证据；
- `account_enum_report.md`：适合贴入渗透测试报告的摘要、表格、Diff 和修复建议。

默认账号脱敏。若报告仅保存在受控位置且需要完整账号作为复现证据，可加 `--show-accounts`。密码、敏感请求头、Token/Cookie 类字段仍会脱敏。

## 8. 常见误报来源

- 自动生成的不存在邮箱与已知账号长度/域名不同，触发不同校验分支；本工具已尽量同形态生成，强格式标识仍建议显式样本。
- 一个账号在测试前已被预热或缓存，另一个没有；应随机排序并多次复测。
- TLS 握手和 HTTP 连接复用造成首轮偏慢；可先对同一 origin 发一个无害健康检查请求，或在报告中关注顺序漂移。
- WAF/限流响应本身区分“正常请求”和“高频请求”，不是业务枚举；熔断后不要继续。
- 注册接口的字段校验顺序可能导致非账号字段错误；务必使用只有账号状态不同、其他字段完全一致的模板。

## 9. 修复方向

- 登录失败统一文案、状态码、响应结构、跳转和耗时路径，例如“账号或密码错误”。
- 找回密码统一返回“如果该标识已注册，重置指引已发送”。
- 对不存在用户执行等价哑哈希/计算，降低时序差异。
- 注册/账号可用性检查加入限流、人机校验和监控；避免匿名、高频、细粒度可用性查询。
- 避免简单失败 N 次即永久锁定真实用户；可使用指数延迟、设备/IP/标识组合风控、告警和客服恢复流程。
- 验证码不是唯一修复；验证码实现、复用和绕过问题需要单独评估。

## 10. 项目文件

- `account_enum_detector.py`：主工具，单文件、标准库实现。
- `examples/mock_target.py`：仅监听本机的练习靶场。
- `examples/accounts.existing.txt`：靶场测试账号。
- `examples/login-template.json`：嵌套/自定义请求体模板示例。
