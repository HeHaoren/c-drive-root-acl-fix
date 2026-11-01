# Windows 卷根目录权限修复脚本

修复 Windows 磁盘根目录被授予 `Everyone` / `BUILTIN\Users` 写入权限的问题。

最典型的触发场景：**Clash Verge Rev 更新后 TUN 模式无法使用，服务模式被拒绝**。

---

## 症状

Clash Verge Rev 弹出「服务内核未通过安全检查，已切换到普通模式（Sidecar）」，
右键通知 → 复制 → 粘贴出来是类似这样的内容：

```
verge-mihomo.exe: core path "\\?\C:\" has an untrusted write ACE:
ace_index=4, sid=S-1-5-32-545, type=0, flags=0x03, mask=0x001F01FF, dangerous=0x000C0040
verge-mihomo-alpha.exe: core path "\\?\C:\" has an untrusted write ACE:
ace_index=4, sid=S-1-5-32-545, type=0, flags=0x03, mask=0x001F01FF, dangerous=0x000C0040
```

### 这段报错怎么读

| 字段 | 含义 |
| --- | --- |
| `core path "\\?\C:\"` | 未通过检查的位置是 **C 盘根目录**，`\\?\` 只是 Windows 路径前缀。**不代表软件装在根目录**，服务会一路检查到磁盘根 |
| `sid=S-1-5-32-545` | 触发拦截的账户：`S-1-5-32-545` = `BUILTIN\Users`，`S-1-1-0` = `Everyone`，`S-1-5-11` = `Authenticated Users`，`S-1-5-21-` 开头是本机某个用户/组 |
| `mask=0x001F01FF` | 该账户在根目录上的**有效**权限 = 完全控制 |
| `dangerous=0x000C0040` | 危险位：删除子文件夹及文件 + 更改权限 + 取得所有权 |
| `flags=0x03` | 这条权限会继承给下面所有子目录和文件 |

> 注意：报错里写的是 `Users`，但真正给满权限的常常是 **`Everyone` 完全控制** 那条。
> 因为 Users 组成员同时也是 Everyone 成员，服务算的是有效权限，叠加之后就成了完全控制。
> 所以在「安全」选项卡里只盯着 Users 看是找不出问题的，一定要看 Everyone。

## 为什么会这样

服务模式会以 `SYSTEM` 权限启动内核。如果普通账户也能改内核文件、或替换安装目录及
其上级目录里的文件，其他程序就能借此把权限提升到 SYSTEM。所以服务会检查内核文件和
各级目录的权限，不符合就拒绝启动。

而某些「一键修复权限」教程、优化工具、老游戏/老软件的安装脚本，会给磁盘根目录加上：

```
Everyone      : 完全控制   (继承到所有子对象)
BUILTIN\Users : 修改       (作用于根目录本身)
```

Windows 出厂从来不是这样的。这既是提权漏洞，也会让 Clash Verge Rev 这类做安全检查
的软件直接罢工。

## 脚本做什么

只动**根目录这一层**的 DACL：

| 阶段 | 内容 |
| --- | --- |
| 备份 | 把当前 ACL 存成 SDDL 文本，放在脚本同目录 |
| 删除 | 移除 `Everyone` 和 `BUILTIN\Users` 的全部条目 |
| 重建 | 按 Windows 默认形态重新授予 Users：根目录「读取和执行」+ 子文件夹和文件「修改」（仅继承） |
| 自检 | 修复后重新判定，确认根目录不再对非特权账户可写 |

**不会**递归子目录、**不会** `/reset`、**不会**改所有者、**不会**删除任何文件。
Windows 默认允许 Authenticated Users 在根目录建文件夹、允许 Users 对子目录有修改权限，
这些是正常行为，脚本不会动它们。

## 用法

### 1. 先体检（不需要管理员）

```powershell
powershell -ExecutionPolicy Bypass -File .\Fix-ClashVergeTunACL.ps1 -CheckOnly
```

退出码 `0` = 安全，`1` = 有问题并列出具体条目。也可以看别的盘：

```powershell
powershell -ExecutionPolicy Bypass -File .\Fix-ClashVergeTunACL.ps1 -CheckOnly -Root D:\
```

### 2. 修复（需要管理员）

- 双击 **`Run-Fix-As-Admin.bat`**（会自动申请管理员权限，UAC 点「是」）
- 或者在已提权的 PowerShell 里执行：

```powershell
powershell -ExecutionPolicy Bypass -File .\Fix-ClashVergeTunACL.ps1
```

想先看看会改什么，加 `-WhatIf`（不会真正写入）。修别的盘加 `-Root D:\`。

### 3. 让 Clash Verge Rev 恢复服务模式

1. 托盘图标 → 完全退出 Clash Verge Rev（不是关窗口）
2. 以**普通**身份重新启动
3. 设置 → 服务模式 → 重新安装 / 修复服务，UAC 点「是」
4. 重新打开 TUN

不想改权限的话，官方也提供退路：直接**以管理员身份运行** Clash Verge Rev，
不装服务（Sidecar）也能用 TUN，只是每次都要管理员启动。

## 回滚

脚本同目录下会有 `Root_ACL_backup_<时间戳>.txt`，里面是修改前的 SDDL。
需要还原时在**管理员** PowerShell 里执行（把文件路径换成你的备份）：

```powershell
$sddl = Get-Content .\Root_ACL_backup_ORIGINAL_pre-fix.txt
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetSecurityDescriptorSddlForm($sddl)
Set-Acl -LiteralPath 'C:\' -AclObject $acl
```

## 注意事项

- **不要**对整个 C 盘递归执行权限重置、接管所有权、或删除用户组权限
- **不要**勾选「使用可从此对象继承的权限项目替换所有子对象的权限项目」
- 这些操作会破坏 Windows 和其他软件的权限，严重时系统都起不来
- 修复后 C 盘根目录本身不再允许普通账户直接写入 —— 这是 Windows 的默认状态。
  如果某个工具习惯往 `C:\` 根目录丢文件，它需要以管理员运行；子目录仍然可写
- 磁盘根上若还有指向某个具体账户（非 Everyone/Users）的写入权限，
  脚本会提示 `needs manual review` 并不会自动处理，请在「安全 → 高级」里人工确认

## 参考

- 官方 FAQ：[服务内核未通过安全检查](https://www.clashverge.dev/faq/windows.html#sidecar)
- 适用于 Windows 10 / 11

## 许可

MIT
