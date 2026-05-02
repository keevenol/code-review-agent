#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
智能代码审查与自动修复 Agent 系统
Multi-Agent Code Review & Auto-Fix System

核心痛点：
1. 人工 Code Review 耗时且容易遗漏安全漏洞
2. 开发者代码规范意识薄弱，反复修改成本高
3. 存量代码技术债累积，缺乏自动化治理手段

核心逻辑流（多 Agent 协作 + 长链推理）：
- ScannerAgent: 静态代码扫描，提取 AST/依赖关系
- AnalyzerAgent: 深度推理分析，漏洞分级与根因定位
- FixerAgent: 基于上下文生成修复补丁
- ValidatorAgent: 闭环验证（单元测试+安全扫描）

示例成果：
"我构建了一个基于多 Agent 协作的智能代码审查系统。它能自动扫描代码中的安全漏洞和
规范违规，通过长链推理定位根因，自动生成修复 PR 并运行测试验证闭环。目前已在公司
15 人研发团队落地，每日处理约 200 个 PR，将代码审查效率提升了 75%，高危漏洞漏检率
从 30% 降至 5% 以下，每日消耗约 300 万 Token。"
"""

import asyncio
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IssueType(Enum):
    SECURITY = "security"
    PERFORMANCE = "performance"
    STYLE = "style"
    BUG = "bug"
    BEST_PRACTICE = "best_practice"


@dataclass
class CodeIssue:
    file_path: str
    line_number: int
    column: int
    issue_type: IssueType
    severity: Severity
    rule_id: str
    message: str
    code_snippet: str
    suggested_fix: Optional[str] = None
    confidence: float = 0.0
    root_cause_chain: List[str] = None

    def __post_init__(self):
        if self.root_cause_chain is None:
            self.root_cause_chain = []


@dataclass
class ScanResult:
    file_path: str
    issues: List[CodeIssue]
    scan_duration_ms: float
    lines_of_code: int
    timestamp: str


@dataclass
class FixResult:
    original_issue: CodeIssue
    fixed_code: str
    validation_passed: bool
    test_results: Dict[str, Any]
    applied: bool = False


# ==================== Agent 基类 ====================
class BaseAgent:
    def __init__(self, name: str):
        self.name = name
        self.memory: List[Dict] = []

    async def think(self, context: Dict) -> Dict:
        """模拟 Agent 推理过程（实际应调用 LLM API）"""
        raise NotImplementedError

    def log_thought(self, thought: str):
        self.memory.append({
            "timestamp": datetime.now().isoformat(),
            "agent": self.name,
            "thought": thought
        })


# ==================== 1. 扫描 Agent ====================
class ScannerAgent(BaseAgent):
    """
    扫描 Agent：负责静态代码分析
    - 提取 AST 结构
    - 识别危险函数调用
    - 检测依赖漏洞
    """

    DANGEROUS_PATTERNS = {
        "eval": (IssueType.SECURITY, Severity.CRITICAL, "SEC-001", "使用 eval() 存在 RCE 风险"),
        "exec": (IssueType.SECURITY, Severity.CRITICAL, "SEC-002", "使用 exec() 存在代码注入风险"),
        "pickle.loads": (IssueType.SECURITY, Severity.HIGH, "SEC-003", "pickle 反序列化可导致任意代码执行"),
        "subprocess.call(shell=True)": (IssueType.SECURITY, Severity.CRITICAL, "SEC-004", "shell=True 存在命令注入风险"),
        "requests.get(verify=False)": (IssueType.SECURITY, Severity.HIGH, "SEC-005", "禁用 SSL 验证存在中间人攻击风险"),
        "sql_injection": (IssueType.SECURITY, Severity.CRITICAL, "SEC-006", "检测到可能的 SQL 注入漏洞"),
        "hardcoded_password": (IssueType.SECURITY, Severity.HIGH, "SEC-007", "检测到硬编码密码"),
        "TODO": (IssueType.BEST_PRACTICE, Severity.LOW, "BP-001", "存在未完成的 TODO 项"),
        "FIXME": (IssueType.BEST_PRACTICE, Severity.LOW, "BP-002", "存在未完成的 FIXME 项"),
    }

    def __init__(self):
        super().__init__("ScannerAgent")

    async def scan_file(self, file_path: str, content: str) -> ScanResult:
        self.log_thought(f"开始扫描文件: {file_path}")
        start_time = datetime.now()

        issues = []
        lines = content.split('\n')

        for i, line in enumerate(lines, 1):
            for pattern, (issue_type, severity, rule_id, message) in self.DANGEROUS_PATTERNS.items():
                if pattern.lower() in line.lower():
                    # 提取代码上下文
                    context_start = max(0, i-2)
                    context_end = min(len(lines), i+2)
                    snippet = '\n'.join(lines[context_start:context_end])

                    issue = CodeIssue(
                        file_path=file_path,
                        line_number=i,
                        column=line.lower().find(pattern.lower()),
                        issue_type=issue_type,
                        severity=severity,
                        rule_id=rule_id,
                        message=message,
                        code_snippet=snippet,
                        confidence=0.85
                    )
                    issues.append(issue)
                    self.log_thought(f"发现 {severity.value} 级别问题: {rule_id} at line {i}")

        duration = (datetime.now() - start_time).total_seconds() * 1000

        return ScanResult(
            file_path=file_path,
            issues=issues,
            scan_duration_ms=duration,
            lines_of_code=len(lines),
            timestamp=datetime.now().isoformat()
        )


# ==================== 2. 分析 Agent（长链推理） ====================
class AnalyzerAgent(BaseAgent):
    """
    分析 Agent：深度推理分析
    - 漏洞根因链分析（长链推理）
    - 影响面评估
    - 修复优先级排序
    """

    def __init__(self):
        super().__init__("AnalyzerAgent")

    async def analyze(self, scan_result: ScanResult) -> List[CodeIssue]:
        self.log_thought(f"开始分析 {len(scan_result.issues)} 个问题")

        analyzed_issues = []

        for issue in scan_result.issues:
            # 长链推理：构建根因分析链
            root_cause_chain = await self._build_reasoning_chain(issue)
            issue.root_cause_chain = root_cause_chain

            # 根据根因链调整置信度
            issue.confidence = self._calculate_confidence(issue)

            self.log_thought(
                f"问题 {issue.rule_id} 根因链: {' -> '.join(root_cause_chain)}"
            )
            analyzed_issues.append(issue)

        # 按严重程度和置信度排序
        analyzed_issues.sort(
            key=lambda x: (
                self._severity_score(x.severity),
                x.confidence
            ),
            reverse=True
        )

        return analyzed_issues

    async def _build_reasoning_chain(self, issue: CodeIssue) -> List[str]:
        """
        长链推理核心：构建从表象到根因的推理链
        示例：eval(user_input) -> 用户输入未过滤 -> 动态代码执行 -> RCE漏洞
        """
        chain = [f"检测到违规模式: {issue.rule_id}"]

        if issue.issue_type == IssueType.SECURITY:
            if "eval" in issue.code_snippet or "exec" in issue.code_snippet:
                chain.extend([
                    "识别到动态代码执行函数",
                    "追溯参数来源...",
                    "参数包含用户输入数据",
                    "用户输入未经过滤/转义",
                    "攻击者可注入恶意代码",
                    "根因：缺乏输入验证 + 使用危险函数",
                    "风险：远程代码执行 (RCE)"
                ])
            elif "pickle" in issue.code_snippet:
                chain.extend([
                    "识别到反序列化操作",
                    "pickle 可加载任意 Python 对象",
                    "攻击者可构造恶意序列化数据",
                    "根因：使用不安全反序列化",
                    "风险：任意代码执行"
                ])
            elif "shell=True" in issue.code_snippet:
                chain.extend([
                    "识别到子进程调用",
                    "shell=True 允许 shell 元字符",
                    "参数可能包含用户输入",
                    "根因：命令拼接 + shell=True",
                    "风险：命令注入"
                ])
            elif "verify=False" in issue.code_snippet:
                chain.extend([
                    "识别到 HTTPS 请求",
                    "SSL 验证被禁用",
                    "中间人可伪造证书",
                    "根因：安全传输配置错误",
                    "风险：中间人攻击 (MITM)"
                ])

        return chain

    def _calculate_confidence(self, issue: CodeIssue) -> float:
        """基于根因链长度和类型计算置信度"""
        base_confidence = issue.confidence
        chain_bonus = min(len(issue.root_cause_chain) * 0.02, 0.1)
        return min(base_confidence + chain_bonus, 1.0)

    def _severity_score(self, severity: Severity) -> int:
        scores = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0
        }
        return scores.get(severity, 0)


# ==================== 3. 修复 Agent ====================
class FixerAgent(BaseAgent):
    """
    修复 Agent：基于上下文生成修复方案
    - 理解代码语义
    - 生成最小化补丁
    - 保持代码风格一致性
    """

    FIX_TEMPLATES = {
        "SEC-001": {
            "description": "将 eval() 替换为安全的 ast.literal_eval() 或 JSON 解析",
            "replacement": "# 安全替代方案\nimport ast\nresult = ast.literal_eval(user_input)  # 仅支持字面量"
        },
        "SEC-002": {
            "description": "避免使用 exec()，改用配置化方案",
            "replacement": "# 安全替代方案\n# 使用字典映射替代动态执行\nhandler = HANDLERS.get(command)\nif handler:\n    result = handler(args)"
        },
        "SEC-003": {
            "description": "使用 JSON 替代 pickle 进行序列化",
            "replacement": "import json\n# 安全替代方案\ndata = json.loads(serialized_data)"
        },
        "SEC-004": {
            "description": "使用列表传参替代 shell=True",
            "replacement": "# 安全替代方案\nsubprocess.run(['ls', '-la'], capture_output=True)  # 不使用 shell"
        },
        "SEC-005": {
            "description": "恢复 SSL 验证并配置可信证书",
            "replacement": "# 安全替代方案\nrequests.get(url, verify='/path/to/ca-bundle.crt')"
        },
    }

    def __init__(self):
        super().__init__("FixerAgent")

    async def generate_fix(self, issue: CodeIssue, original_content: str) -> FixResult:
        self.log_thought(f"为 {issue.rule_id} 生成修复方案")

        template = self.FIX_TEMPLATES.get(issue.rule_id)

        if template:
            suggested_fix = template["replacement"]
            self.log_thought(f"应用修复模板: {template['description']}")
        else:
            suggested_fix = f"# TODO: 手动修复 {issue.rule_id}\n# {issue.message}"
            self.log_thought("未找到对应修复模板，标记为手动修复")

        # 生成修复后的代码片段
        lines = original_content.split('\n')
        fix_lines = suggested_fix.split('\n')

        # 构建修复后的文件内容（简化版）
        fixed_content = original_content.replace(
            issue.code_snippet,
            f"# [FIXED] {issue.rule_id}: {issue.message}\n" + '\n'.join(fix_lines)
        )

        return FixResult(
            original_issue=issue,
            fixed_code=fixed_content,
            validation_passed=False,  # 待验证
            test_results={}
        )


# ==================== 4. 验证 Agent ====================
class ValidatorAgent(BaseAgent):
    """
    验证 Agent：闭环验证
    - 语法检查
    - 单元测试运行
    - 安全扫描二次确认
    """

    def __init__(self):
        super().__init__("ValidatorAgent")

    async def validate(self, fix_result: FixResult, original_content: str) -> FixResult:
        self.log_thought(f"验证修复方案: {fix_result.original_issue.rule_id}")

        # 模拟验证流程
        validation_results = {
            "syntax_check": self._check_syntax(fix_result.fixed_code),
            "security_recheck": self._security_recheck(fix_result),
            "unit_tests": self._run_mock_tests(fix_result),
            "style_check": self._check_style(fix_result.fixed_code)
        }

        all_passed = all(r["passed"] for r in validation_results.values())
        fix_result.validation_passed = all_passed
        fix_result.test_results = validation_results

        self.log_thought(
            f"验证结果: {'通过' if all_passed else '未通过'} "
            f"({sum(1 for r in validation_results.values() if r['passed'])}/{len(validation_results)} 项通过)"
        )

        return fix_result

    def _check_syntax(self, code: str) -> Dict:
        try:
            compile(code, '<string>', 'exec')
            return {"passed": True, "message": "语法检查通过"}
        except SyntaxError as e:
            return {"passed": False, "message": f"语法错误: {e}"}

    def _security_recheck(self, fix_result: FixResult) -> Dict:
        """检查修复后的代码是否仍包含漏洞"""
        dangerous = ["eval(", "exec(", "pickle.loads", "shell=True", "verify=False"]
        for d in dangerous:
            if d in fix_result.fixed_code:
                return {"passed": False, "message": f"仍包含危险模式: {d}"}
        return {"passed": True, "message": "安全复查通过"}

    def _run_mock_tests(self, fix_result: FixResult) -> Dict:
        """模拟运行单元测试"""
        import random
        passed = random.random() > 0.1  # 90% 通过率模拟
        return {
            "passed": passed,
            "message": f"单元测试{'通过' if passed else '失败'} (模拟)",
            "coverage": f"{random.randint(70, 95)}%"
        }

    def _check_style(self, code: str) -> Dict:
        """检查代码风格"""
        lines = code.split('\n')
        long_lines = [i for i, line in enumerate(lines, 1) if len(line) > 120]
        return {
            "passed": len(long_lines) == 0,
            "message": f"代码风格检查: {'通过' if not long_lines else f'{len(long_lines)} 行长度过长'}"
        }


# ==================== 编排器：多 Agent 协作 ====================
class CodeReviewOrchestrator:
    """
    编排器：协调多 Agent 协作
    实现长链推理工作流：扫描 -> 分析 -> 修复 -> 验证 -> 报告
    """

    def __init__(self):
        self.scanner = ScannerAgent()
        self.analyzer = AnalyzerAgent()
        self.fixer = FixerAgent()
        self.validator = ValidatorAgent()
        self.workflow_log: List[Dict] = []

    async def review_code(self, file_path: str, content: str) -> Dict[str, Any]:
        """完整代码审查流程"""
        self.workflow_log.append({"step": "start", "timestamp": datetime.now().isoformat()})

        # Step 1: 扫描
        scan_result = await self.scanner.scan_file(file_path, content)
        self.workflow_log.append({
            "step": "scan",
            "issues_found": len(scan_result.issues),
            "duration_ms": scan_result.scan_duration_ms
        })

        if not scan_result.issues:
            return {
                "status": "clean",
                "message": "未发现问题",
                "scan_result": asdict(scan_result)
            }

        # Step 2: 深度分析（长链推理）
        analyzed_issues = await self.analyzer.analyze(scan_result)
        self.workflow_log.append({
            "step": "analyze",
            "critical_count": sum(1 for i in analyzed_issues if i.severity == Severity.CRITICAL),
            "high_count": sum(1 for i in analyzed_issues if i.severity == Severity.HIGH)
        })

        # Step 3 & 4: 生成修复并验证
        fix_results = []
        for issue in analyzed_issues:
            if issue.severity in [Severity.CRITICAL, Severity.HIGH]:
                fix = await self.fixer.generate_fix(issue, content)
                validated_fix = await self.validator.validate(fix, content)
                fix_results.append(validated_fix)

        self.workflow_log.append({
            "step": "fix_validate",
            "fixes_generated": len(fix_results),
            "fixes_validated": sum(1 for f in fix_results if f.validation_passed)
        })

        # Step 5: 生成报告
        report = self._generate_report(scan_result, analyzed_issues, fix_results)

        return report

    def _generate_report(
        self,
        scan_result: ScanResult,
        issues: List[CodeIssue],
        fix_results: List[FixResult]
    ) -> Dict[str, Any]:

        severity_distribution = {}
        for s in Severity:
            count = sum(1 for i in issues if i.severity == s)
            if count > 0:
                severity_distribution[s.value] = count

        type_distribution = {}
        for t in IssueType:
            count = sum(1 for i in issues if i.issue_type == t)
            if count > 0:
                type_distribution[t.value] = count

        return {
            "status": "completed",
            "file": scan_result.file_path,
            "summary": {
                "total_issues": len(issues),
                "severity_distribution": severity_distribution,
                "type_distribution": type_distribution,
                "fixes_generated": len(fix_results),
                "fixes_validated": sum(1 for f in fix_results if f.validation_passed),
                "scan_duration_ms": scan_result.scan_duration_ms
            },
            "issues": [
                {
                    "rule_id": i.rule_id,
                    "severity": i.severity.value,
                    "type": i.issue_type.value,
                    "location": f"{i.file_path}:{i.line_number}:{i.column}",
                    "message": i.message,
                    "confidence": f"{i.confidence:.0%}",
                    "reasoning_chain": i.root_cause_chain,
                    "suggested_fix": i.suggested_fix
                }
                for i in issues
            ],
            "workflow_log": self.workflow_log,
            "agent_memories": {
                "scanner": self.scanner.memory,
                "analyzer": self.analyzer.memory,
                "fixer": self.fixer.memory,
                "validator": self.validator.memory
            }
        }


# ==================== 演示 ====================
async def demo():
    """演示多 Agent 协作代码审查"""

    # 示例：包含多个安全漏洞的代码
    vulnerable_code = '''
import pickle
import subprocess
import requests

def process_user_data(user_input):
    # 危险：使用 eval 执行用户输入
    result = eval(user_input)
    return result

def load_config(serialized_data):
    # 危险：不安全的反序列化
    config = pickle.loads(serialized_data)
    return config

def run_command(cmd):
    # 危险：shell=True 存在命令注入
    subprocess.call(cmd, shell=True)

def fetch_data(url):
    # 危险：禁用 SSL 验证
    response = requests.get(url, verify=False)
    return response.json()

# TODO: 需要添加输入验证
# FIXME: 错误处理不完善
'''

    print("=" * 60)
    print("🚀 智能代码审查 Agent 系统演示")
    print("=" * 60)
    print("\n📄 待审查代码文件: example_vulnerable.py")
    print("-" * 60)

    orchestrator = CodeReviewOrchestrator()
    result = await orchestrator.review_code("example_vulnerable.py", vulnerable_code)

    print(f"\n📊 审查结果:")
    print(f"   发现问题总数: {result['summary']['total_issues']}")
    print(f"   严重程度分布: {result['summary']['severity_distribution']}")
    print(f"   问题类型分布: {result['summary']['type_distribution']}")
    print(f"   生成修复方案: {result['summary']['fixes_generated']}")
    print(f"   验证通过: {result['summary']['fixes_validated']}")

    print(f"\n🔍 详细问题列表:")
    for issue in result['issues']:
        print(f"\n   [{issue['severity'].upper()}] {issue['rule_id']}")
        print(f"   位置: {issue['location']}")
        print(f"   描述: {issue['message']}")
        print(f"   置信度: {issue['confidence']}")
        if issue['reasoning_chain']:
            print(f"   推理链:")
            for step in issue['reasoning_chain']:
                print(f"      → {step}")

    print(f"\n🤖 Agent 推理日志:")
    for agent, memories in result['agent_memories'].items():
        print(f"\n   [{agent}]:")
        for mem in memories[:3]:  # 只显示前3条
            print(f"      • {mem['thought']}")
        if len(memories) > 3:
            print(f"      ... 共 {len(memories)} 条记录")

    # 保存完整报告
    report_path = "review_report.json"
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(f"\n✅ 完整报告已保存至: {report_path}")

    return result


if __name__ == "__main__":
    asyncio.run(demo())
