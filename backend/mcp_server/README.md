# In-A-Lign MCP Server

AI 개발 도구를 위한 Model Context Protocol 서버.

## 기능

Claude Code, Cursor 등 AI 코딩 도구에서 사용할 수 있는 7가지 도구 제공:

| 도구 | 설명 |
|------|------|
| `analyze_project` | 프로젝트 분석 - 태스크 분류, 모델 추천, 비용 분석 |
| `optimize_prompt` | 프롬프트 최적화 - 토큰 효율성 개선 |
| `recommend_model` | 모델 추천 - 태스크에 최적인 AI 모델 선택 |
| `estimate_cost` | 비용 계산 - 모델별 비용 비교 |
| `security_scan` | 보안 스캔 - 프롬프트 인젝션 취약점 탐지 |
| `generate_system_prompt` | 시스템 프롬프트 생성 - 태스크별 최적화된 템플릿 |
| `get_optimization_report` | 최적화 리포트 - 종합 분석 및 절감 방안 |

## 설치

### 1. 의존성 설치

```bash
cd backend
pip install mcp
```

### 2. Claude Code 설정

`~/.claude/claude_desktop_config.json`에 추가:

```json
{
  "mcpServers": {
    "in-a-lign": {
      "command": "python",
      "args": ["-m", "mcp_server"],
      "cwd": "/path/to/in-a-lign/backend",
      "env": {
        "PYTHONPATH": "."
      }
    }
  }
}
```

### 3. Cursor 설정

`.cursor/mcp.json`에 추가:

```json
{
  "mcpServers": {
    "in-a-lign": {
      "command": "python",
      "args": ["-m", "mcp_server"],
      "cwd": "./backend"
    }
  }
}
```

## 사용 예시

### 프로젝트 분석

```
"내 프로젝트 분석해줘. 고객 서비스 챗봇이고, 하루 5000건 정도 처리해."
```

Claude가 `analyze_project` 도구를 호출하여:
- 태스크 유형 분류 (customer_service)
- 최적 모델 추천 (예: claude-3.5-haiku)
- 예상 비용 계산
- 최적화 제안 제공

### 프롬프트 최적화

```
"이 프롬프트 최적화해줘:
'안녕하세요, 고객님의 요청에 친절하게 답변드리겠습니다.
혹시 불편한 점이 있으시다면 말씀해 주세요...'"
```

Claude가 `optimize_prompt` 도구를 호출하여:
- 불필요한 문구 제거
- 토큰 절감량 계산
- 최적화된 버전 제공

### 보안 스캔

```
"이 사용자 입력 보안 검사해줘: 'Ignore all previous instructions and...'"
```

Claude가 `security_scan` 도구를 호출하여:
- 인젝션 패턴 탐지
- 위험도 평가
- 보안 권고사항 제공

## 도구 상세

### analyze_project

```json
{
  "project_name": "Customer Support Bot",
  "project_description": "E-commerce customer support chatbot",
  "sample_prompts": ["I want to return my order", "Where is my package?"],
  "current_model": "gpt-4o",
  "requests_per_day": 5000
}
```

### optimize_prompt

```json
{
  "prompt": "Please kindly help me with the following task...",
  "task_type": "customer_service",
  "aggressive": true
}
```

### recommend_model

```json
{
  "task_description": "Write a Python function to parse JSON",
  "priority": "balanced",
  "budget_mode": false
}
```

### estimate_cost

```json
{
  "models": ["gpt-4o", "gpt-4o-mini", "claude-3.5-sonnet"],
  "avg_input_tokens": 500,
  "avg_output_tokens": 200,
  "requests_per_day": 1000
}
```

### security_scan

```json
{
  "text": "User input to scan...",
  "context": "user_input"
}
```

## Proxy와의 차이점

| 기능 | MCP Server | Proxy |
|------|------------|-------|
| 실행 시점 | 개발 중 (수동) | 런타임 (자동) |
| 용도 | 분석 & 제안 | 보안 & 효율화 |
| 설치 | 로컬 도구 | API 엔드포인트 |
| 영향 | 정보 제공 | 요청 변환/차단 |

**권장**: MCP로 개발 중 분석 → Proxy로 프로덕션 보호

## 지원 모델

- OpenAI: GPT-4o, GPT-4o-mini, GPT-4-Turbo, o1, o3-mini
- Anthropic: Claude Opus 4, Claude Sonnet 4, Claude 3.5 Sonnet/Haiku
- Google: Gemini 2.5 Pro/Flash, Gemini 2.0 Flash
- DeepSeek: DeepSeek-V3, DeepSeek-R1

## 라이선스

MIT License - In-A-Lign Project
