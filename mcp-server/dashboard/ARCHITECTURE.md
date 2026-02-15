# InALign Dashboard — UX Architecture Document
## Palantir Foundry + LangSmith Observability 기반 설계

---

## 1. Palantir Foundry Data Lineage 분석

### 1.1 그래프 캔버스 기본 구성
- **메인 캔버스**: 전체 화면 DAG(Directed Acyclic Graph) — 노드 확장/축소 가능
- **좌측 Search Helper Panel**: 리소스 검색 → 노드 추가
- **우측 Detail Panel**: 선택된 노드의 메타데이터, 프리뷰, 빌드 이력
- **상단 Toolbar**: 확대/축소, 레이아웃 변경(계층/수직/수평/색상 그룹별), 저장/공유
- **하단 Build Timeline**: 시간축 히스토그램 — 빌드 이력 시각화

### 1.2 노드 색상 코딩 (Automatic Coloring Options)
| 옵션 | 설명 |
|------|------|
| Resource Type | 데이터셋, 오브젝트, 트랜스폼 등 타입별 색상 |
| Build Status | 성공(green), 실패(red), 진행중(blue), 미빌드(gray) |
| Staleness | 최신(green) → 오래됨(amber) → 매우 오래됨(red) |
| Custom | 사용자 지정 색상 그룹 |

### 1.3 그래프 상호작용 패턴
1. **노드 Expand** — 좌/우 화살표 클릭 → 부모/자식 노드 로드
2. **Common Ancestors** — 선택 노드들의 공통 조상 찾기
3. **Path Finding** — 두 노드 사이 최단 경로 하이라이트
4. **Multi-select** — Shift+클릭으로 다중 선택 → 일괄 레이아웃 적용
5. **Context Menu** — 우클릭 → 빌드/스케줄/프리뷰/권한 확인

### 1.4 InALign 매핑
| Palantir 개념 | InALign 대응 |
|---------------|-------------|
| Dataset Node | Entity (파일/URL/시크릿) |
| Transform Node | Activity (ToolCall) |
| Build Status | Risk Level (critical/high/medium/low) |
| Data Pipeline | 에이전트 행동 체인 (causal chain) |
| Path Finding | .env → curl 호출 경로 추적 |
| Staleness | Sensitivity Classification |

---

## 2. LangSmith Observability UI 분석

### 2.1 전체 레이아웃
- **좌측 Nav**: Projects / Datasets / Annotation Queues / Dashboards
- **상단 Filter Bar**: 프로젝트 선택, 시간 범위, 태그 필터, 검색
- **메인 영역**: 트레이스 테이블 (sortable columns)
- **드릴다운**: 행 클릭 → Trace Detail 페이지

### 2.2 Trace Detail 페이지
- **좌측 Run Tree** (계층 구조):
  ```
  ├─ Chain (root)
  │  ├─ LLM Call (GPT-4)
  │  ├─ Tool: SearchAPI
  │  │  └─ HTTP Request
  │  └─ LLM Call (GPT-4)
  ```
- **우측 Detail Panel** (탭 구조):
  - **Input**: 원본 입력 데이터
  - **Output**: 결과 데이터
  - **Metadata**: 모델, 토큰, 레이턴시, 태그
  - **Feedback**: 평가 점수, 어노테이션

### 2.3 Dashboard Metrics
- Metric Cards (P50/P95 latency, error rate, token usage)
- Time-series Charts (volume, latency, cost over time)
- Drill-down: 차트 클릭 → 해당 시간대 트레이스 필터링

### 2.4 InALign 매핑
| LangSmith 개념 | InALign 대응 |
|----------------|-------------|
| Trace | 세션 (provenance chain) |
| Run | 개별 이벤트 (tool_call, message 등) |
| Run Tree | Timeline 탭 계층 뷰 |
| Input/Output | tool_input / tool_result |
| Metadata | provenance hash, timestamp, sensitivity |
| Dashboard Metrics | Risk score, OWASP, Compliance |

---

## 3. InALign IA (Information Architecture) 설계

### 3.1 탭 구조 (좌측 Sidebar)
```
IA
├── Overview        — 전체 에이전트/세션 리스크 요약
├── Sessions        — 세션 리스트 + 개별 세션 상세
│   └── Session Detail (7탭)
│       ├── Overview
│       ├── Trace Tree    ← LangSmith Run Tree 스타일
│       ├── Provenance    ← 해시 체인 뷰
│       ├── Security      ← MITRE ATT&CK 매핑
│       ├── Data Flows    ← Palantir Lineage 스타일 그래프
│       ├── Governance    ← OWASP/EU AI Act/Drift
│       └── AI Analysis   ← LLM 분석
├── Security        — 크로스세션 리스크 매트릭스
└── (Future) Policies — 정책 위반 요약
```

### 3.2 Overview 페이지
**상단 Filter Bar**: Time range, Risk level, Agent filter
**Metric Cards Row**: (Palantir stat card + LangSmith metric card 혼합)
- Risk Score (게이지), Chain Integrity, OWASP Score, Sessions Count, Drift Status
**중앙**: Risk trend chart (time-series) + Event distribution
**하단**: Recent sessions table with risk indicators

### 3.3 Sessions 페이지
**상단**: Search + Filters (risk level, has_findings, time range)
**테이블**: Session ID, Time, Records, Risk Score, Status, Chain Valid
**빈 세션 필터**: "Show empty sessions" 토글 (기본: OFF)

### 3.4 Session Detail — Trace Tree 탭 (LangSmith 스타일)
**좌측 (40%)**: Run Tree — 계층적 이벤트 트리
```
├── User Input "파일 읽어줘"
│   ├── Thinking (350 chars)
│   ├── Tool: Read(/etc/passwd) ⚠️
│   │   └── Result: [content...]
│   ├── Tool: Bash(curl http://...) 🔴
│   │   └── Result: [200 OK]
│   └── Assistant Response
```
**우측 (60%)**: Detail Panel (탭: Input / Output / Metadata / Risk)

### 3.5 Session Detail — Data Flows 탭 (Palantir Lineage 스타일)
**전체 화면 Graph Canvas**:
- 노드 타입별 표현:
  | 타입 | 모양 | 색상 | 크기 |
  |------|------|------|------|
  | Agent | 원형 | Indigo #6366f1 | L |
  | Session | 사각형(둥근) | Violet #8b5cf6 | L |
  | ToolCall/Activity | 사각형 | Blue #3b82f6 | M |
  | Entity (file) | 다이아몬드 | Emerald #10b981 | M |
  | Entity (URL) | 다이아몬드 | Cyan #06b6d4 | M |
  | Entity (secret) | 다이아몬드 | Red #ef4444 | M |
  | Decision | 육각형 | Amber #f59e0b | S |
  | Risk | 삼각형 | Red #ef4444 | S |

- **Risk-based coloring**: 노드 보더 색상으로 sensitivity 표시
  - CRITICAL: red glow
  - HIGH: orange border
  - MEDIUM: amber border
  - LOW: default

**우측 Panel**: 선택 노드 상세 (attrs, connections, risk)
**상단 Toolbar**: Zoom, Layout(dagre/force/radial), Path finder, Risk filter
**하단**: Path explanation bar ("Entity .env → ToolCall Read → ToolCall Bash(curl) → Entity http://evil.com")

---

## 4. 디자인 시스템 (Palantir Blueprint Dark 기반)

### 4.1 Color Palette
```
// Background layers (Palantir dark 5단계)
bg-app:     #0d1117    (GitHub dark와 유사)
bg-surface: #161b22    (카드/패널 배경)
bg-raised:  #1c2333    (elevated surface)
bg-overlay: #21283b    (모달/드롭다운)
bg-input:   #0d1117    (인풋 필드)

// Borders (Blueprint 스타일)
border-default:  rgba(255,255,255,0.08)
border-hover:    rgba(255,255,255,0.15)
border-focus:    rgba(99,102,241,0.5)

// Text (4단계 hierarchy)
text-primary:    #e6edf3    (제목, 강조)
text-secondary:  #8b949e    (본문)
text-tertiary:   #6e7681    (부가 정보)
text-quaternary: #484f58    (비활성)

// Intent colors (Blueprint 패턴)
intent-primary:  #6366f1    (Indigo — 브랜드)
intent-success:  #10b981    (Emerald)
intent-warning:  #f59e0b    (Amber)
intent-danger:   #ef4444    (Red)
intent-info:     #06b6d4    (Cyan)

// Risk gradient
risk-critical:   #ef4444
risk-high:       #f97316
risk-medium:     #eab308
risk-low:        #10b981
```

### 4.2 Typography
```
font-sans:  'Inter', -apple-system, sans-serif
font-mono:  'JetBrains Mono', 'SF Mono', monospace

// Scale (Palantir 패턴 — 작은 사이즈 선호)
text-xl:    18px / 700    (페이지 제목)
text-lg:    15px / 600    (섹션 제목)
text-md:    13px / 400    (본문)
text-sm:    12px / 400    (보조 텍스트)
text-xs:    11px / 500    (라벨, 배지)
text-xxs:   10px / 400    (해시, 부가 정보)
text-micro: 9px  / 500    (상태 표시)
```

### 4.3 Component Styles
```
// Card (Blueprint elevation 패턴)
card: {
  background: bg-surface,
  border: 1px solid border-default,
  borderRadius: 8px,
  boxShadow: '0 1px 3px rgba(0,0,0,0.12), 0 1px 2px rgba(0,0,0,0.24)',
}

// Table (Palantir dense table 패턴)
table-header: {
  background: bg-raised,
  fontSize: 10px,
  textTransform: uppercase,
  letterSpacing: '0.05em',
  color: text-tertiary,
}
table-row: {
  borderBottom: '1px solid rgba(255,255,255,0.04)',
  fontSize: 13px,
  padding: '8px 12px',
}
table-row-hover: {
  background: 'rgba(255,255,255,0.02)',
}

// Badge (Intent-colored)
badge: {
  fontSize: 10px,
  padding: '2px 8px',
  borderRadius: 4px,
  fontWeight: 600,
  letterSpacing: '0.03em',
}

// Input (Blueprint dark input)
input: {
  background: bg-input,
  border: '1px solid rgba(255,255,255,0.1)',
  borderRadius: 6px,
  fontSize: 13px,
  color: text-primary,
}
input-focus: {
  borderColor: intent-primary,
  boxShadow: '0 0 0 2px rgba(99,102,241,0.2)',
}

// Button
button-primary: {
  background: 'linear-gradient(135deg, #6366f1, #4f46e5)',
  color: white,
  fontSize: 12px,
  padding: '6px 14px',
  borderRadius: 6px,
}
button-ghost: {
  background: 'transparent',
  border: '1px solid rgba(255,255,255,0.08)',
  color: text-secondary,
}
```

---

## 5. 핵심 컴포넌트 카탈로그

### 5.1 `<Layout>` — 앱 Shell
```
Props: { children }
구조:
  ┌─────────────────────────────────┐
  │ Sidebar (56px)  │  Main Content │
  │ ┌─ Logo ─────┐ │               │
  │ │ IA InALign  │ │               │
  │ ├─ Nav ──────┤ │               │
  │ │ Dashboard   │ │               │
  │ │ Sessions    │ │               │
  │ │ Security    │ │               │
  │ ├─ Footer ───┤ │               │
  │ │ Sync / Ver  │ │               │
  │ └────────────┘ │               │
  └─────────────────────────────────┘
참고: Palantir 좌측 Nav + LangSmith Project Selector
```

### 5.2 `<RiskGauge>` — 원형 리스크 게이지
```
Props: { score: number, level: string }
구조: SVG 원형 프로그레스 + 중앙 숫자
색상: risk gradient 기반 stroke color + glow
참고: Palantir Build Status 게이지
```

### 5.3 `<MetricCard>` — 요약 메트릭 카드
```
Props: { label, value, trend?, intent?, icon? }
구조: 상단 라벨 (micro text) → 값 (lg font) → 하단 트렌드/배지
참고: LangSmith P50/P95 카드 스타일
```

### 5.4 `<TraceTree>` — LangSmith Run Tree 스타일
```
Props: { events: Event[], onSelect: (event) => void }
구조: 재귀적 트리 — user→thinking→tool_call→result 계층
아이콘: 타입별 (User=person, Bot=bot, Tool=terminal, Brain=thinking)
하이라이트: suspicious 이벤트 red background
참고: LangSmith Trace Detail 좌측 패널
```

### 5.5 `<EventDetailPanel>` — 이벤트 상세 패널
```
Props: { event: Event }
탭: Input / Output / Metadata / Risk
구조:
  ┌─ Tab Bar ──────────────┐
  │ Input  Output  Meta    │
  ├────────────────────────┤
  │ Code block (JSON)      │
  │ with syntax highlight  │
  ├────────────────────────┤
  │ Hash: abc123...        │
  │ Timestamp: ...         │
  └────────────────────────┘
참고: LangSmith Run Detail 우측 패널
```

### 5.6 `<LineageGraph>` — Palantir Data Lineage 스타일
```
Props: { nodes, edges, selectedNode, onNodeSelect }
구조:
  ┌─ Toolbar ──────────────────────┐
  │ Zoom │ Layout │ Path │ Filter  │
  ├─ Canvas ───────────┬─ Panel ──┤
  │                     │ Details  │
  │  [Agent]            │ ─ Type  │
  │    ↓                │ ─ Attrs │
  │  [ToolCall]→[Entity]│ ─ Edges │
  │    ↓                │ ─ Risk  │
  │  [Entity(URL)]      │         │
  ├─ Path Bar ─────────┴─────────┤
  │ .env → Read → Bash(curl) → URL│
  └────────────────────────────────┘
참고: Palantir Data Lineage 전체 화면 그래프
```

### 5.7 `<ProvenanceChain>` — 해시 체인 시각화
```
Props: { records, verification }
구조: 세로 체인 — 각 블록에 sequence, type, hash
참고: 블록체인 탐색기 스타일 + Palantir Build Timeline
```

### 5.8 `<ComplianceTable>` — 규제 준수 테이블
```
Props: { checks: Check[] }
구조: Palantir dense table 패턴
컬럼: Check ID, Article, Description, Status(badge)
참고: Palantir Permission Matrix 테이블
```

### 5.9 `<SessionsTable>` — 세션 리스트
```
Props: { sessions, onSelect, filters }
구조:
  ┌─ Filter Bar ─────────────────┐
  │ Search │ Risk ▼ │ Show empty │
  ├─ Table ──────────────────────┤
  │ ID│Time│Records│Risk│Chain│↗ │
  └──────────────────────────────┘
참고: LangSmith Traces 테이블 + Palantir 필터
```

---

## 6. 설계 의도 요약

| 패턴 | 출처 | 적용 위치 |
|------|------|-----------|
| Dense data table | Palantir Blueprint | Sessions, Provenance, Compliance |
| Run Tree hierarchy | LangSmith | Timeline/Trace Tree 탭 |
| Full-screen graph canvas | Palantir Data Lineage | Data Flows 탭 |
| Node expand/path-find | Palantir Data Lineage | KG 그래프 상호작용 |
| Metric cards row | LangSmith Dashboard | Overview 상단 |
| Right-side detail panel | Palantir + LangSmith | 그래프/트리 선택 시 |
| Filter chips | LangSmith | Timeline 필터, Sessions 필터 |
| Intent-based coloring | Palantir Blueprint | 모든 badge, border, glow |
| Dark mode 5-layer bg | Palantir Blueprint Dark | 전체 배경 시스템 |
| Monospace hash display | 자체 | Provenance, Merkle Root |
