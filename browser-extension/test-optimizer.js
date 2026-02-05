// In-A-Lign Prompt Optimizer Test

const PromptOptimizer = {
    detectTaskType(text) {
        if (/코드|code|프로그램|script|함수|function/i.test(text)) return 'coding';
        if (/번역|translate/i.test(text)) return 'translation';
        if (/요약|summarize|정리/i.test(text)) return 'summarize';
        if (/설명|explain|알려|뭐야/i.test(text)) return 'explain';
        if (/작성|write|써줘|만들어/i.test(text)) return 'writing';
        return 'general';
    },

    detectLanguage(text) {
        if (/[가-힣]/.test(text)) return 'ko';
        return 'en';
    },

    optimizeForClaude(text, taskType, lang) {
        if (taskType === 'coding' && lang === 'ko') {
            return `다음 요구사항에 맞는 코드를 작성해주세요:

**요구사항:** ${text}

**조건:**
- 깔끔하고 읽기 쉬운 코드
- 주석으로 주요 로직 설명
- 에러 핸들링 포함
- 모범 사례(best practices) 적용`;
        }

        if (taskType === 'coding' && lang === 'en') {
            return `Please write code for the following requirement:

**Requirement:** ${text}

**Guidelines:**
- Clean, readable code
- Comments explaining key logic
- Include error handling
- Follow best practices`;
        }

        if (taskType === 'explain' && lang === 'ko') {
            return `다음에 대해 명확하게 설명해주세요:

**주제:** ${text}

다음 형식으로 답변해주세요:
1. 핵심 개념 (한 문장)
2. 상세 설명
3. 실제 예시
4. 주의사항 (있다면)`;
        }

        if (lang === 'ko') {
            return `${text}

명확하고 구조화된 형식으로 답변해주세요.`;
        }

        return `${text}

Please respond in a clear, structured format.`;
    },

    optimize(text, llm = 'claude') {
        if (!text || text.trim().length < 5) return text;
        const taskType = this.detectTaskType(text);
        const lang = this.detectLanguage(text);
        return this.optimizeForClaude(text, taskType, lang);
    }
};

// 테스트 실행
console.log('========================================');
console.log('In-A-Lign Prompt Optimizer Test');
console.log('========================================\n');

const tests = [
    { input: '파이썬으로 웹스크래핑 코드 짜줘', desc: '한국어 코딩 요청' },
    { input: 'write a python function to sort', desc: '영어 코딩 요청' },
    { input: '머신러닝이 뭐야', desc: '한국어 설명 요청' },
    { input: '이메일 작성해줘', desc: '한국어 작성 요청' },
    { input: 'hello', desc: '짧은 입력 (변환 안됨)' },
];

tests.forEach((test, i) => {
    console.log(`\n[테스트 ${i+1}] ${test.desc}`);
    console.log(`입력: "${test.input}"`);
    console.log(`---`);
    const result = PromptOptimizer.optimize(test.input);
    console.log(`출력:\n${result}`);
    console.log('');
});
