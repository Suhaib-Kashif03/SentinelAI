# Evaluation

SentinelAI includes a test-driven evaluation suite that checks how well the system detects safe and risky inputs.

## Test Coverage

The evaluation suite covers:

- Safe prompts
- Prompt injection
- Jailbreak attempts
- Secret leakage
- Safe commands
- Package installation
- System reconnaissance
- Network reconnaissance
- Destructive commands
- Unsafe network execution
- Secret file access
- Privileged commands
- Unsafe code patterns

## Running the Evaluation

Start the backend:

```bash
python -m uvicorn backend.main:app --reload
```

#### Run evaluation:

```bash
python evaluation/run_evaluation.py
```

## Generated Files

```bash
evaluation/evaluation_results.json
evaluation/evaluation_report.md
```

## Metrics

The evaluation report includes:

- Total tests
- Passed tests
- Failed tests
- Pass rate
- Decision breakdown
- Error breakdown
- Category coverage
- Full test results

## Interpretation

A high pass rate indicates that SentinelAI is correctly detecting known risky patterns. Failed tests are useful because they reveal rule gaps, false positives, or underclassified risks.

## Important Note

SentinelAI uses rule-based detection. The evaluation suite does not prove complete security coverage against all possible attacks. It provides measurable evidence for the implemented detection categories.