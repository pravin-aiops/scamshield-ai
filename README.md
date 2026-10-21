# ScamShield AI

AI-assisted scam message detection and risk analysis.

## Overview

ScamShield AI is a web application designed to analyse suspicious SMS messages, WhatsApp messages, emails, and URLs. It identifies potential scam indicators, presents an explainable risk assessment, and recommends safer next steps.

## Planned Features

- Message and URL analysis
- Rule-based scam detection
- Risk classification and explanations
- Optional AI-powered analysis
- Responsive web interface
- Automated testing
- Docker packaging
- AWS deployment and monitoring

## Technology Stack

- Frontend: React, Vite, TypeScript
- Backend: Python, FastAPI
- Detection: Python-based rules engine
- Containerization: Docker
- Version Control: Git and GitHub
- Cloud: AWS Elastic Beanstalk, subject to service availability

## Project Status

**Phase 1 — Foundation and setup in progress.**

Features listed above are planned and will be marked complete only after implementation and testing.

## Development Goals

1. Build the frontend and backend.
2. Implement explainable scam detection.
3. Add optional AI-assisted analysis.
4. Test security, reliability, and error handling.
5. Deploy to AWS where supported.
6. Document setup, testing, and deployment.

## How to read the results (limits)

- The score (0-100) is a rule-based warning level, **not a probability**. Low is under 25, Caution is 25-49 and High is 50 or more.
- The score and findings come from fixed rules. The AI model only helps explain them in plain words, and never changes the score.
- The link check uses Google Safe Browsing's list of known threats. "No known threat" is **not** the same as "safe": new scam sites can be missed.
- Only English summaries are written by the AI by default (`AI_SUMMARY_LANGUAGES=en`), because the small default model (`qwen2.5:0.5b`) writes weak Hindi. Hindi and Hinglish reports use rule-based summaries. With a larger model set `AI_SUMMARY_LANGUAGES=en,hi,hinglish`.
- Rate limit and AI cache are held in memory, so they are per server process.
- ScamShield AI is an independent tool and not a government service. If money is lost, call 1930 or report at cybercrime.gov.in.

## Security and Privacy

Do not commit credentials, API keys, access tokens, or real users' sensitive messages. Detection results are assessments, not guarantees that a message is safe or fraudulent.

## License

To be decided before public release.