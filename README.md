# ai_security_assistant
AI-powered cybersecurity assistant for threat detection, security log analysis, RAG-based investigation, and intelligent incident response.
security_logs.json
       ↓
log_reader.py
       ↓
detection_engine.py----->Detect suspicious patterns
       ↓
Incident
       ↓
ai_assistant.py
       ↓
llm_client.py
       ↓
boto3
       ↓
Amazon Bedrock---->AI investigation layer.
       ↓
Claude Sonnet 4
       ↓
AI Security Analysis


## Running the Application

### Demo Mode (Default)

Demo mode detects security alerts and incidents without making Amazon Bedrock API calls. This is the recommended mode for the public demo.

```cmd
streamlit run app.py
```

### Live AI Mode (AWS Bedrock)

To enable live AI-powered security analysis, configure your AWS credentials and Bedrock model access first.

In Windows Command Prompt, run:

```cmd
set AI_MODE=live
set AWS_PROFILE=ai-security-assistant
streamlit run app.py
```

Live mode sends incident analysis requests to Amazon Bedrock and may incur AWS charges.

### Switch Back to Demo Mode

Stop the application with `Ctrl + C`, then run:

```cmd
set AI_MODE=demo
streamlit run app.py
```


