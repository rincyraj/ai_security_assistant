import json

import boto3


class LLMClient:
    def __init__(
        self,
        region_name="us-east-1",
        profile_name="ai-security-assistant",
        model_id="us.anthropic.claude-sonnet-4-6",
    ):
        session = boto3.Session(
            profile_name=profile_name,
            region_name=region_name,
        )

        self.client = session.client("bedrock-runtime")
        self.model_id = model_id

    def generate(self, prompt):
        request_body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 2000,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": prompt,
                        }
                    ],
                }
            ],
        }

        response = self.client.invoke_model(
            modelId=self.model_id,
            body=json.dumps(request_body),
        )

        response_body = json.loads(response["body"].read())

        return response_body["content"][0]["text"]