import json
import os

import boto3


class LLMClient:
    def __init__(
        self,
        region_name=None,
        profile_name=None,
        model_id=None,
    ):
        self.region_name = (
            region_name
            or os.getenv("AWS_REGION")
            or "us-east-1"
        )

        self.model_id = (
            model_id
            or os.getenv("BEDROCK_MODEL_ID")
            or "us.anthropic.claude-sonnet-4-6"
        )

        # Local development:
        # Use the configured AWS profile when provided.
        #
        # Hosted environment:
        # If no profile is provided, boto3 uses the
        # standard AWS credential/provider chain.
        if profile_name:
            session = boto3.Session(
                profile_name=profile_name,
                region_name=self.region_name,
            )
        else:
            session = boto3.Session(
                region_name=self.region_name,
            )

        self.client = session.client("bedrock-runtime")

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

        response_body = json.loads(
            response["body"].read()
        )

        return response_body["content"][0]["text"]

