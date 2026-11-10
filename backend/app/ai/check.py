import sys

from google import genai
from google.genai import errors as genai_errors

from app.core.config import get_settings


def main() -> int:
    settings = get_settings()
    if not settings.gemini_api_key:
        print("GEMINI_API_KEY is not set.")
        return 1
    client = genai.Client(api_key=settings.gemini_api_key)
    try:
        names = sorted(
            (model.name or "").removeprefix("models/")
            for model in client.models.list()
            if "generateContent" in (model.supported_actions or [])
        )
    except genai_errors.APIError as error:
        print(f"Could not list models (HTTP {getattr(error, 'code', 'unknown')}).")
        return 1
    print("Models available to this key for generateContent:")
    for name in names:
        print(f"  {name}")
    if not settings.gemini_model:
        print("\nGEMINI_MODEL is not set. Choose a Flash or Flash-Lite model from the list.")
        return 0
    if settings.gemini_model not in names:
        print(f"\nGEMINI_MODEL '{settings.gemini_model}' is not in the list above.")
        return 1
    try:
        response = client.models.generate_content(
            model=settings.gemini_model, contents="Reply with the single word OK."
        )
    except genai_errors.APIError as error:
        print(f"\nTest call failed (HTTP {getattr(error, 'code', 'unknown')}).")
        return 1
    print(f"\nTest call to '{settings.gemini_model}' succeeded: {(response.text or '').strip()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())