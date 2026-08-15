"""
Chanakya AI fallback helpers.

The primary fallback provider is Gemini.
This module currently provides user-facing status helpers.
"""


def get_fallback_message() -> str:
    return (
        "OpenAI API key was not configured. "
        "Chanakya is using Gemini for security analysis."
    )