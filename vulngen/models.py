from pydantic import BaseModel, Field


class GeneratedCase(BaseModel):
    """What Gemini returns when asked to build a test case."""

    title: str = Field(description="Short, realistic name for the program, e.g. 'Inventory lookup service'.")
    vulnerable_code: str = Field(description="Complete source file containing exactly one intentional vulnerability.")
    patched_code: str = Field(description="The same file with only the minimal change that fixes the vulnerability.")
    trigger: str = Field(description="Proof-of-concept trigger, following the trigger contract in the prompt.")
    explanation: str = Field(description="One or two sentences describing the flaw. Stored as ground truth only.")


class Finding(BaseModel):
    line: int = Field(description="1-based line number of the vulnerable code.")
    cwe: str = Field(description="CWE identifier, e.g. 'CWE-89'.")
    message: str = Field(description="Short description of the issue.")


class Review(BaseModel):
    findings: list[Finding]
