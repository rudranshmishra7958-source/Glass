from fastapi import APIRouter, UploadFile, File
from pydantic import BaseModel

from sandbox.runner import run_code

router = APIRouter()


class CodeRequest(BaseModel):
    code: str


@router.post("/execute")
def execute_code(request: CodeRequest):
    return run_code(request.code)


@router.post("/analyze-file")
async def analyze_file(file: UploadFile = File(...)):
    filename = file.filename or "uploaded_file"

    contents = await file.read()

    if len(contents) > 100_000:
        return {
            "status": "error",
            "error": "File is too large. Maximum size is 100 KB."
        }

    try:
        code = contents.decode("utf-8")
    except UnicodeDecodeError:
        return {
            "status": "error",
            "error": "For the MVP, SafeBox only supports UTF-8 text/code files."
        }

    result = run_code(code)

    result["file"] = {
        "name": filename,
        "size": len(contents),
    }

    return result