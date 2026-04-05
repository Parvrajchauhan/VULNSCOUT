from fastapi import APIRouter, HTTPException
from api.schemas import QueryRequest, QueryResponse
from api.core.generator import generate

router = APIRouter()

@router.post("/query", response_model=QueryResponse)
def query_endpoint(req: QueryRequest):
    try:
        return generate(req)         
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))