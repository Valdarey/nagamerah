from pydantic import BaseModel, Field
from typing import Any
class ProviderResult(BaseModel):
    provider:str; status:str; score:float|None=None; summary:dict[str,Any]=Field(default_factory=dict); queried_at:str|None=None; from_cache:bool=False; error:str|None=None
class AnalysisResult(BaseModel):
    ioc:dict; providers:list[ProviderResult]=Field(default_factory=list); score:float|None=None; verdict:str="Unknown"; confidence:str="LOW"; labels:list[str]=Field(default_factory=list); evidence:list[str]=Field(default_factory=list)
