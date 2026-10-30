from pydantic import BaseModel


class SampleRead(BaseModel):
    name: str
    title: str
    description: str