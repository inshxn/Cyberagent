from pydantic import BaseModel, Field


class SignupIn(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_]+$")
    password: str = Field(min_length=6, max_length=128)


class LoginIn(BaseModel):
    username: str
    password: str


class PostIn(BaseModel):
    content: str = Field(min_length=1, max_length=280)

