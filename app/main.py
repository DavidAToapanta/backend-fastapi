from fastapi import FastAPI

app = FastAPI(title="Mi API", version="0.1.0")

@app.get("/")
def read_root():
    return {"status": "ok", "message": "Backend funcionando"}

@app.get("/health")
def health_check():
    return {"status": "healthy"}