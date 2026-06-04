from fastapi import FastAPI, HTTPException

app = FastAPI(title="My API")


@app.get("/")
def root():
    return {"message": "hello"}


@app.get("/items/{item_id}")
def read_item(item_id: int):
    if item_id < 0:
        raise HTTPException(status_code=404)
    return {"item_id": item_id}


@app.post("/items")
def create_item():
    return {"message": "created"}


@app.put("/items/{item_id}")
def update_item(item_id: int):
    return {"item_id": item_id, "updated": True}


@app.delete("/items/{item_id}")
def delete_item(item_id: int):
    return {"message": "deleted"}


def _unused_helper():
    """Private helper that is never called."""
    pass
