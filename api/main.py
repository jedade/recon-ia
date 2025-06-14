from fastapi import FastAPI

app = FastAPI(
    title="API Dockerisée",
    description="API exemple avec FastAPI pour l'environnement dockerisé",
    version="1.0.0",
    openapi_url="/api/openapi.json",
    docs_url="/docs",
    redoc_url=None
)

@app.get("/", tags=["Statut"])
def health_check():
    return {"status": "ok", "message": "API en fonctionnement"}

@app.get("/items", tags=["Exemples"])
def list_items():
    return [
        {"id": 1, "name": "Item A"},
        {"id": 2, "name": "Item B"}
    ]

@app.get("/items/{item_id}", tags=["Exemples"])
def get_item(item_id: int):
    return {"id": item_id, "name": f"Item {item_id}", "description": "Ceci est un exemple d'item"}