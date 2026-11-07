from fastapi import APIRouter

from app.api import analysis, attack_paths, auth, environments, health, imports, rules, samples

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(environments.router)
api_router.include_router(imports.router)
api_router.include_router(analysis.router)
api_router.include_router(attack_paths.router)
api_router.include_router(rules.router)
api_router.include_router(samples.router)