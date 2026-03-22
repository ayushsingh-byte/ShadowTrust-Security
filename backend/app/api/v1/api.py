from fastapi import APIRouter

from app.api.v1.nodes import router as nodes_router
from app.api.v1.endpoints.auth import router as auth_router

api_router = APIRouter()
api_router.include_router(nodes_router, prefix="/nodes", tags=["nodes"])
api_router.include_router(auth_router, prefix="/auth", tags=["auth"])
from app.api.v1.endpoints.logs import router as logs_router
api_router.include_router(logs_router, prefix="/logs", tags=["logs"])
from app.api.v1.endpoints.dashboard import router as dashboard_router
api_router.include_router(dashboard_router, prefix="/dashboard", tags=["dashboard"])

from app.api.v1.endpoints.malware import router as malware_router
api_router.include_router(malware_router, prefix="/malware", tags=["malware"])

from app.api.v1.endpoints.admin import router as admin_router
api_router.include_router(admin_router, prefix="/admin", tags=["admin"])

from app.api.v1.endpoints.vm import router as vm_router
api_router.include_router(vm_router, prefix="/vm", tags=["vm"])

from app.api.v1.endpoints.labs import router as labs_router
api_router.include_router(labs_router, prefix="/labs", tags=["labs"])

from app.api.v1.endpoints.url_scan import router as url_scan_router
api_router.include_router(url_scan_router, prefix="/url-scan", tags=["url-scan"])

from app.api.v1.endpoints.mitre import router as mitre_router
api_router.include_router(mitre_router, prefix="/mitre", tags=["mitre"])

from app.api.v1.endpoints.mobsf_proxy import router as mobsf_proxy_router
api_router.include_router(mobsf_proxy_router, prefix="/mobsf-proxy", tags=["mobsf-proxy"])

# Legacy routers commented out until migrated
from app.api.v1.endpoints.users import router as users_router
api_router.include_router(users_router, prefix="/users", tags=["users"])

from app.api.v1.endpoints.session import router as session_router
api_router.include_router(session_router, prefix="/session", tags=["session"])

from app.api.v1.endpoints.events import router as events_router
api_router.include_router(events_router, prefix="/events", tags=["events"])

from app.api.v1.endpoints.aws import router as aws_router
api_router.include_router(aws_router, prefix="/aws", tags=["aws"])

from app.api.v1.endpoints.analytics import router as analytics_router
api_router.include_router(analytics_router, prefix="/analytics", tags=["analytics"])

from app.api.v1.endpoints.behavior import router as behavior_router
api_router.include_router(behavior_router, prefix="/behavior", tags=["behavior"])

from app.api.v1.endpoints.credentials_api import router as credentials_router
api_router.include_router(credentials_router, prefix="/credentials", tags=["credentials"])

from app.api.v1.endpoints.sectors import router as sectors_router
api_router.include_router(sectors_router, prefix="/sectors", tags=["sectors"])

from app.api.v1.endpoints.attacks_api import router as attacks_router
api_router.include_router(attacks_router, prefix="/attacks", tags=["attacks"])

from app.api.v1.endpoints.honeypots_api import router as honeypots_router
api_router.include_router(honeypots_router, prefix="/honeypots", tags=["honeypots"])
