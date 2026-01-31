# ============================================
# MyAPI - FastAPI com JWT e API Key
# ============================================

import os
from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthenticationCredentials, APIKeyHeader
from pydantic import BaseModel
from jose import JWTError, jwt
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ============ CONFIGURAÇÕES ============
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-myapi-2026-prod-key-12345678")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
API_KEY = os.getenv("API_KEY", "sk_live_abc123def456ghi789jkl012mnopqrstuvwxyz")

# ============ SECURITY SETUP ============
bearer_scheme = HTTPBearer(auto_error=False)
api_key_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)

# ============ MODELS ============
class LoginRequest(BaseModel):
    """Modelo para requisição de login"""
    username: str
    password: str

class Token(BaseModel):
    """Modelo para resposta de token"""
    access_token: str
    token_type: str
    expires_in: int

class User(BaseModel):
    """Modelo de usuário"""
    username: str
    email: str

class ResponseModel(BaseModel):
    """Modelo padrão de resposta"""
    success: bool
    message: str
    data: Optional[dict] = None
    timestamp: str

# ============ CRIAR JWT TOKEN ============
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Criar token JWT"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# ============ VERIFICAR JWT TOKEN ============
def verify_token(credentials: HTTPAuthenticationCredentials = Depends(bearer_scheme)):
    """Verificar e validar JWT token"""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token não fornecido",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token inválido"
            )
        return username
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expirado ou inválido"
        )

# ============ VERIFICAR API KEY ============
def verify_api_key(x_api_key: str = Depends(api_key_scheme)):
    """Verificar e validar API Key"""
    if x_api_key is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API Key não fornecida"
        )
    if x_api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API Key inválida"
        )
    return x_api_key

# ============ CRIAR APP ============
app = FastAPI(
    title="MyAPI",
    description="API FastAPI com Autenticação JWT e API Key",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# ============ ROTAS PÚBLICAS ============
@app.get("/", tags=["Info"])
def root():
    """Rota raiz - Informações da API"""
    return {
        "name": "MyAPI",
        "version": "1.0.0",
        "status": "online",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/health", tags=["Health"])
def health():
    """Health check da API"""
    return ResponseModel(
        success=True,
        message="API está saudável",
        data={"status": "healthy"},
        timestamp=datetime.utcnow().isoformat()
    )

@app.get("/info", tags=["Info"])
def api_info():
    """Informações sobre autenticação"""
    return {
        "name": "MyAPI",
        "version": "1.0.0",
        "auth_types": [
            {
                "type": "JWT Bearer",
                "endpoint": "/login",
                "header": "Authorization: Bearer <token>"
            },
            {
                "type": "API Key",
                "header": f"X-API-Key: {API_KEY[:20]}..."
            }
        ],
        "docs": "http://localhost:8000/docs"
    }

# ============ AUTH ENDPOINTS ============
@app.post("/login", response_model=Token, tags=["Auth"])
def login(request: LoginRequest):
    """
    Endpoint de login
    
    **Credenciais padrão:**
    - username: admin
    - password: admin123
    """
    if request.username == "admin" and request.password == "admin123":
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": request.username},
            expires_delta=access_token_expires
        )
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciais inválidas"
    )

@app.post("/register", tags=["Auth"])
def register(request: LoginRequest):
    """Registrar novo usuário"""
    if len(request.username) < 3:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username deve ter pelo menos 3 caracteres"
        )
    if len(request.password) < 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Senha deve ter pelo menos 6 caracteres"
        )
    
    return ResponseModel(
        success=True,
        message=f"Usuário {request.username} registrado com sucesso",
        data={"username": request.username},
        timestamp=datetime.utcnow().isoformat()
    )

# ============ ROTAS PROTEGIDAS COM JWT ============
@app.get("/protected", tags=["Protected"])
def protected_route(username: str = Depends(verify_token)):
    """Rota protegida com JWT"""
    return ResponseModel(
        success=True,
        message=f"Bem-vindo {username}!",
        data={"username": username},
        timestamp=datetime.utcnow().isoformat()
    )

@app.get("/me", response_model=User, tags=["User"])
def get_me(username: str = Depends(verify_token)):
    """Obter informações do usuário logado"""
    return User(
        username=username,
        email=f"{username}@myapi.com"
    )

@app.get("/profile", tags=["User"])
def get_profile(username: str = Depends(verify_token)):
    """Obter perfil completo do usuário"""
    return ResponseModel(
        success=True,
        message="Perfil carregado com sucesso",
        data={
            "username": username,
            "email": f"{username}@myapi.com",
            "role": "admin" if username == "admin" else "user",
            "created_at": datetime.utcnow().isoformat(),
            "verified": True
        },
        timestamp=datetime.utcnow().isoformat()
    )

# ============ ROTAS PROTEGIDAS COM API KEY ============
@app.get("/api/protected", tags=["API Key"])
def api_protected(api_key: str = Depends(verify_api_key)):
    """Rota protegida com API Key"""
    return ResponseModel(
        success=True,
        message="Acesso concedido via API Key",
        data={
            "api_key": api_key[:15] + "...",
            "permissions": ["read", "write"]
        },
        timestamp=datetime.utcnow().isoformat()
    )

@app.get("/api/data", tags=["API Key"])
def api_get_data(api_key: str = Depends(verify_api_key)):
    """Obter dados com API Key"""
    return ResponseModel(
        success=True,
        message="Dados obtidos com sucesso",
        data={
            "items": [
                {"id": 1, "name": "Item 1"},
                {"id": 2, "name": "Item 2"},
                {"id": 3, "name": "Item 3"}
            ],
            "total": 3
        },
        timestamp=datetime.utcnow().isoformat()
    )

@app.post("/api/data", tags=["API Key"])
def api_post_data(request: dict, api_key: str = Depends(verify_api_key)):
    """Enviar dados com API Key"""
    return ResponseModel(
        success=True,
        message="Dados recebidos com sucesso",
        data={
            "received": request,
            "processed": True,
            "saved_id": 123
        },
        timestamp=datetime.utcnow().isoformat()
    )

@app.get("/api/stats", tags=["API Key"])
def api_stats(api_key: str = Depends(verify_api_key)):
    """Obter estatísticas com API Key"""
    return ResponseModel(
        success=True,
        message="Estatísticas da API",
        data={
            "total_requests": 1250,
            "active_users": 45,
            "uptime_hours": 720,
            "api_key_status": "active"
        },
        timestamp=datetime.utcnow().isoformat()
    )

# ============ STARTUP EVENT ============
@app.on_event("startup")
async def startup():
    """Executar ao iniciar a aplicação"""
    print("\n" + "=" * 70)
    print("🚀 MyAPI - Iniciada com Sucesso!")
    print("=" * 70)
    print(f"📊 Versão: 1.0.0")
    print(f"📚 Swagger: http://localhost:8000/docs")
    print(f"📖 ReDoc: http://localhost:8000/redoc")
    print(f"\n🔐 Credenciais Padrão:")
    print(f"   👤 Usuário: admin")
    print(f"   🔑 Senha: admin123")
    print(f"\n🔑 API Key: {API_KEY}")
    print("=" * 70 + "\n")

# ============ MAIN ============
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )