from workers import DurableObject, Response, WorkerEntrypoint

BACKEND_URL = "https://siem-backend.tanubhavj.workers.dev"

ALLOWED_ORIGINS = [
    "https://freekhana-frontend.pages.dev",
    "http://localhost:5173",
    "http://localhost:3000",
]

class MyDurableObject(DurableObject):
    def __init__(self, ctx, env):
        super().__init__(ctx, env)

    async def say_hello(self, name):
        return f"Hello, {name}!"
    
    async def handle_proxy(self, request):
        origin = request.headers.get("Origin", "")
        
        if origin and any(origin.strip() == ao for ao in ALLOWED_ORIGINS):
            cors_origin = origin
        else:
            cors_origin = ALLOWED_ORIGINS[0]
        
        method = request.method
        path = request.url.path.replace("/api", "", 1)
        query = request.url.search
        
        url = f"{BACKEND_URL}{path}{query}"
        
        headers = {}
        cf_access_client_id = request.headers.get("CF-Access-Client-Id")
        cf_access_signature = request.headers.get("CF-Access-Signature")
        
        if cf_access_client_id:
            headers["CF-Access-Client-Id"] = cf_access_client_id
        if cf_access_signature:
            headers["CF-Access-Signature"] = cf_access_signature
        
        for h in ["Content-Type", "Accept", "Authorization", "User-Agent"]:
            val = request.headers.get(h)
            if val:
                headers[h] = val
        
        try:
            response = await fetch(url, {
                "method": method,
                "headers": headers,
                "body": method != "GET" and method != "HEAD" and await request.arrayBuffer() or undefined
            })
            
            response_headers = {}
            for k, v in response.headers.items():
                response_headers[k] = v
            
            response_headers["Access-Control-Allow-Origin"] = cors_origin
            response_headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            response_headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, CF-Access-Client-Id, CF-Access-Signature"
            response_headers["Access-Control-Max-Age"] = "86400"
            
            return Response(
                body=await response.arrayBuffer(),
                status=response.status,
                headers=response_headers
            )
        except Exception as e:
            return Response.json({
                "error": "Proxy error",
                "message": str(e)
            }, status=502)

class Default(WorkerEntrypoint):
    async def fetch(self, request):
        if request.method == "OPTIONS":
            origin = request.headers.get("Origin", "")
            if origin and any(origin.strip() == ao for ao in ALLOWED_ORIGINS):
                cors_origin = origin
            else:
                cors_origin = ALLOWED_ORIGINS[0]
            
            return Response(None, {
                "Access-Control-Allow-Origin": cors_origin,
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization, CF-Access-Client-Id, CF-Access-Signature",
                "Access-Control-Max-Age": "86400"
            })
        
        path = request.url.path
        
        if path.startswith("/api/"):
            stub = self.env.MY_DURABLE_OBJECT.getByName("proxy")
            return await stub.handle_proxy(request)
        
        stub = self.env.MY_DURABLE_OBJECT.getByName("foo")
        greeting = await stub.say_hello("world")
        
        return Response(greeting)
