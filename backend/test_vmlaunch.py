from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)
try:
    response = client.post("/api/v1/vm/launch", json={"ami_id": "ami-123", "instance_type": "t3.micro", "subnet_id": "sub-123", "iam_profile_name": "role", "session_id": "sess_123", "profile_id": "win_base"})
    print(response.json())
except Exception as e:
    import traceback
    traceback.print_exc()
