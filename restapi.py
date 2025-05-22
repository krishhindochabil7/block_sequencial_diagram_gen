import sys
from pathlib import Path
import time
import os
from fastapi import FastAPI, HTTPException, Depends, status, Query, Form, UploadFile, File
from fastapi.responses import JSONResponse
from dotenv import load_dotenv, find_dotenv
from datetime import datetime, timedelta, UTC
import traceback
import logging
from bson import ObjectId
from typing import Optional, List, Dict
from motor.motor_asyncio import AsyncIOMotorClient
from uuid import uuid4
from urllib.parse import urlparse
from src.auth.auth import AuthService
from src.services.user.user_service import UserService, users_collection
from src.models.Registeruser import RegisterUser, BaseModel
from src.models.User import EmailAuthPasswordForm, PasswordReset, RoleUpdate, UserRole
from src.services.retrieval.master_retrieval import MASTER_RETREIVER
from src.services.ingestion.sql_kbms_ingestion import *
from src.logger.logger import setup_logger
from src.config.config import settings
from src.utils.version_utils import get_version
from src.middleware.request_id import RequestIdMiddleware
from src.middleware.CORS import CORSMiddleware
from src.services.history.summarize_and_embed import summarize_and_store
auth_service = AuthService(settings.JWT_SECRET_KEY, settings.JWT_ALGORITHM, settings.JWT_ACCESS_TOKEN_EXPIRE_DAYS)
user_service = UserService(users_collection)

logger = setup_logger()

load_dotenv()

MONGO_URL = os.getenv("MONGODB_URI")
client = AsyncIOMotorClient(MONGO_URL)
db = client["bilgo_app"]
job_details_col = db["job_details"]
qna_sessions_col = db["qna_sessions"]
partition_collection = db["partitions"]
access_collection = db["partition_access"]

sql_kbms_ingestion = KBMS_SQL_INGESTION()
retriever = MASTER_RETREIVER()
master_ingestion = MASTER_INGESTION()

BASE_URL = os.getenv("BASE_URL", "/ragapi")

app = FastAPI(
    title="RAG for Billgo",
    description="API for ingesting different types of files and retrieval over all files",
    version=get_version(),
    docs_url=f"{BASE_URL}/docs",
    redoc_url=f"{BASE_URL}/redoc",  # ReDoc endpoint (alternative docs, default)
    openapi_tags=[
        {
            "name": "Ingestion",
            "description": "Endpoint for different type of file ingestion"
        },
        {
            "name": "Retrieval",
            "description": "Endpoint for retrieving data"
        }
    ],
    openapi_security=[{
        "oauth2": {
            "type": "oauth2",
            "flow": "password",
            "tokenUrl": f"{BASE_URL}/auth/login"
        }
    }]
)

app.add_middleware(CORSMiddleware)
app.add_middleware(RequestIdMiddleware)

class queryRequest(BaseModel):
    query: str
    session_id: str
    partition_name: Optional[str]
    partition_value: Optional[str]
    dbquery: bool

logger.setLevel(logging.WARNING)


@app.get("/touch")
async def touch():
    """
    Endpoint to check if the API is valid and operational.
    """
    return {"message": "API is valid and operational", "status": "success"}

# Auth Routes
@app.post(f"{BASE_URL}/auth/register", tags=["Authentication"], summary="Register")
async def register(user: RegisterUser):
    existing_user = await user_service.get_user_by_email(user.email)
    if (existing_user):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered"
        )
    
    user_id = await user_service.create_user(
        email=user.email,
        full_name=user.full_name,
        password=user.password.get_secret_value(),
        username=user.username,
        company_name=user.company_name,
    )
    return {"message": "User registered successfully", "user_id": user_id}

@app.post(f"{BASE_URL}/auth/login", tags=["Authentication"], summary="Login")
async def login_for_access_token(form_data: EmailAuthPasswordForm = Depends(EmailAuthPasswordForm.as_form)):
    # Get the login identifier (either email or username)
    try:
        login_identifier = form_data.username if form_data.username else form_data.email
        user = await user_service.authenticate_user(login_identifier, form_data.password)
        if not user:
            logger.warning(f"Failed login attempt for user: {login_identifier}")
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "detail": "Incorrect email or password"
                },
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        access_token = auth_service.create_access_token(
            data={"sub": user["email"],"userId": str(user["_id"])}, expires_delta=timedelta(days=settings.JWT_ACCESS_TOKEN_EXPIRE_DAYS)
        )
        return {
            "id": str(user["_id"]),
            "email": user["email"],
            "full_name": user["full_name"],
            "username": user["username"],
            "company_name": user["company_name"],
            "role": user["role"],
            "access_token": access_token, 
            "token_type": "bearer",
            "expiry_time": (datetime.now() + timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S %Z")
        }
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during authentication"
        )

@app.get(f"{BASE_URL}/auth/users/me", tags=["Authentication"], summary="Get current user")
async def read_users_me(current_user: dict = Depends(auth_service.get_current_user)):
    return {
        "id": str(current_user["_id"]),
        "email": current_user["email"],
        "full_name": current_user["full_name"],
        "created_at": current_user["created_at"],
        "updated_at": current_user["updated_at"],
        "active": current_user["active"]
    }

@app.get(f"{BASE_URL}/admin/pending-registrations", tags=["Admin"], summary="Get pending user registrations", dependencies=[Depends(auth_service.check_admin)])
async def get_pending_registrations():
    """Get all pending user registrations."""
    try:
        pending_users = await user_service.get_pending_registrations()
        return {
            "pending_users": [
                {
                    "id": str(user["_id"]),
                    "email": user["email"],
                    "full_name": user["full_name"],
                    "username": user["username"],
                    "company_name": user["company_name"],
                    "created_at": user["created_at"]
                } for user in pending_users
            ]
        }
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post(f"{BASE_URL}/admin/approve-user/{{user_id}}", tags=["Admin"], summary="Approve a user registration", dependencies=[Depends(auth_service.check_admin)])
async def approve_user(user_id: str, current_admin: dict = Depends(auth_service.get_current_user)):
    """Approve a pending user registration."""
    try:
        approver_mail = str(current_admin["email"])
        approver_id = str(current_admin["_id"])
        await user_service.approve_user(user_id, approver_id, approver_mail)
        return {"message": "User approved successfully"}
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post(f"{BASE_URL}/admin/reject-user/{{user_id}}", tags=["Admin"], summary="Reject a user registration", dependencies=[Depends(auth_service.check_admin)])
async def reject_user(user_id: str):
    """Reject a pending user registration."""
    try:
        await user_service.reject_user(user_id)
        return {"message": "User rejected successfully"}
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete(f"{BASE_URL}/admin/delete-user/{{user_id}}", tags=["Admin"], summary="Delete an existing user", dependencies=[Depends(auth_service.check_admin)])
async def delete_user(user_id: str):
    """Delete an existing user."""
    try:
        await user_service.delete_user(user_id)
        return {"message": "User deleted successfully"}
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get(f"{BASE_URL}/admin/users", tags=["Admin"], summary="Get all active users", dependencies=[Depends(auth_service.check_admin)])
async def get_all_users(
    company_name: Optional[str] = Query(None, description="Filter by company name"),
    role: Optional[UserRole] = Query(None, description="Filter by user role"),
    full_name: Optional[str] = Query(None, description="Search by full name"),
    username: Optional[str] = Query(None, description="Search by username"),
    email: Optional[str] = Query(None, description="Search by email"),
    approver_mail: Optional[str] = Query(None, description="Search by approver email")
):
    """Get all active users with optional filters."""
    try:
        # Build the query based on provided filters
        query = {}
        if company_name:
            query["company_name"] = company_name
        if role:
            query["role"] = role
        if full_name:
            query["full_name"] = {"$regex": full_name, "$options": "i"}  # Case-insensitive search
        if username:
            query["username"] = {"$regex": username, "$options": "i"}  # Case-insensitive search
        if email:
            query["email"] = {"$regex": email, "$options": "i"}  # Case-insensitive search
        if approver_mail:
            query["approver_mail"] = {"$regex": approver_mail, "$options": "i"}  # Case-insensitive search

        users = await user_service.get_all_users(query)
        return {
            "users": [
                {
                    "id": str(user["_id"]),
                    "email": user["email"],
                    "full_name": user["full_name"],
                    "username": user["username"],
                    "company_name": user["company_name"],
                    "role": user["role"],
                    "created_at": user["created_at"],
                    "updated_at": user["updated_at"],
                    "approver_mail": user["approver_mail"]
                } for user in users
            ]
        }
    except Exception as e:
        logger.error(f"Error: %s", str(e))
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.post(f"{BASE_URL}/admin/reset-password/{{user_id}}", tags=["Admin"], summary="Reset user's password", dependencies=[Depends(auth_service.check_admin)])
async def reset_user_password(user_id: str, password_data: PasswordReset):
    """Reset a user's password. Only accessible by admins."""
    try:
        await user_service.reset_password(user_id, password_data.new_password.get_secret_value())
        return {"message": "Password reset successfully"}
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get(f"{BASE_URL}/admin/users/{{user_id}}/role", tags=["Admin"], summary="Get user's current role", dependencies=[Depends(auth_service.check_admin)])
async def get_user_role(user_id: str):
    """Get a user's current role. Only accessible by admins."""
    try:
        role = await user_service.get_user_role(user_id)
        return {"user_id": user_id, "role": role}
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.put(f"{BASE_URL}/admin/users/{{user_id}}/role", tags=["Admin"], summary="Update user's role", dependencies=[Depends(auth_service.check_admin)])
async def update_user_role(user_id: str, role_data: RoleUpdate, current_admin: dict = Depends(auth_service.get_current_user)):
    """Update a user's role. Only accessible by admins."""
    try:
        # Prevent admin from changing their own role
        if user_id == str(current_admin["_id"]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Admins cannot modify their own role"
            )
        
        # If changing to admin role, ensure there will still be at least one admin
        if role_data.role != UserRole.ADMIN:
            # Get the user being modified
            target_user = await user_service.get_user_by_userId(user_id)
            if target_user and target_user.get("role") == UserRole.ADMIN:
                # Count remaining admins
                admin_count = await users_collection.count_documents({"role": UserRole.ADMIN})
                if admin_count <= 1:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Cannot remove the last admin user"
                    )

        await user_service.update_user_role(user_id, role_data.role)
        return {"message": f"User role updated to {role_data.role} successfully"}
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# Request Models
class PartitionInsertRequest(BaseModel):
    partition: str
    values: List[str]

class ValueAppendRequest(BaseModel):
    value: str


# Append a single value to a partition
@app.get("/partitions/")
async def get_partitions():
    try:
        data = await partition_collection.find({}, {"_id": 0}).to_list(length=None)
        return data
    except Exception as e:
        error_message = traceback.format_exc()
        raise HTTPException(status_code=500, detail=f"Error fetching partitions: {error_message}")
 
# Add new partition or update values
@app.post("/partitions/")
async def add_partition(req: PartitionInsertRequest):
    try:
        result = await partition_collection.update_one(
            {"Partition": req.partition},
            {"$set": {"Partition_value": req.values}},
            upsert=True
        )
        return {"message": "Partition inserted or updated"}
    except Exception as e:
        error_message = traceback.format_exc()
        raise HTTPException(status_code=500, detail=f"Error adding/updating partition: {error_message}")
 
access_collection = db["partition_access"]

@app.get("/partitions/role/{role_name}")
async def get_partitions_by_role(role_name: str):
    try:
        access_doc = await access_collection.find_one({})
        if not access_doc or "roles" not in access_doc:
            raise HTTPException(status_code=404, detail="Access config not found")

        matched_role = next((r for r in access_doc["roles"] if r["role"].lower() == role_name.lower()), None)
        if not matched_role:
            raise HTTPException(status_code=404, detail=f"Role '{role_name}' not found")

        access_partitions = [p.lower() for p in matched_role["partition_access"]]
        
        # Convert partition names to proper case as stored
        query_filter = {"Partition": {"$in": [p.capitalize() for p in access_partitions]}}
        cursor = partition_collection.find(query_filter, {"_id": 0})
        results = await cursor.to_list(length=None)

        return results
    
    except Exception as e:
        error_message = traceback.format_exc()
        raise HTTPException(status_code=500, detail=f"Error appending value: {error_message}")

# Append a single value to a partition
@app.put("/partitions/{partition_name}")
async def append_value(partition_name: str, req: ValueAppendRequest):
    try:
        result = await partition_collection.update_one(
            {"Partition": partition_name},
            {"$addToSet": {"Partition_value": req.value}}
        )
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Partition not found")
        return {"message": f"Value added to {partition_name}"}
    except Exception as e:
        error_message = traceback.format_exc()
        raise HTTPException(status_code=500, detail=f"Error appending value: {error_message}")

@app.get(f"{BASE_URL}/new-session-id", tags=["Ingestion"], summary="Generate a new session ID")
async def new_session():
    session_id = str(uuid4())
    return {"session_id": session_id}
    

@app.get("/user-sessions", tags=["Retrieval"])
async def get_sessions_for_user(user_id: str = Query(..., description="MongoDB ObjectId of the user")):
    try:
        # Convert the user_id to ObjectId
        object_id = ObjectId(user_id)

        # Aggregation pipeline to get session_ids and the earliest query for each session_id
        pipeline = [
            {"$match": {"user_id": object_id}},  # Match by user_id
            {"$sort": {"timestamp": -1}},  # Sort by timestamp descending (latest first)
            {"$group": {
                "_id": "$session_id",  # Group by session_id
                "earliest_query": {"$first": "$query"},  # Get the first query for each session_id
                "timestamp": {"$first": "$timestamp"}  # Get the latest timestamp for each session_id
            }},
            {"$sort": {"timestamp": -1}},  # Sort by timestamp to get the latest session first
            {"$project": {
                "session_id": "$_id",  # Rename _id to session_id
                "earliest_query": 1,  # Include earliest query
                "_id": 0  # Exclude the default _id field
            }}
        ]

        # Execute the aggregation pipeline
        result = await qna_sessions_col.aggregate(pipeline).to_list(length=100)

        if not result:
            return {"user_id": user_id, "sessions": []}

        # Format the response with session_id and earliest query
        sessions_with_queries = [{"session_id": doc["session_id"], "earliest_query": doc["earliest_query"]} for doc in result]

        return {"user_id": user_id, "sessions": sessions_with_queries}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

@app.get("/session-details", tags=["Retrieval"])
async def get_session_details(session_id: str = Query(..., description="The session ID to fetch queries and responses")):
    try:
        # Ensure the session_id is valid
        if not session_id:
            raise HTTPException(status_code=400, detail="Session ID is required")

        pipeline = [
            {"$match": {"session_id": session_id}},  # Match by session_id
            {"$sort": {"timestamp": 1}},  # Sort by timestamp ascending (oldest first)
            {"$project": {
                "query": 1,
                "response": 1,  # Only include query and response
                "timestamp": 1
            }}
        ]

        result = await qna_sessions_col.aggregate(pipeline).to_list(length=100)  # Adjust length as needed

        if not result:
            return {"session_id": session_id, "data": []}

        # Format the response to include only query and response
        session_data = [{"query": doc["query"], "response": doc["response"]} for doc in result]

        return {"session_id": session_id, "data": session_data}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")


    
@app.post("/ingest-data", tags=["Ingestion"])
async def ingest_data(
    file: UploadFile = File(...),
    table: bool = Form(False),  
    description: str = Form(None), 
    private: bool = Form(...), 
    document_type: str = Form(...), 
    user_id: str = Form(...), 
    user_role: str = Form(...), 
    partition_name: str = Form(...), 
    partition_metadata: str = Form(...)
):

    result = await sql_kbms_ingestion.ingest_kbms_sql(file, table, private, document_type, user_id, user_role, partition_name, partition_metadata, description)

    await db["uploaded_files"].insert_one({
        "file_name": file.filename,
        "description": description,
        "private": private,
        "file_type": "table" if table else "file",
        "document_type": document_type,
        "user_id": user_id,
        "user_role": user_role,
        "partition_name": partition_name,
        "partition_metadata": partition_metadata,
        "timestamp": datetime.utcnow(),
        "ingestion_result": result
    })

    return {"status": "success", "result": result}


@app.post("/ingest-url", tags=["Ingestion"])
async def ingest_url_data(urls: list = Form(...), description: str = Form(None), private: bool = Form(...), document_type: str = Form(...), user_id:str=Form(...), user_role:str=Form(...), partition_name:str=Form(...), partition_metadata:str=Form(...), current_user: dict = Depends(auth_service.get_current_user)):

    try:
        logger.warning(f"Received URLs for ingestion: {urls}")
        # Normalize input in case a single string was submitted with commas
        normalized_urls = []
        for url in urls:
            if isinstance(url, str):
                normalized_urls.extend([u.strip() for u in url.split(",")])
            else:
                normalized_urls.append(url)

        logger.warning(f"Normalized URLs for ingestion: {normalized_urls}")
        print("partition  ", partition_name)
        print("metadata   ", partition_metadata)
        database = await master_ingestion.ingest_url(
            normalized_urls, private, document_type, user_id, user_role, partition_name, partition_metadata, description
        )

        logger.info(f"Ingestion result: {database} - {urls}")

        for url in normalized_urls:

            parsed = urlparse(url)
            path = parsed.path.strip('/')
            
            if path:  # If path exists (e.g., /wiki/Elon_Musk)
                url_name = os.path.basename(path)
            else:  # If no path (e.g., https://nasa.gov/)
                url_name = parsed.netloc.replace('www.', '')
            
            await db["uploaded_files"].insert_one({
                "file_name": url_name,
                "description": description,
                "private": private,
                "file_type": "url",
                "document_type": document_type,
                "user_id": user_id,
                "user_role": user_role,
                "partition_name": partition_name,
                "partition_metadata": partition_metadata,
                "timestamp": datetime.utcnow(),
                "ingestion_result": database
            })

        return {"result": database}
    
    except Exception as e:
        logger.error(f"Error during URL ingestion: {str(e)}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error during URL ingestion: {str(e)}")

@app.post("/process-query", tags=["Retrieval"])
async def process_query(request: queryRequest, current_user: dict = Depends(auth_service.get_current_user)):
    try:
        query = request.query
        partition_name = request.partition_name or None
        partition_value = request.partition_value or None
        dbquery = request.dbquery
        session_id = request.session_id.strip()
        user_id = current_user['_id']
        
        if not session_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Session ID is required"
            )
        
        # Retrieve conversation history (previous 4 interactions)
        conversation_history = await qna_sessions_col.find(
            {"session_id": session_id},
            {"_id": 0, "query": 1, "response": 1}  # Project only query and response
        ).sort("timestamp", -1).limit(5).to_list(length=5)

        
        # Reverse to get chronological order
        conversation_history.reverse()
        print(conversation_history)
        
        # Process query with conversation history
        response = await retriever.master_retrieval(
            db, 
            query, 
            dbquery, 
            partition_name, 
            partition_value,
            conversation_history if conversation_history else None
        )
        
        # Log query and answer
        await qna_sessions_col.insert_one({
            "session_id": session_id,
            "user_id": user_id,
            "query": query,
            "response": response,
            "timestamp": datetime.utcnow(),
            "partition_name": partition_name,
            "partition_value": partition_value
        })
        
        return {"session_id": session_id, "response": response}
    
    except HTTPException as http_exc:
        raise http_exc
    
    except Exception as e:
        # Log the traceback to stderr or your logger
        traceback_str = traceback.format_exc()
        print(traceback_str)  # or use logging.error(traceback_str)
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected error occurred: {str(e)}"
        )

@app.get("/save-chat-session")
async def save_chat_session(session_id: str):
    try:
        await summarize_and_store(session_id)
        return {
            "status": "success",
            "message": f"Chat session saved/updated for {session_id}"
        }    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=1000, reload=True)
