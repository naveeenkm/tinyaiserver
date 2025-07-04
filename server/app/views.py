import datetime
import random
import traceback
from bson import ObjectId
from django.shortcuts import render
from django.contrib.auth.hashers import check_password
from django.http import JsonResponse
from pymongo import MongoClient
from django.contrib.auth.hashers import make_password, check_password
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from pymongo import MongoClient
import jwt
import datetime
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from google.generativeai import GenerativeModel, configure

import os
from dotenv import load_dotenv

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from app.auth_decorators import JWTAuthentication
from rest_framework.decorators import authentication_classes
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from django.utils.crypto import get_random_string
from django.core.mail import send_mail
import google.generativeai as genai


uri = "mongodb+srv://kmnaveen1110:Naveen%40123@cluster0.kqdhrnt.mongodb.net/techmiyaai?retryWrites=true&w=majority"
    
  
client = MongoClient(uri)
db = client['techmiyaai']
collection = db['auth_user']
deleted_account_collection = db['deleted_auth_user']
reset_tokens = db['password_reset_tokens']



from dotenv import load_dotenv
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
import google.generativeai as genai
import os
import traceback

load_dotenv()


chat_history = []

@api_view(['POST'])
@permission_classes([AllowAny])
def chat_with_ai(request):
    user_message = request.data.get('message')
    api_key = os.getenv('GEMINI_API_KEY')

    if not user_message:
        return Response({'error': 'No message provided'}, status=400)

    try:
        genai.configure(api_key=api_key)

        model = genai.GenerativeModel("gemini-2.0-flash")
        chat = model.start_chat(history=chat_history)

        response = chat.send_message(user_message)
        reply = response.text.strip()

        # Update global history
        chat_history.append({'role': 'user', 'parts': [user_message]})
        chat_history.append({'role': 'model', 'parts': [reply]})

        if not reply:
            return Response({'error': 'No response from Gemini. Try again later.'}, status=503)

        return Response(reply)

    except Exception as e:
        print("Error:", str(e))
        traceback.print_exc()
        return Response({'error': 'Internal server error'}, status=500)



def send_reset_link(request):
    import json
    data = json.loads(request.body)
    email = data.get("email")

    user = collection.find_one({"email": email})
    if not user:
        return JsonResponse({"error": "Email not registered"}, status=400)

    token = get_random_string(64)
    expiry = datetime.datetime.now() + datetime.timedelta(minutes=4)
    
    reset_tokens.insert_one({
        "user_id": str(user["_id"]),
        "token": token,
        "expires_at": expiry
    })
    email_name = user.get("name", email.split("@")[0].rstrip("0123456789") or "User")
    user_name = user.get("name", email_name)
    subject = "Tiny.ai - Password Reset Request"
    reset_link = f"{settings.FRONTEND_BASE_URL}/#/reset-password/{token}"
    message = f"""
Hi {user_name or 'there'},

We received a request to reset your password. Please click the link below to set a new password:

{reset_link}

Note: This link is valid for 4 minutes. If you did not request a password reset, please ignore this email.

Best regards,  
Tiny.ai Team
"""
    send_mail(
        subject=subject,
        message=message,
        from_email="kmnaveen432@gmail.com",
        recipient_list=[email]
    )

    return JsonResponse({"message": "Password reset link sent successfully"})



def reset_password(request):
    import json
    data = json.loads(request.body)
    token = data.get("token")
    new_password = data.get("new_password")

    record = reset_tokens.find_one({"token": token})
    if not record:
        return JsonResponse({"error": "Invalid token"}, status=400)

    if datetime.datetime.now() > record["expires_at"]:
        return JsonResponse({"error": "Token expired"}, status=400)
    
    user_id = record["user_id"]
    user = collection.find_one({"_id": ObjectId(user_id)})

    if not user:
        return JsonResponse({"error": "User not found"}, status=404)

    old_password_hashed = str(user.get("password"))
    
    # Check if new password is same as the old one
    if check_password(new_password, old_password_hashed):
        return JsonResponse({"error": "Password was previously used"}, status=400)
    print(user_id,new_password)
    hashed_new_password = make_password(new_password)
    collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"password": hashed_new_password}}
    )

    reset_tokens.delete_one({"token": token})

    return JsonResponse({"message": "Password updated successfully"})


@api_view(['POST'])
@permission_classes([AllowAny])
def google_login_view(request):
    credential = request.data.get('credential')

    if not credential:
        return Response({"error": "Google credential is required"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        # Verify the token with Google's library
        idinfo = id_token.verify_oauth2_token(credential, google_requests.Request())

        email = idinfo.get('email')
        name = idinfo.get('name')
        if not email:
            return Response({"error": "Invalid Google token"}, status=status.HTTP_400_BAD_REQUEST)

        # Check if user already exists
        user = collection.find_one({"email": email})

        if not user:
            # Register new user
            user_data = {
                "email": email,
                "name":name,
                "password":random.randint(100000, 999999),  
    #             "google_id": idinfo.get('sub'),
    # "picture": idinfo.get('picture'),
    # "email_verified": idinfo.get('email_verified'),
                "login_using":"google",
                "created_at": datetime.datetime.now()
            }
            insert_result = collection.insert_one(user_data)
            user_data['_id'] = insert_result.inserted_id
        else:
            user_data = user

        # Generate JWT token
        payload = {
            'user_id': str(user_data['_id']),
            'email': user_data['email'],
            'name': user_data['name'],
            'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7),
            'iat': datetime.datetime.now(datetime.timezone.utc),
        }

        token = jwt.encode(
            payload,
            settings.JWT_CONFIG['SIGNING_KEY'],
            algorithm=settings.JWT_CONFIG['ALGORITHM']
        )

        return Response({
            "message": "Google login successful",
            "token": token,
            "user": {
                "id": str(user_data['_id']),
                "email": user_data['email'],
                'name': user_data['name'],
                "joinedAt": user_data['created_at'].strftime("%Y-%m-%d %H:%M:%S") if 'created_at' in user_data else None,
            }
        })

    except ValueError as e:
        print("Google token verification failed:", str(e))
        return Response({"error": "Invalid Google credential"}, status=status.HTTP_401_UNAUTHORIZED)

    except Exception as e:
        print("Google login error:", str(e))
        return Response({"error": "Google login failed"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)





@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def protected_view(request):
    print(request.user)
    return Response({
        "message": "You are authenticated!",
        "user": {
            "id": str(request.user._id), 
            "email": request.user.email,
            "name": request.user.name,
            "joinedAt": request.user.created_at.strftime("%Y-%m-%d %H:%M:%S")
        }
    })

@api_view(['PUT'])
@permission_classes([AllowAny])
def change_password_view(request):
    print(request.data)
    id = request.data.get('id')
    old_password = request.data.get('currentPassword')
    new_password = request.data.get('newPassword')

    if not id or not old_password or not new_password:
        return Response({"error": "All fields are required"}, status=status.HTTP_400_BAD_REQUEST)
    print("hii")
    user = collection.find_one({"_id": ObjectId(id)})
    print(user)
    if not user:
        return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    if not check_password(old_password, user['password']):
        return Response({"message": "Old password is incorrect"}, status=status.HTTP_403_FORBIDDEN)

    hashed_new_password = make_password(new_password)
    collection.update_one({"_id":  ObjectId(id)}, {"$set": {"password": hashed_new_password}})
    return Response({"message": "Password changed successfully"}, status=status.HTTP_200_OK)

@api_view(['DELETE'])
@permission_classes([AllowAny])
def delete_account_view(request):
    print(request.data)
    id = request.data.get('id')

    if not id:
        return Response({"error": "ID is required"}, status=status.HTTP_400_BAD_REQUEST)
    user_data = collection.find_one({"_id": ObjectId(id)})
    
    if not user_data:
        return Response({"error": "Account not found"}, status=status.HTTP_404_NOT_FOUND)
    deleted_account_collection.insert_one(user_data)
    result = collection.delete_one({"_id": ObjectId(id)})  # Using _id for deletion
    if result.deleted_count == 1:
        return Response({"message": "Account deleted successfully"}, status=status.HTTP_200_OK)
    else:
        return Response({"error": "Account not found"}, status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
@permission_classes([AllowAny])
def registerUser(request):
    email = request.data.get('email')
    password = request.data.get('password')
    
    # Input validation
    if not email or not password:
        return Response({"error_message": "Email and password are required"}, status=status.HTTP_400_BAD_REQUEST)

    # Check if user already exists
    existing_user = collection.find_one({"email": email})
    if existing_user:
      
        return Response({"error_message": "User email already exists"}, status=status.HTTP_400_BAD_REQUEST)

    # Hash the password before saving
    hashed_password = make_password(password)

    # Create a new user in MongoDB
    new_user = {
        "email": email,
        "password": hashed_password,
        "name": email.split("@")[0].rstrip("0123456789") or "User",
        "login_using":"email",
       
        "created_at": datetime.datetime.now()
    }
    
    result = collection.insert_one(new_user)

    # Return success response
    return Response({
        "message": "User registered successfully",
        "user": {
            "id": str(result.inserted_id),
            "email": email,
           
        }
    }, status=status.HTTP_201_CREATED)
    
    
@api_view(['POST'])
@permission_classes([AllowAny])
def loginUser(request):
    email = request.data.get('email')
    password = request.data.get('password')
    print(password)
    if not email or not password:
        return Response({"error_message": "Email and password are required"}, 
                       status=status.HTTP_400_BAD_REQUEST)

    try:
        user = collection.find_one({"email": email})
        
        if not user:
            return Response({"error_message": "Email not found"}, 
                          status=status.HTTP_401_UNAUTHORIZED)
        print(user['password'])
        if not check_password(password, str(user['password'])):
            print("Password check failed")
            return Response({"error_message": "Invalid Credentials"}, 
                          status=status.HTTP_401_UNAUTHORIZED)
       
        payload = {
            'user_id': str(user['_id']),
            'email': user['email'],
            'name': user['name'],
            'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7),
            'iat': datetime.datetime.now(datetime.timezone.utc),  # Explicit UTC time
        }
        
        token = jwt.encode(
            payload,
            settings.JWT_CONFIG['SIGNING_KEY'],
            algorithm=settings.JWT_CONFIG['ALGORITHM']
        )
    
        return Response({
            "message": "Login successful",
            "token": token,  
            "user": {
                "id": str(user['_id']),
                "email": user['email'],
                "name":user['name'],
                "joinedAt": user['created_at'].strftime("%Y-%m-%d %H:%M:%S"),
            }
        }, status=status.HTTP_200_OK)

    except Exception as e:
        print(f"Login error: {str(e)}")
        return Response({"error_message": "Login failed"}, 
                      status=status.HTTP_500_INTERNAL_SERVER_ERROR)




