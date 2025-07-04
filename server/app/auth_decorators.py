from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
import jwt
from django.conf import settings
from pymongo import MongoClient
from bson import ObjectId



from django.contrib.auth.models import AnonymousUser

class MongoDBUser:
    def __init__(self, user_dict):
        self.user_dict = user_dict
        self.is_authenticated = True 

    def __getattr__(self, name):
        try:
            return self.user_dict[name]
        except KeyError:
            raise AttributeError(name)



# MongoDB Client setup
uri = "mongodb+srv://kmnaveen1110:Naveen%40123@cluster0.kqdhrnt.mongodb.net/techmiyaai?retryWrites=true&w=majority"
client = MongoClient(uri)
db = client['techmiyaai']
collection = db['auth_user']

class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return None
            
        try:
            token = auth_header.split(' ')[1]
            decoded = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=['HS256'],
                options={'verify_iat': True, 'leeway': 30}
            )
            # print("Decoded JWT:", decoded)  # Debugging line
            user_id = decoded.get('user_id')
            if not user_id:
                raise AuthenticationFailed('Invalid token')
                
            user = collection.find_one({"_id": ObjectId(user_id)})
            
            if not user:
                raise AuthenticationFailed('User not found')
            
            # Convert to our custom user class
            return (MongoDBUser(user), None)
            
        except Exception as e:
            raise AuthenticationFailed(str(e))