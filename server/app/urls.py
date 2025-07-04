from django.urls import path
from .views import  change_password_view, chat_with_ai, delete_account_view, google_login_view, registerUser,loginUser,protected_view, reset_password, send_reset_link


from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)




urlpatterns = [
     path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/register/', registerUser),
    path('api/login/', loginUser),
    path('api/protected/', protected_view), 
     path('api/changePassword/', change_password_view),
    path('api/deleteAccount/', delete_account_view),
    path('api/auth/google/', google_login_view),
     path('api/send-reset-link/', send_reset_link, name='send-reset-link'),
    path('api/reset-password/', reset_password, name='reset-password'),
    path('api/chat/', chat_with_ai, name='chat-with-ai'),
]
