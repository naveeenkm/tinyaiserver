from django.utils.deprecation import MiddlewareMixin
from django.conf import settings

class MongoDBMiddleware(MiddlewareMixin):
    def __init__(self, get_response):
        super().__init__(get_response)
        self.get_response = get_response
        self.db = settings.db  # From your settings.py

    def __call__(self, request):
        request.app = type('App', (), {'db': self.db})
        response = self.get_response(request)
        return response