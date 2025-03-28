from django.conf import settings
from django.http import JsonResponse
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        encrypted_password = attrs.get('password')
        decrypted_password = decrypt_payload(encrypted_password)
        attrs['password'] = decrypted_password
        return super().validate(attrs)

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

def get_public_key(request):
    return JsonResponse({"public_key": settings.PUBLIC_KEY})

def decrypt_payload(encrypted_b64):
    private_key = serialization.load_pem_private_key(
        settings.PRIVATE_KEY.encode(), password=None
    )
    encrypted_bytes = base64.b64decode(encrypted_b64)
    decrypted = private_key.decrypt(
        encrypted_bytes,
        padding.PKCS1v15()
    )
    return decrypted.decode()