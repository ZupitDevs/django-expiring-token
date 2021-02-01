from django.contrib.auth import authenticate
from django.utils import timezone
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_200_OK
from rest_framework.views import APIView

from drf_expiring_token.authentication import token_expire_handler
from drf_expiring_token.models import ExpiringToken
from drf_expiring_token.serializers import UserSigninSerializer


class LoginView(APIView):
    serializer_class = UserSigninSerializer
    permission_classes = []

    def post(self, request):
        signin_serializer = UserSigninSerializer(data=request.data)
        if not signin_serializer.is_valid():
            return Response(signin_serializer.errors, status=HTTP_400_BAD_REQUEST)

        user = authenticate(
            username=signin_serializer.data['username'],
            password=signin_serializer.data['password']
        )

        if not user:
            return Response({'detail': 'Invalid Credentials'}, status=HTTP_400_BAD_REQUEST)
        # TOKEN STUFF
        token, _ = ExpiringToken.objects.get_or_create(user=user)

        # token_expire_handler will check, if the token is expired it will generate new one
        is_expired, token = token_expire_handler(token)  # The implementation will be described further
        return Response({
            'token': token.key
        }, status=HTTP_200_OK)

class LogoutView(APIView):
    permission_classes = [IsAuthenticated,]

    def post(self, request):
        token = ExpiringToken.objects.get(user=request.user)
        token.expires = timezone.now()
        token.save()
        return Response(status=HTTP_200_OK)
