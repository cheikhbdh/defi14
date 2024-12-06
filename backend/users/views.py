from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from rest_framework import status
from rest_framework.permissions import BasePermission
from .models import CustomUser
from .serializers import UserSerializer
import jwt
import datetime
import random
from django.core.mail import send_mail


class IsAuthenticated(BasePermission):
    def has_permission(self, request, view):
        token = request.headers.get('Authorization')

        if not token:
            raise AuthenticationFailed('Token not provided', code='token_not_provided')

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Token has expired', code='token_expired')

        user = CustomUser.objects.filter(id_u=payload['id']).first()
        if user is None:
            raise AuthenticationFailed('User not found!', code='user_not_found')

        return True


class VerifierEmailView(APIView):
    def post(self, request):
        email = request.data.get('email')
        verification_code = ''.join(random.choices('0123456789', k=6))
        send_mail(
            'Email Verification Code',
            f'Your email verification code is: {verification_code}',
            '22034@supnum.mr',
            [email],
            fail_silently=False,
        )
        return Response({"verification_code": verification_code}, status=status.HTTP_200_OK)


class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response({"error": "cette email est deja exist"}, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self, request):
        login_or_email = request.data.get('login_or_email')
        password = request.data.get('password')

        if '@' in login_or_email:
            user = CustomUser.objects.filter(email=login_or_email).first()
        else:
            user = CustomUser.objects.filter(login=login_or_email).first()

        if user is None:
            raise AuthenticationFailed('User not found!', code='user_not_found')

        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect password!', code='incorrect_password')

        payload = {
            'id': user.id_u,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=6),
            'iat': datetime.datetime.utcnow()
        }
        token = jwt.encode(payload, 'secret', algorithm='HS256')

        response = Response({'jwt': token})
        response.set_cookie(key='jwt', value=token, httponly=True, secure=False, samesite='Lax')
        return response


class UserView(APIView):
    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            return Response({'error': 'Unauthenticated!'}, status=401)

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({'error': 'Token has expired!'}, status=401)
        except jwt.InvalidTokenError:
            return Response({'error': 'Invalid token!'}, status=401)

        user = CustomUser.objects.filter(id_u=payload['id']).first()

        if not user:
            return Response({'error': 'User not found!'}, status=404)

        serializer = UserSerializer(user)
        return Response(serializer.data)


class LogoutView(APIView):
    def post(self, request):
        response = Response({'message': 'success'})
        response.delete_cookie('jwt')
        return response
