from django.shortcuts import render
from rest_framework import generics, status, views
from .serializers import RegisterSerializer, EmailVerificationSerializer
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
import jwt
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi


class RegisterView(generics.GenericAPIView):

    serializer_class = RegisterSerializer

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])

        current_site = get_current_site(request).domain
        relativeLink = reverse('email-verify')
        token = RefreshToken.for_user(user).access_token
        absurl = 'http://' + current_site + relativeLink+"?token=" + str(token)
        email_body = 'Olá, ' + user.username + \
            '!\n Utilize o link abaixo para verificar o seu e-mail\n' + absurl
        data = {'email_body': email_body, 'to_email': user.email,
                'email_subject': 'Verificação de e-mail!'}

        Util.send_email(data)

        return Response(user_data, status.HTTP_201_CREATED)


class VerifyEmail(views.APIView):
    serializer_class = EmailVerificationSerializer
    token_param_config = openapi.Parameter(
        'token', in_=openapi.IN_QUERY, description='Description', type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY)
            user = User.objects.get(id=payload['user_id'])

            if not user.is_verified:
                user.is_verified = True
                user.save()

            return Response({'email': 'Ativado com sucesso!'}, status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as expiredSignatureError:
            return Response({'error': 'Link expirado!'}, status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as decodeError:
            return Response({'error': 'Token inválido!'}, status.HTTP_400_BAD_REQUEST)