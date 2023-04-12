from django.shortcuts import render
from rest_framework import generics, status, views
from .serializers import RegisterSerializer, RequestPasswordEmailRequestSerializer, EmailVerificationSerializer, LoginSerializer, SetNewPassordSerializer
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
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import Util         


class RegisterView(generics.GenericAPIView):

    serializer_class = RegisterSerializer

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])

        token = RefreshToken.for_user(user).access_token

        current_site = get_current_site(request).domain
        relativeLink = reverse('email-verify')
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


class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exceptions=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class RequestPasswordResetEmail(generics.GenericAPIView):

    serializer_class = RequestPasswordEmailRequestSerializer

    def post(self, request):

        serializer = self.serializer_class(data=request.data)
        
        email = request.data['email']
        
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(
                request=request).domain
            relativeLink = reverse(
                'password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
            absurl = 'http://' + current_site + relativeLink
            email_body = 'Olá!\n Utilize o link abaixo para resetar a sua senha \n' + absurl
            data = {'email_body': email_body, 'to_email': user.email,
                    'email_subject': 'Resetando a senha!'}

            Util.send_email(data)
        return Response({'Sucesso!': 'Enviamos um link para redefinir sua senha'}, status=status.HTTP_200_OK)


class PasswordTokenCheckAPI(generics.GenericAPIView):
    def get(self, request, uidb64, token):
        
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            
            if PasswordTokenCheckAPI().check_token(user, token):
                return Response({'error': 'Token não é valido, porfavor solicite um novo'}, status=status.HTTP_401_UNAUTHORIZED)
            
            return Response({'Sucesso!' :True, 'mensagem': 'Credenciais Valida!', 'uidb64': uidb64, 'token': token}, status=status.HTTP_200_OK)
        
        except DjangoUnicodeDecodeError as identifier:
            return Response({'error': 'Token não é valido, porfavor solicite um novo'}, status=status.HTTP_401_UNAUTHORIZED)


class SetNewPassordAPIView(generics.GenericAPIView):
    serializer_class= SetNewPassordSerializer
    
    def patch(self,request):
        serializer=self.serializer_class(data=request.data)
        
        serializer.is_valid(raise_exception=True)
        return Response({'Sucesso!':True, 'mensagem': 'Senha alterado com sucesso'},status=status.HTTP_200_OK)