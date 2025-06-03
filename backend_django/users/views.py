import json
from django.views import View
from django.contrib.auth import get_user_model
from django.contrib.auth import logout, login, authenticate
from django.http import JsonResponse
from users.utils import read_data_from_request
from users.authentication import generate_activation_link, register_user
from users.validators import check_error_validation, normalize_email
import users.exceptions as custom_ex
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.contrib.auth import get_user_model
from django.core.mail import send_mail

from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.contrib.sites.shortcuts import get_current_site
from .tokens import account_activation_token
import logging

User = get_user_model()

logger = logging.getLogger(__name__)

#************************************# Rest API (non DRF) #***********************************************

@method_decorator(csrf_exempt, name="dispatch")
class CreateUserView(View):
    def get(self, request):
        pass

    def post(self, request):
        try:
            data  = read_data_from_request(request)
            data["domain"] = get_current_site(request).domain
            result =  register_user(data)
            return JsonResponse(
                {"status": "ok", "data": {"userId": result}},
                status=201
            )
        except custom_ex.ValidationError as e:
            logger.error(f"Validation Error: {e.message}")
            return e.to_response()

        except custom_ex.CreateUserError as e:
            logger.error(f"Error creating user: {e.message}")
            return e.to_response()

        except custom_ex.SendEmailError as e:
            logger.error(f"Error sending activation link: {e.message}")
            return e.to_response()
        
        except custom_ex.CustomBaseError:
            logger.error(f"Unknown error: {e.message}")
            return e.to_response()


class ActivateUser(View):
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user and account_activation_token.check_token(user, token):
            user.is_active = True
            user.save()
            logger.info(f"User '{user.email}' registration completed successfully")
            return JsonResponse(
                {"status": "ok", "data": {"userId": uid}},
                status=201
            )
        else:
            return JsonResponse(
                {"status": "error", "message": "Activation link is invalid"},
                status=400
            )


@method_decorator(csrf_exempt, name="dispatch")
class LoginUserView(View):
   def post(self, request):
        if request.content_type != "application/json":
            return JsonResponse({"status": "error", "message": "Expected application/json"}, status=415)

        # Trying to read JSON
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"status": "error", "message": "Invalid JSON"}, status=400)
        
        email = normalize_email(data.get("email"))
        password = data.get("password")

        if not (email and password):
            return JsonResponse({"status": "error", "message": "Email and password required"}, status=400)
        
        user = authenticate(request, email=email, password=password)

        if user is None: 
            return JsonResponse({"status": "error", "message": "Invalid credential"}, status=400)
        
        if not user.is_active:
            return JsonResponse({"status": "error", "message": "User in not active"}, status=400)
        
        login(request, user)
        return JsonResponse({"status": "ok", "data": {"userId": user.id}}, status=200)

@method_decorator(csrf_exempt, name="dispatch")
class LogoutUserView(View):
    def post(self, request):
        logout(request)
        return JsonResponse({"status": "ok", "message": "User logged out"}, status=200)
