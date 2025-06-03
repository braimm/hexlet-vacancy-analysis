from django.contrib.auth import get_user_model
from django.db import OperationalError
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from backend_django.users.mail import safe_send_mail
import users.exceptions as custom_ex
from users.validators import check_error_validation, normalize_email

from .tokens import account_activation_token
from django.urls import reverse

User = get_user_model()

def generate_activation_link(user, domain):
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = account_activation_token.make_token(user)
        activation_link = reverse("activate", kwargs={"uidb64": uid, "token": token})
        return f"http://{domain}{activation_link}"

def register_user(data):
    # Validation
    if check := check_error_validation(data):
        msg, status = check
        raise custom_ex.ValidationError(message=msg, code=status)

    # Create a user
    email = normalize_email(data.get("email"))
    password = data.get("password")
    try:
        user = User.objects.create_user(email=email)
        user.set_password(password)
        user.is_active = False
        user.save()
    except OperationalError:
        raise custom_ex.CreateUserError(message="Database Errors", code=500)

    # Send message with activation link
    domain = data["domain"]
    activate_url = generate_activation_link(user, domain)
    
    message = render_to_string("activation_email.html", {
        "user": user,
        "activate_url": activate_url,
    })
    try:
        safe_send_mail(message=message, recipient=[user.email])
    except custom_ex.SendEmailError as e:
        raise

    # Success
    return user.id
