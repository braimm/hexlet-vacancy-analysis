import json
import re
from django.shortcuts import render, redirect
from django.urls import reverse_lazy, reverse
from django.views import View
from django.contrib.messages.views import SuccessMessageMixin
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.contrib.auth import logout, login
from django.http import HttpResponseRedirect, JsonResponse
from django.contrib.auth.views import LoginView
from .forms import SHORT_PASSWORD_MSG, RegisterUserForm, CustomLoginUserForm
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.urls import reverse
from .tokens import account_activation_token
from django.core.validators import validate_email
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator


#************************************# Rest API (non DRF) #***********************************************

@method_decorator(csrf_exempt, name='dispatch')
class CreateUserView(View):
    def get(self, request):
        pass

    def post(self, request):
        if request.content_type != 'application/json':
            return JsonResponse({"status": "error", "message": 'Expected application/json'}, status=415)

        # Trying to read JSON
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"status": "error", "message": 'Invalid JSON'}, status=400)

        # Parse fields
        email = data.get('email')
        password = data.get('password')
        password_again = data.get('passwordAgain')
        accept_terms = data.get('acceptTerms')

        # Validation
        User = get_user_model()
        if not all([email, password, password_again, accept_terms]):
            return JsonResponse({"status": "error", "message": "All fields are required"}, status=400)
        if validate_email(email):
            return JsonResponse({"status": "error", "message": "Invalid email"}, status=400)
        if password != password_again:
            return JsonResponse({"status": "error", "message": "Passwords do not match"}, status=400)
        if not re.match(r'^(?=.*[A-Z])(?=.*\d).{8,}$', password):
            return JsonResponse({"status": "error", "message": SHORT_PASSWORD_MSG}, status=400)
        if not accept_terms:
            return JsonResponse({"status": "error", "message": "Terms must be accepted"}, status=400)
        if User.objects.filter(email=email).exists():
            return JsonResponse({"status": "error", "message": "Email already registered"}, status=409)

        # Create a user
        user = User.objects.create_user(email=email)
        user.set_password(password)
        user.is_active = False
        user.save()

        # Generate activation link
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = account_activation_token.make_token(user)
        domain = get_current_site(request).domain
        activation_link = reverse('activate', kwargs={'uidb64': uid, 'token': token})
        activate_url = f"http://{domain}{activation_link}"

        # Send message
        message = render_to_string('activation_email.html', {
            'user': user,
            'activate_url': activate_url,
        })

        send_mail(
            subject='Подтвердите регистрацию',
            message=message,
            from_email='noreply@example.com',
            recipient_list=[user.email],
        )

        return JsonResponse(
            {"status": "ok", "data": {"userId": user.id}},
            status=201
        )

class ActivateUser(View):
    def get(self, request, uidb64, token):
        User = get_user_model()
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user and account_activation_token.check_token(user, token):
            user.is_active = True
            user.save()
            login(request, user)
            return JsonResponse(
                {"status": "ok", "data": {"userId": uid}},
                status=409
            )
        else:
            return JsonResponse(
                {"status": "error", "message": "Activation link is invalid"},
                status=400
            )


class LoginUserView(SuccessMessageMixin, LoginView):
    form_class = CustomLoginUserForm
    template_name = 'login.html'
    next_page = reverse_lazy('start_page')
    success_message = 'You are logged in'


class LogoutUserView(View):
    def post(self, request):
        logout(request)
        messages.info(request, 'You are logged out')
        return HttpResponseRedirect(reverse('start_page'))


#************************************# classic #***********************************************


class CreateUserView_classic(View):
    def get(self, request):
        return render(request, 'register_user.html')
    
    def post(self, request):
        form = RegisterUserForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False
            user.set_password(form.cleaned_data['password1'])
            user.save()
            
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = account_activation_token.make_token(user)
            domain = get_current_site(request).domain
            activation_link = reverse('activate_classic', kwargs={'uidb64': uid, 'token': token})
            activate_url = f"http://{domain}{activation_link}"

            message = render_to_string('activation_email.html', {
            'user': user,
            'activate_url': activate_url,
            })

            send_mail(
            subject='Подтвердите регистрацию',
            message=message,
            from_email='noreply@example.com',
            recipient_list=[user.email],
            )

            messages.success(request, 'User successfully registered, confirm to email')
            return redirect('login_classic')
        email = request.POST.get('email')
        return render(
            request,
            'register_user.html',
            {'form': form, 'email': email}
        )


def activate_user_classic(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        login(request, user)
        messages.success(request, 'User successfully activated, email is confirm')
        return redirect('start_page')
    else:
        messages.error(request, 'User activated is failed.')
        return redirect('start_page')


class LoginUserView_classic(SuccessMessageMixin, LoginView):
    form_class = CustomLoginUserForm
    template_name = 'login.html'
    next_page = reverse_lazy('start_page')
    success_message = 'You are logged in'


class LogoutUserView_classic(View):
    def post(self, request):
        logout(request)
        messages.info(request, 'You are logged out')
        return HttpResponseRedirect(reverse('start_page'))


# class UpdateUserView(NoLogin, UpdateView):
#     model = get_user_model()
#     form_class = RegisterUserForm
#     success_url = reverse_lazy("start_page")
#     template_name = 'users/update_user.html'

#     def get(self, request, pk):
#         if pk != request.user.pk:
#             messages.error(
#                 request,
#                 'You do not have permission to modify another user.'
#             )
#             return redirect(reverse_lazy('start_page'))
#         return super().get(request, pk)

#     def post(self, request, pk):
#         form = UpdateUserForm(request.POST)
#         input_username = request.POST.get('username')
#         current_username = request.user.username
#         is_conflict_username = False
#         if current_username != input_username:
#             is_conflict_username = get_user_model().objects.\
#                 filter(username=input_username).exists()

#         if form.is_valid() and not is_conflict_username:
#             user = get_user_model().objects.get(pk=pk)
#             user.first_name = form.cleaned_data['first_name']
#             user.last_name = form.cleaned_data['last_name']
#             user.username = form.cleaned_data['username']
#             user.set_password(form.cleaned_data['password1'])
#             user.save()
#             messages.success(request, 'User successfully updated')
#             return redirect('start_page')
#         if is_conflict_username:
#             form.add_error(
#                 'username',
#                 'A user with this name already exists.'
#             )

#         return render(
#             request,
#             'users/update_user.html',
#             {'form': form, 'username': input_username}
        # )


# class DeleteUserView(NoLogin, View):
#     def get(self, request, pk):
#         if request.user.pk != pk:
#             messages.error(
#                 request,
#                 'You do not have permission to modify another user.'
#             )
#             return redirect('start_page')
#         return render(request, 'users/delete_user.html')

#     def post(self, request, pk):
#         user = get_user_model().objects.get(pk=pk)
#         if user.author.exists() or user.executor.exists():
#             messages.error(
#                 request,
#                 _('Cannot delete user because it is in use')
#             )
#             return redirect('start_page')
#         user.delete()
#         messages.success(request, 'User successfully delete')
#         return redirect('start_page')
