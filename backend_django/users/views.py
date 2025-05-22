from django.shortcuts import render, redirect
from django.urls import reverse_lazy, reverse
from django.views import View
from django.contrib.messages.views import SuccessMessageMixin
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.contrib.auth import logout
from django.http import HttpResponseRedirect
from django.contrib.auth.views import LoginView
from .forms import RegisterUserForm, CustomLoginUserForm


class CreateUserView(View):
    def get(self, request):
        return render(request, 'register_user.html')
    
    def post(self, request):
        form = RegisterUserForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password1'])
            user.save()
            messages.success(request, 'User successfully registered')
            return redirect('start_page')
        email = request.POST.get('email')
        return render(
            request,
            'register_user.html',
            {'form': form, 'email': email}
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
