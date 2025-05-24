from django.forms import CharField, PasswordInput
from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from django.utils.translation import gettext_lazy as _
import re


SHORT_PASSWORD_MSG = 'Pass must contain at least 8 characters, \
                        mininum one digital and one big letter'
PASS_NO_MATCH_MSG = 'The passwords entered do not match.'
EMAIL_ALREADY_EXIST_MSG = 'This Email already exists.'
ACCEPT_TERMS_MSG = 'Agreement to terms and condition'

class CustomLoginUserForm(forms.Form):
    email = forms.EmailField(label='Email')
    password = CharField(label='Password', widget=PasswordInput)

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request', None)
        super().__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get('email')
        password = cleaned_data.get('password')

        user = authenticate(email=email, password=password)
        if user is None:
            raise forms.ValidationError('Invalid login or password')
        self.user = user
        return cleaned_data
    
    def get_user(self):
        return getattr(self, 'user', None)


class RegisterUserForm(forms.ModelForm):
    email = forms.EmailField(
        max_length=320,
        required=True,
        label='email'
    )
    password1 = forms.CharField(
        label=_('Password'),
        widget=forms.PasswordInput,
        required=True
    )
    password2 = forms.CharField(
        label=_('Password Confirmation'),
        widget=forms.PasswordInput,
        required=True
    )
    accept_terms = forms.BooleanField(
        label="I agree to the terms",
        required=True
    )

    class Meta:
        model = get_user_model()
        fields = ['email', 'password1']

    def clean_accept_terms(self):
        accept = self.cleaned_data['accept_terms']
        if accept == False:
            raise forms.ValidationError(ACCEPT_TERMS_MSG)
        return accept

    def clean_email(self):
        email = self.cleaned_data['email']
        if get_user_model().objects.filter(email=email).exists():
            raise forms.ValidationError(EMAIL_ALREADY_EXIST_MSG)
        return email

    def clean_password2(self):
        cd = self.cleaned_data
        if cd.get('password1') and cd.get('password1') != cd.get('password2'):
            raise forms.ValidationError(PASS_NO_MATCH_MSG)
        if not re.match(r'^(?=.*[A-Z])(?=.*\d).{8,}$', cd['password2']):
            raise forms.ValidationError(SHORT_PASSWORD_MSG)
        return cd['password2']


# class UpdateUserForm(forms.Form):
#     first_name = forms.CharField(max_length=150, label=_('First name'))
#     last_name = forms.CharField(max_length=150, label=_('Last name'))
#     username = forms.CharField(
#         max_length=150,
#         required=True,
#         label=_('User name')
#     )
#     password1 = forms.CharField(
#         label=_('Password'),
#         widget=forms.PasswordInput
#     )
#     password2 = forms.CharField(
#         label=_('Password Confirmation'),
#         widget=forms.PasswordInput
#     )

#     def clean_username(self):
#         username = self.cleaned_data.get('username')
#         if not re.match(r'^[\w.@+-]+$', username):
#             message = _(
#                 'Please enter a valid username. \
#                     It can only contain letters, numbers and @/./+/-/_ signs.')
#             raise forms.ValidationError(message)
#         return username

#     def clean_password2(self):
#         cd = self.cleaned_data
#         if cd.get('password1') and cd.get('password1') != cd.get('password2'):
#             raise forms.ValidationError(PASS_NO_MATCH_MSG)
#         if len(cd['password2']) < 3:
#             raise forms.ValidationError(SHORT_PASSWORD_MSG)
#         return cd['password2']