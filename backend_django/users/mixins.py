from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.utils.translation import gettext as _


class NoLogin(LoginRequiredMixin):
    login_url = 'login'

    def get_login_url(self):
        messages.error(
            self.request, _('You are not logged in! Please sign in.')
        )
        return super().get_login_url()
