from django.urls import path
from . import views


urlpatterns = [
    path('register/', views.CreateUserView.as_view(), name='register_user'),
    path('login/', views.LoginUserView.as_view(), name='login'),
    path('logout/', views.LogoutUserView.as_view(), name='logout'),
    # path(
    #     '<int:pk>/delete/',
    #     views.DeleteUserView.as_view(),
    #     name='delete_user'
    # ),
    # path(
    #     '<int:pk>/update/',
    #     views.UpdateUserView.as_view(),
    #     name='update_user'
    # ),
]