
from django.contrib import admin
from django.urls import path
from django.contrib import admin
from django.urls import path, include  # Ensure `include` is imported
from django.urls import path, include
from users.views import RegisterView, LoginView, UserView, LogoutView ,VerifierEmailView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include([
        path('register/', RegisterView.as_view()),
        path('login/', LoginView.as_view()),
        path('user/', UserView.as_view()),
        path('logout/', LogoutView.as_view()),
        path('verify-email/', VerifierEmailView.as_view(), name='verify-email'),

    ])),
]
