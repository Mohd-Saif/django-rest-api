from django.contrib import admin
from django.urls import path, include


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include("account.urls")),  # Replace 'your_app' with the actual app name
]

