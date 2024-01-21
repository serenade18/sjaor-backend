"""
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework import routers
from django.conf import settings
from django.conf.urls.static import static

from sjaorApp import views
from sjaorApp.views import SuperUserRegistrationView

router = routers.DefaultRouter()
router.register("news", views.NewsViewSet, basename="news")
router.register("popes-prayers", views.PopesPrayerIntentionsViewSet, basename="popes-prayers")

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),
    path('auth/', include('djoser.urls')),
    path('auth/', include('djoser.urls.jwt')),
    path('auth/', include('djoser.urls.authtoken')),
    path('auth/', include('djoser.social.urls')),
    path('auth/superuser/', SuperUserRegistrationView.as_view({'post': 'create_superuser'}),\
         name='superuser-registration'),
]

# Serve media files during development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
