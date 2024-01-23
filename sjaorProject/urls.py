"""
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework import routers
from django.conf import settings
from django.conf.urls.static import static

from sjaorApp import views
from sjaorApp.views import SuperUserRegistrationView, DocumentOnlyViewSet

router = routers.DefaultRouter()
router.register("news", views.NewsViewSet, basename="news")
router.register("catalogues", views.CataloguesViewSet, basename="catalogues")
router.register("popes-prayers", views.PopesPrayerIntentionsViewSet, basename="popes-prayers")
router.register("ignatian-thoughts", views.IgnatianThoughtsViewSet, basename="ignatian-thoughts")
router.register("documents", views.DocumentViewSet, basename="documents")
router.register("shukran", views.ShukranViewSet, basename="shukran")
router.register("documents-category", views.DocumentCategoryViewSet, basename="documents-category")
router.register("dashboard", views.DashboardApi, basename="dashboard")

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),
    path('auth/', include('djoser.urls')),
    path('auth/', include('djoser.urls.jwt')),
    path('auth/', include('djoser.urls.authtoken')),
    path('auth/', include('djoser.social.urls')),
    path('auth/superuser/', SuperUserRegistrationView.as_view({'post': 'create_superuser'}),\
         name='superuser-registration'),
    path('api/documentonly/', DocumentOnlyViewSet.as_view(), name="documentonly"),
]

# Serve media files during development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
