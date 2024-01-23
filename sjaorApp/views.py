from django.shortcuts import render, get_object_or_404
from djoser.views import UserViewSet
from rest_framework import generics, status, viewsets
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework_simplejwt.authentication import JWTAuthentication

from sjaorApp import serializers
from sjaorApp.models import UserAccount, News, PopesPrayerIntentions, Adusums, Products, Catalogues, Documents, \
    DocumentCategory, Shukran, IgnatianThoughts
from sjaorApp.serializers import UserAccountSerializer, NewsSerializer, PopesPrayerIntentionsSerializer, \
    AdusumsSerializer, ProductsSerializer, CataloguesSerializer, DocumentSerializer, DocumentCategorySerializer, \
    ShukranSerializer, IgnatianThoughtsSerializer

from django.contrib.auth import get_user_model

User = get_user_model()

# Create your views here.


class SuperUserRegistrationView(UserViewSet):
    # Override get_permissions method to allow unauthenticated access only for create_superuser action
    def get_permissions(self):
        if self.action == "create_superuser":
            return [AllowAny()]
        return super().get_permissions()

    @action(["post"], detail=False, url_path="superuser")
    def create_superuser(self, request, *args, **kwargs):
        serializer = serializers.UserCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Create the user object using serializer.save()
        user = serializer.save(user_type='admin')  # Set the user_type to 'admin'

        if user:
            # Set user as a superuser and staff
            user.is_superuser = True
            user.is_staff = True
            user.is_active = True
            user.save()

            return Response({"error": False, "message": "Admin account created and activated successfully"}, status=status.HTTP_201_CREATED)
        else:
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserAccountUpdateView(generics.UpdateAPIView):
    serializer_class = UserAccountSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        user_id = self.kwargs.get('user_id')
        user = self.request.user

        if user_id:
            # If a user_id is provided, check if the user is an admin
            if user.is_staff:
                # Admin can edit name and phone of other users
                return get_object_or_404(User, id=user_id)

        # If no user_id or if the user is not an admin, allow users to update their own accounts
        return user

    def perform_update(self, serializer):
        user = self.request.user

        if user.is_staff:
            # Admins can update the name and phone without email uniqueness check
            serializer.save()
        else:
            # Regular users can update all fields, including email, with email uniqueness check
            email = serializer.validated_data.get('email')
            instance = serializer.instance

            if email and User.objects.exclude(pk=instance.pk).filter(email=email).exists():
                raise serializers.ValidationError("User with this email already exists.")

            serializer.save()


class UserAccountDeleteView(generics.DestroyAPIView):
    serializer_class = UserAccountSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    queryset = UserAccount.objects.all()  # Update with the correct queryset

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()

        # You can add additional logic here if needed

        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)


class NewsViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]

    def list(self, request):
        news = News.objects.all().order_by('-id')
        serializer = NewsSerializer(news, many=True, context={"request": request})

        response_dict = {"error": False, "message": "All News", "data": serializer.data}

        return Response(response_dict)

    def create(self, request):
        try:
            serializer = NewsSerializer(data=request.data, context={"request": request})
            if serializer.is_valid():
                serializer.save()
                dict_response = {"error": False, "message": "News Posted Successfully"}
            else:
                dict_response = {"error": True, "message": "Validation Error", "errors": serializer.errors}
        except Exception as e:
            print("Error during video creation:", e)
            dict_response = {"error": True, "message": "Error During Creating Video"}

        return Response(dict_response,
                        status=status.HTTP_201_CREATED if not dict_response["error"] else status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        queryset = News.objects.all()
        news = get_object_or_404(queryset, pk=pk)
        serializer = NewsSerializer(news, context={"request": request})

        return Response({"error": False, "message": "Single Data Fetch", "data": serializer.data})

    def update(self, request, pk=None):
        try:
            queryset = News.objects.all()
            news = get_object_or_404(queryset, pk=pk)
            serializer = NewsSerializer(news, data=request.data, context={"request": request})
            serializer.is_valid(raise_exception=True)
            serializer.save()
            dict_response = {"error": False, "message": "News updated Successfully"}

        except ValidationError as e:
            dict_response = {"error": True, "message": "Validation Error", "details": str(e)}
        except Exception as e:
            dict_response = {"error": True, "message": "An Error Occurred", "details": str(e)}

        return Response(dict_response,
                            status=status.HTTP_400_BAD_REQUEST if dict_response['error'] else status.HTTP_201_CREATED)

    def destroy(self, request, pk=None):
        # if not request.user.is_staff:
        #     return Response({"error": True, "message": "User does not have enough permission to perform this task"},\
        #                     status=status.HTTP_401_UNAUTHORIZED)

        queryset = News.objects.all()
        news = get_object_or_404(queryset, pk=pk)
        news.delete()
        return Response({"error": False, "message": "News Deleted"})


class PopesPrayerIntentionsViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]

    def list(self, request):
        prayers = PopesPrayerIntentions.objects.all().order_by('-id')
        serializer = PopesPrayerIntentionsSerializer(prayers, many=True, context={"request": request})

        response_dict = {"error": False, "message": "All Popes Prayers", "data": serializer.data}

        return Response(response_dict)

    def create(self, request):
        try:
            serializer = PopesPrayerIntentionsSerializer(data=request.data, context={"request": request})
            if serializer.is_valid():
                serializer.save()
                dict_response = {"error": False, "message": "Prayers Posted Successfully"}
            else:
                dict_response = {"error": True, "message": "Validation Error", "errors": serializer.errors}
        except Exception as e:
            print("Error during video creation:", e)
            dict_response = {"error": True, "message": "Error During Creating Video"}

        return Response(dict_response,
                        status=status.HTTP_201_CREATED if not dict_response["error"] else status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        queryset = PopesPrayerIntentions.objects.all()
        prayers = get_object_or_404(queryset, pk=pk)
        serializer = PopesPrayerIntentionsSerializer(prayers, context={"request": request})

        return Response({"error": False, "message": "Single Data Fetch", "data": serializer.data})

    def update(self, request, pk=None):
        try:
            queryset = PopesPrayerIntentions.objects.all()
            prayers = get_object_or_404(queryset, pk=pk)
            serializer = PopesPrayerIntentionsSerializer(prayers, data=request.data, context={"request": request})
            serializer.is_valid(raise_exception=True)
            serializer.save()
            dict_response = {"error": False, "message": "Prayer Updated Successfully"}

        except ValidationError as e:
            dict_response = {"error": True, "message": "Validation Error", "details": str(e)}
        except Exception as e:
            dict_response = {"error": True, "message": "An Error Occurred", "details": str(e)}

        return Response(dict_response,
                            status=status.HTTP_400_BAD_REQUEST if dict_response['error'] else status.HTTP_201_CREATED)

    def destroy(self, request, pk=None):
        if not request.user.is_staff:
            return Response({"error": True, "message": "User does not have enough permission to perform this task"},\
                            status=status.HTTP_401_UNAUTHORIZED)

        queryset = PopesPrayerIntentions.objects.all()
        news = get_object_or_404(queryset, pk=pk)
        news.delete()
        return Response({"error": False, "message": "Prayers Removed"})


class CataloguesViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def list(self, request):
        catalogues = Catalogues.objects.all().order_by('-id')
        serializer = CataloguesSerializer(catalogues, many=True, context={"request": request})

        response_dict = {"error": False, "message": "All Catalogues", "data": serializer.data}

        return Response(response_dict)

    def create(self, request):
        try:
            # Get the total number of catalogues
            total_catalogues = Catalogues.objects.count()

            # Check if the limit is reached (e.g., 5)
            if total_catalogues >= 5:
                # Retrieve the oldest catalogue
                oldest_catalogue = Catalogues.objects.order_by('added_on').first()

                # Delete the oldest catalogue
                oldest_catalogue.delete()

            serializer = CataloguesSerializer(data=request.data, context={"request": request})
            if serializer.is_valid():
                serializer.save()
                dict_response = {"error": False, "message": "Catalogue Added Successfully"}
            else:
                dict_response = {"error": True, "message": "Validation Error", "errors": serializer.errors}
        except Exception as e:
            print("Error during catalogue creation:", e)
            dict_response = {"error": True, "message": "Error During Creating Catalogue"}

        return Response(dict_response,
                        status=status.HTTP_201_CREATED if not dict_response["error"] else status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        try:
            queryset = Catalogues.objects.all()
            catalogues = get_object_or_404(queryset, pk=pk)
            serializer = CataloguesSerializer(catalogues, data=request.data, context={"request": request})
            serializer.is_valid(raise_exception=True)
            serializer.save()
            dict_response = {"error": False, "message": "Catalogue Updated Successfully"}

        except ValidationError as e:
            dict_response = {"error": True, "message": "Validation Error", "details": str(e)}
        except Exception as e:
            dict_response = {"error": True, "message": "An Error Occurred", "details": str(e)}

        return Response(dict_response,
                            status=status.HTTP_400_BAD_REQUEST if dict_response['error'] else status.HTTP_201_CREATED)


class DocumentViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def list(self, request):
        documents = Documents.objects.all().order_by('-id')
        serializer = DocumentSerializer(documents, many=True, context={"request": request})

        response_dict = {"error": False, "message": "All Documents", "data": serializer.data}

        return Response(response_dict)

    def create(self, request):
        try:
            serializer = DocumentSerializer(data=request.data, context={"request": request})
            if serializer.is_valid():
                serializer.save()
                dict_response = {"error": False, "message": "Document Added Successfully"}
            else:
                dict_response = {"error": True, "message": "Validation Error", "errors": serializer.errors}
        except Exception as e:
            print("Error during catalogue creation:", e)
            dict_response = {"error": True, "message": "Error During Creating Catalogue"}

        return Response(dict_response,
                        status=status.HTTP_201_CREATED if not dict_response["error"] else status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        try:
            queryset = Documents.objects.all()
            documents = get_object_or_404(queryset, pk=pk)
            serializer = DocumentSerializer(documents, data=request.data, context={"request": request})
            serializer.is_valid(raise_exception=True)
            serializer.save()
            dict_response = {"error": False, "message": "Document Updated Successfully"}

        except ValidationError as e:
            dict_response = {"error": True, "message": "Validation Error", "details": str(e)}
        except Exception as e:
            dict_response = {"error": True, "message": "An Error Occurred", "details": str(e)}

        return Response(dict_response,
                            status=status.HTTP_400_BAD_REQUEST if dict_response['error'] else status.HTTP_201_CREATED)

    def destroy(self, request, pk=None):
        # if not request.user.is_staff:
        #     return Response({"error": True, "message": "User does not have enough permission to perform this task"},\
        #                     status=status.HTTP_401_UNAUTHORIZED)

        queryset = Documents.objects.all()
        news = get_object_or_404(queryset, pk=pk)
        news.delete()
        return Response({"error": False, "message": "Document Deleted"})


class DocumentCategoryViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]

    def list(self, request):
        doc_categories = DocumentCategory.objects.all().order_by('-id')
        serializer = DocumentCategorySerializer(doc_categories, many=True, context={"request": request})

        response_dict = {"error": False, "message": "All Categories", "data": serializer.data}

        return Response(response_dict)

    def create(self, request):
        try:
            serializer = DocumentCategorySerializer(data=request.data, context={"request": request})
            if serializer.is_valid():
                serializer.save()
                dict_response = {"error": False, "message": "Category Added Successfully"}
            else:
                dict_response = {"error": True, "message": "Validation Error", "errors": serializer.errors}
        except Exception as e:
            print("Error during video creation:", e)
            dict_response = {"error": True, "message": "Error During Creating Video"}

        return Response(dict_response,
                        status=status.HTTP_201_CREATED if not dict_response["error"] else status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        queryset = DocumentCategory.objects.all()
        news = get_object_or_404(queryset, pk=pk)
        serializer = DocumentCategorySerializer(news, context={"request": request})

        return Response({"error": False, "message": "Single Data Fetch", "data": serializer.data})

    def update(self, request, pk=None):
        try:
            queryset = DocumentCategory.objects.all()
            news = get_object_or_404(queryset, pk=pk)
            serializer = DocumentCategorySerializer(news, data=request.data, context={"request": request})
            serializer.is_valid(raise_exception=True)
            serializer.save()
            dict_response = {"error": False, "message": "Category updated Successfully"}

        except ValidationError as e:
            dict_response = {"error": True, "message": "Validation Error", "details": str(e)}
        except Exception as e:
            dict_response = {"error": True, "message": "An Error Occurred", "details": str(e)}

        return Response(dict_response,
                            status=status.HTTP_400_BAD_REQUEST if dict_response['error'] else status.HTTP_201_CREATED)

    def destroy(self, request, pk=None):
        # if not request.user.is_staff:
        #     return Response({"error": True, "message": "User does not have enough permission to perform this task"},\
        #                     status=status.HTTP_401_UNAUTHORIZED)

        queryset = DocumentCategory.objects.all()
        news = get_object_or_404(queryset, pk=pk)
        news.delete()
        return Response({"error": False, "message": "Category Deleted"})


class DocumentOnlyViewSet(generics.ListAPIView):
    serializer_class = DocumentCategorySerializer

    def get_queryset(self):
        return DocumentCategory.objects.all()


class ShukranViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def list(self, request):
        shukran = Shukran.objects.all().order_by('-id')
        serializer = ShukranSerializer(shukran, many=True, context={"request": request})

        response_dict = {"error": False, "message": "All shukran", "data": serializer.data}

        return Response(response_dict)

    def create(self, request):
        try:
            # Get the total number of shukran
            total_shukran = Shukran.objects.count()

            # Check if the limit is reached (e.g., 5)
            if total_shukran >= 4:
                # Retrieve the oldest catalogue
                oldest_shukran = Shukran.objects.order_by('added_on').first()

                # Delete the oldest catalogue
                oldest_shukran.delete()

            serializer = ShukranSerializer(data=request.data, context={"request": request})
            if serializer.is_valid():
                serializer.save()
                dict_response = {"error": False, "message": "Catalogue Added Successfully"}
            else:
                dict_response = {"error": True, "message": "Validation Error", "errors": serializer.errors}
        except Exception as e:
            print("Error during catalogue creation:", e)
            dict_response = {"error": True, "message": "Error During Creating Catalogue"}

        return Response(dict_response,
                        status=status.HTTP_201_CREATED if not dict_response["error"] else status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        try:
            queryset = Shukran.objects.all()
            shukran = get_object_or_404(queryset, pk=pk)
            serializer = ShukranSerializer(shukran, data=request.data, context={"request": request})
            serializer.is_valid(raise_exception=True)
            serializer.save()
            dict_response = {"error": False, "message": "Catalogue Updated Successfully"}

        except ValidationError as e:
            dict_response = {"error": True, "message": "Validation Error", "details": str(e)}
        except Exception as e:
            dict_response = {"error": True, "message": "An Error Occurred", "details": str(e)}

        return Response(dict_response,
                            status=status.HTTP_400_BAD_REQUEST if dict_response['error'] else status.HTTP_201_CREATED)

    def destroy(self, request, pk=None):
        # if not request.user.is_staff:
        #     return Response({"error": True, "message": "User does not have enough permission to perform this task"},\
        #                     status=status.HTTP_401_UNAUTHORIZED)

        queryset = Shukran.objects.all()
        shukran = get_object_or_404(queryset, pk=pk)
        shukran.delete()
        return Response({"error": False, "message": "Category Deleted"})


class IgnatianThoughtsViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]

    def list(self, request):
        news = IgnatianThoughts.objects.all().order_by('-id')
        serializer = IgnatianThoughtsSerializer(news, many=True, context={"request": request})

        response_dict = {"error": False, "message": "All Thoughts", "data": serializer.data}

        return Response(response_dict)

    def create(self, request):
        try:
            serializer = IgnatianThoughtsSerializer(data=request.data, context={"request": request})
            if serializer.is_valid():
                serializer.save()
                dict_response = {"error": False, "message": "Thought Posted Successfully"}
            else:
                dict_response = {"error": True, "message": "Validation Error", "errors": serializer.errors}
        except Exception as e:
            print("Error during video creation:", e)
            dict_response = {"error": True, "message": "Error During Creating Video"}

        return Response(dict_response,
                        status=status.HTTP_201_CREATED if not dict_response["error"] else status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        queryset = IgnatianThoughts.objects.all()
        news = get_object_or_404(queryset, pk=pk)
        serializer = IgnatianThoughtsSerializer(news, context={"request": request})

        return Response({"error": False, "message": "Single Data Fetch", "data": serializer.data})

    def update(self, request, pk=None):
        try:
            queryset = IgnatianThoughts.objects.all()
            news = get_object_or_404(queryset, pk=pk)
            serializer = IgnatianThoughtsSerializer(news, data=request.data, context={"request": request})
            serializer.is_valid(raise_exception=True)
            serializer.save()
            dict_response = {"error": False, "message": "Thought updated Successfully"}

        except ValidationError as e:
            dict_response = {"error": True, "message": "Validation Error", "details": str(e)}
        except Exception as e:
            dict_response = {"error": True, "message": "An Error Occurred", "details": str(e)}

        return Response(dict_response,
                            status=status.HTTP_400_BAD_REQUEST if dict_response['error'] else status.HTTP_201_CREATED)

    def destroy(self, request, pk=None):
        # if not request.user.is_staff:
        #     return Response({"error": True, "message": "User does not have enough permission to perform this task"},\
        #                     status=status.HTTP_401_UNAUTHORIZED)

        queryset = IgnatianThoughts.objects.all()
        news = get_object_or_404(queryset, pk=pk)
        news.delete()
        return Response({"error": False, "message": "News Deleted"})


class DashboardApi(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def list(self, request):
        users = UserAccount.objects.all()
        users_serializer = UserAccountSerializer(users, many=True, context={"request": request})

        news = News.objects.all()
        news_serializer = NewsSerializer(news, many=True, context={"request": request})

        adusums = Adusums.objects.all()
        adusums_serializer = AdusumsSerializer(adusums, many=True, context={"request": request})

        products = Products.objects.all()
        products_serializer = ProductsSerializer(products, many=True, context={"request": request})

        dict_response = {
            "error": False,
            "message": "Home page data",
            "all_users": len(users_serializer.data),
            "all_news": len(news_serializer.data),
            "adusums": len(adusums_serializer.data),
            "products": len(products_serializer.data),
        }
        return Response(dict_response)
