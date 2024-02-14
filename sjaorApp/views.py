import requests
from django.shortcuts import render, get_object_or_404
from djoser.views import UserViewSet
from rest_framework import generics, status, viewsets
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework_simplejwt.authentication import JWTAuthentication
from datetime import datetime
from django.core.mail import send_mail

from sjaorApp import serializers
from sjaorApp.models import UserAccount, News, PopesPrayerIntentions, Adusums, Products, Catalogues, Documents, \
    DocumentCategory, Shukran, IgnatianThoughts, EventCategory, Events, Archivum, Necrology
from sjaorApp.serializers import UserAccountSerializer, NewsSerializer, PopesPrayerIntentionsSerializer, \
    AdusumsSerializer, ProductsSerializer, CataloguesSerializer, DocumentSerializer, DocumentCategorySerializer, \
    ShukranSerializer, IgnatianThoughtsSerializer, EventCategorySerializer, EventsSerializer, ArchivumSerializer, \
    NecrologySerializer

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


class AdusumViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]

    def list(self, request):
        adusums = Adusums.objects.all().order_by('-id')
        serializer = AdusumsSerializer(adusums, many=True, context={"request": request})

        response_dict = {"error": False, "message": "All Adusum", "data": serializer.data}

        return Response(response_dict)

    def create(self, request):
        try:
            # Set the default value for status if not provided in the payload
            request.data.setdefault('status', 0)
            request.data.setdefault('remember_token', '')
            request.data.setdefault('reset_code', '')

            serializer = AdusumsSerializer(data=request.data, context={"request": request})
            if serializer.is_valid():
                serializer.save()
                dict_response = {"error": False, "message": "Adusum Registered Successfully"}
            else:
                dict_response = {"error": True, "message": "Validation Error", "errors": serializer.errors}
        except Exception as e:
            print("Error during adusum creation:", e)
            dict_response = {"error": True, "message": "Error During Creating Adusum"}

        return Response(dict_response,
                        status=status.HTTP_201_CREATED if not dict_response["error"] else status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        queryset = News.objects.all()
        adusums = get_object_or_404(queryset, pk=pk)
        serializer = AdusumsSerializer(adusums, context={"request": request})

        return Response({"error": False, "message": "Single Data Fetch", "data": serializer.data})

    def update(self, request, pk=None):
        if not request.user.is_staff:
            return Response({"error": True, "message": "User does not have enough permission to perform this task"},
                            status=status.HTTP_401_UNAUTHORIZED)

        try:
            queryset = Adusums.objects.all()
            adusums = get_object_or_404(queryset, pk=pk)

            # Check if the status needs to be updated
            new_status = request.data.get('status', None)
            if new_status is not None and adusums.status != new_status:
                adusums.status = new_status
                adusums.save()

                # Send verification email
                self.send_verification_email(adusums.email_address, adusums.fullname)

            # Create a copy of the request data excluding the 'profile_picture' field
            request_data_without_profile_picture = request.data.copy()
            request_data_without_profile_picture.pop('profile_picture', None)

            # Continue with the regular update using the modified data
            serializer = AdusumsSerializer(adusums, data=request_data_without_profile_picture, context={"request": request})
            serializer.is_valid(raise_exception=True)
            serializer.save()

            dict_response = {"error": False, "message": "Adusum updated/verified Successfully"}

        except ValidationError as e:
            dict_response = {"error": True, "message": "Validation Error", "details": str(e)}
        except Exception as e:
            dict_response = {"error": True, "message": "An Error Occurred", "details": str(e)}

        return Response(dict_response,
                        status=status.HTTP_400_BAD_REQUEST if dict_response['error'] else status.HTTP_201_CREATED)

    def send_verification_email(self, recipient_email, recipient_name):

        # Data to be sent in the POST request
        data = {
            'email': recipient_email,
            'name': recipient_name
        }

        # Endpoint to send the verification email
        endpoint_url = 'https://sjaorreadserver.sjaor.org/sendverificationemail'

        try:
            # Send POST request to the endpoint
            response = requests.post(endpoint_url, json=data)

            # Check if the request was successful (status code 200)
            if response.status_code == 200:
                print("Verification email sent successfully")
            else:
                print("Failed to send verification email. Status code:", response.status_code)

        except Exception as e:
            print("An error occurred while sending the verification email:", e)

    def destroy(self, request, pk=None):
        if not request.user.is_staff:
            return Response({"error": True, "message": "User does not have enough permission to perform this task"},\
                            status=status.HTTP_401_UNAUTHORIZED)

        queryset = Adusums.objects.all()
        adusums = get_object_or_404(queryset, pk=pk)
        adusums.delete()
        return Response({"error": False, "message": "Adusum Deleted"})


class UnAdusumViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]

    def list(self, request):
        adusums = Adusums.objects.filter(status=0).order_by('-id')
        serializer = AdusumsSerializer(adusums, many=True, context={"request": request})

        response_dict = {"error": False, "message": "All Adusum", "data": serializer.data}

        return Response(response_dict)

    def update(self, request, pk=None):
        if not request.user.is_staff:
            return Response({"error": True, "message": "User does not have enough permission to perform this task"},
                            status=status.HTTP_401_UNAUTHORIZED)

        try:
            queryset = Adusums.objects.all()
            adusums = get_object_or_404(queryset, pk=pk)

            # Check if the status needs to be updated
            new_status = request.data.get('status', None)
            if new_status is not None and adusums.status != new_status:
                adusums.status = new_status
                adusums.save()

                # Send verification email
                self.send_verification_email(adusums.email_address, adusums.fullname)

            # Create a copy of the request data excluding the 'profile_picture' field
            request_data_without_profile_picture = request.data.copy()
            request_data_without_profile_picture.pop('profile_picture', None)

            # Continue with the regular update using the modified data
            serializer = AdusumsSerializer(adusums, data=request_data_without_profile_picture, context={"request": request})
            serializer.is_valid(raise_exception=True)
            serializer.save()

            dict_response = {"error": False, "message": "Adusum updated/verified Successfully"}

        except ValidationError as e:
            dict_response = {"error": True, "message": "Validation Error", "details": str(e)}
        except Exception as e:
            dict_response = {"error": True, "message": "An Error Occurred", "details": str(e)}

        return Response(dict_response,
                        status=status.HTTP_400_BAD_REQUEST if dict_response['error'] else status.HTTP_201_CREATED)

    def send_verification_email(self, recipient_email, recipient_name):

        # Data to be sent in the POST request
        data = {
            'email': recipient_email,
            'name': recipient_name
        }

        # Endpoint to send the verification email
        endpoint_url = 'https://sjaorreadserver.sjaor.org/sendverificationemail'

        try:
            # Send POST request to the endpoint
            response = requests.post(endpoint_url, json=data)

            # Check if the request was successful (status code 200)
            if response.status_code == 200:
                print("Verification email sent successfully")
            else:
                print("Failed to send verification email. Status code:", response.status_code)

        except Exception as e:
            print("An error occurred while sending the verification email:", e)


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


class ArchivumViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]

    def list(self, request):
        news = Archivum.objects.all().order_by('-id')
        serializer = ArchivumSerializer(news, many=True, context={"request": request})

        response_dict = {"error": False, "message": "All Archivum", "data": serializer.data}

        return Response(response_dict)

    def create(self, request):
        try:
            serializer = ArchivumSerializer(data=request.data, context={"request": request})
            if serializer.is_valid():
                serializer.save()
                dict_response = {"error": False, "message": "Archivum Posted Successfully"}
            else:
                dict_response = {"error": True, "message": "Validation Error", "errors": serializer.errors}
        except Exception as e:
            print("Error during video creation:", e)
            dict_response = {"error": True, "message": "Error During Creating Video"}

        return Response(dict_response,
                        status=status.HTTP_201_CREATED if not dict_response["error"] else status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        queryset = Archivum.objects.all()
        news = get_object_or_404(queryset, pk=pk)
        serializer = ArchivumSerializer(news, context={"request": request})

        return Response({"error": False, "message": "Single Data Fetch", "data": serializer.data})

    def update(self, request, pk=None):
        try:
            queryset = Archivum.objects.all()
            news = get_object_or_404(queryset, pk=pk)
            serializer = ArchivumSerializer(news, data=request.data, context={"request": request})
            serializer.is_valid(raise_exception=True)
            serializer.save()
            dict_response = {"error": False, "message": "Archivum updated Successfully"}

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

        queryset = Archivum.objects.all()
        news = get_object_or_404(queryset, pk=pk)
        news.delete()
        return Response({"error": False, "message": "Archivum Deleted"})


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
            # Get the total number of catalogues
            total_prayers = PopesPrayerIntentions.objects.count()

            # Check if the limit is reached (e.g., 5)
            if total_prayers >= 1:
                # Retrieve the oldest catalogue
                oldest_prayers = PopesPrayerIntentions.objects.order_by('added_on').first()

                # Delete the oldest catalogue
                oldest_prayers.delete()

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
        # if not request.user.is_staff:
        #     return Response({"error": True, "message": "User does not have enough permission to perform this task"},\
        #                     status=status.HTTP_401_UNAUTHORIZED)

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


class NecrologyViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def list(self, request):
        necrology = Necrology.objects.all().order_by('-id')
        serializer = NecrologySerializer(necrology, many=True, context={"request": request})

        response_dict = {"error": False, "message": "All Necrologies", "data": serializer.data}

        return Response(response_dict)

    def create(self, request):
        try:
            # Extract necrology_month from the payload
            month = request.data.get('month')

            # Validate event_month
            if not month:
                dict_response = {"error": True, "message": "Missing necrology_month in the payload"}
                return Response(dict_response, status=status.HTTP_400_BAD_REQUEST)

            # Convert month name to number
            try:
                month = datetime.strptime(month, "%B").month
            except ValueError:
                dict_response = {"error": True, "message": "Invalid month name in the payload"}
                return Response(dict_response, status=status.HTTP_400_BAD_REQUEST)

            # Add the calculated month number to the payload data
            request.data['month'] = month

            serializer = NecrologySerializer(data=request.data, context={"request": request})
            if serializer.is_valid():
                serializer.save()
                dict_response = {"error": False, "message": "Necrology Added Successfully"}
            else:
                dict_response = {"error": True, "message": "Validation Error", "errors": serializer.errors}
        except Exception as e:
            print("Error during catalogue creation:", e)
            dict_response = {"error": True, "message": "Error During Creating Necrology"}

        return Response(dict_response,
                        status=status.HTTP_201_CREATED if not dict_response["error"] else status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        try:
            queryset = Necrology.objects.all()
            necrology = get_object_or_404(queryset, pk=pk)
            serializer = NecrologySerializer(necrology, data=request.data, context={"request": request})
            serializer.is_valid(raise_exception=True)
            serializer.save()
            dict_response = {"error": False, "message": "Necrology Updated Successfully"}

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

        queryset = Necrology.objects.all()
        necrology = get_object_or_404(queryset, pk=pk)
        necrology.delete()
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


class EventCategoryViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]

    def list(self, request):
        doc_categories = EventCategory.objects.all().order_by('-id')
        serializer = EventCategorySerializer(doc_categories, many=True, context={"request": request})

        response_dict = {"error": False, "message": "All Categories", "data": serializer.data}

        return Response(response_dict)

    def create(self, request):
        try:
            serializer = EventCategorySerializer(data=request.data, context={"request": request})
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
        queryset = EventCategory.objects.all()
        news = get_object_or_404(queryset, pk=pk)
        serializer = EventCategorySerializer(news, context={"request": request})

        return Response({"error": False, "message": "Single Data Fetch", "data": serializer.data})

    def update(self, request, pk=None):
        try:
            queryset = EventCategory.objects.all()
            news = get_object_or_404(queryset, pk=pk)
            serializer = EventCategorySerializer(news, data=request.data, context={"request": request})
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

        queryset = EventCategory.objects.all()
        news = get_object_or_404(queryset, pk=pk)
        news.delete()
        return Response({"error": False, "message": "Category Deleted"})


class EventOnlyViewSet(generics.ListAPIView):
    serializer_class = EventCategorySerializer

    def get_queryset(self):
        return EventCategory.objects.all()


class EventViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]

    def list(self, request):
        news = Events.objects.all().order_by('-id')
        serializer = EventsSerializer(news, many=True, context={"request": request})

        response_dict = {"error": False, "message": "All Events", "data": serializer.data}

        return Response(response_dict)

    def create(self, request):
        try:
            # Extract event_month from the payload
            event_month = request.data.get('event_month')

            # Validate event_month
            if not event_month:
                dict_response = {"error": True, "message": "Missing event_month in the payload"}
                return Response(dict_response, status=status.HTTP_400_BAD_REQUEST)

            # Convert month name to number
            try:
                event_month_number = datetime.strptime(event_month, "%B").month
            except ValueError:
                dict_response = {"error": True, "message": "Invalid month name in the payload"}
                return Response(dict_response, status=status.HTTP_400_BAD_REQUEST)

            # Add the calculated month number to the payload data
            request.data['event_month_number'] = event_month_number

            serializer = EventsSerializer(data=request.data, context={"request": request})
            if serializer.is_valid():
                serializer.save()
                dict_response = {"error": False, "message": "Event Created Successfully"}
            else:
                dict_response = {"error": True, "message": "Validation Error", "errors": serializer.errors}
        except Exception as e:
            print("Error during event creation:", e)
            dict_response = {"error": True, "message": "Error During Creating Event"}

        return Response(dict_response,
                        status=status.HTTP_201_CREATED if not dict_response["error"] else status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        queryset = Events.objects.all()
        news = get_object_or_404(queryset, pk=pk)
        serializer = EventsSerializer(news, context={"request": request})

        return Response({"error": False, "message": "Single Data Fetch", "data": serializer.data})

    def update(self, request, pk=None):
        try:
            queryset = Events.objects.all()
            news = get_object_or_404(queryset, pk=pk)

            # Extract event_month from the payload
            event_month = request.data.get('event_month')

            # Validate event_month
            if event_month:
                # Convert month name to number
                try:
                    event_month_number = datetime.strptime(event_month, "%B").month
                    # Update the event_month_number in the data
                    request.data['event_month_number'] = event_month_number
                except ValueError:
                    dict_response = {"error": True, "message": "Invalid month name in the payload"}
                    return Response(dict_response, status=status.HTTP_400_BAD_REQUEST)

            serializer = EventsSerializer(news, data=request.data, context={"request": request})
            serializer.is_valid(raise_exception=True)
            serializer.save()
            dict_response = {"error": False, "message": "Event updated Successfully"}

        except ValidationError as e:
            dict_response = {"error": True, "message": "Validation Error", "details": str(e)}
        except Exception as e:
            dict_response = {"error": True, "message": "An Error Occurred", "details": str(e)}

        return Response(dict_response,
                        status=status.HTTP_400_BAD_REQUEST if dict_response['error'] else status.HTTP_201_CREATED)

    def destroy(self, request, pk=None):
        queryset = Events.objects.all()
        event = get_object_or_404(queryset, pk=pk)

        # Check if the event belongs to the "General Events" category
        if event.event_category and event.event_category.category.lower() == "general events":
            # Check if the event is over (you need to replace the condition with your own logic)
            if event.added_on < datetime.now():
                event.delete()
                return Response({"error": False, "message": "Event Deleted"})
            else:
                return Response({"error": True, "message": "Event is not over yet, cannot be deleted"},
                                status=status.HTTP_400_BAD_REQUEST)

        # For events not belonging to the "General Events" category, proceed with normal deletion
        event.delete()
        return Response({"error": False, "message": "Event Deleted"})


class ProductsViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]

    def list(self, request):
        news = Products.objects.all().order_by('-id')
        serializer = ProductsSerializer(news, many=True, context={"request": request})

        response_dict = {"error": False, "message": "All Products", "data": serializer.data}

        return Response(response_dict)

    def create(self, request):
        try:
            serializer = ProductsSerializer(data=request.data, context={"request": request})
            if serializer.is_valid():
                serializer.save()
                dict_response = {"error": False, "message": "Product Added Successfully"}
            else:
                dict_response = {"error": True, "message": "Validation Error", "errors": serializer.errors}
        except Exception as e:
            print("Error during video creation:", e)
            dict_response = {"error": True, "message": "Error During Creating Video"}

        return Response(dict_response,
                        status=status.HTTP_201_CREATED if not dict_response["error"] else status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        queryset = Products.objects.all()
        news = get_object_or_404(queryset, pk=pk)
        serializer = ProductsSerializer(news, context={"request": request})

        return Response({"error": False, "message": "Single Data Fetch", "data": serializer.data})

    def update(self, request, pk=None):
        try:
            queryset = Products.objects.all()
            news = get_object_or_404(queryset, pk=pk)
            serializer = ProductsSerializer(news, data=request.data, context={"request": request})
            serializer.is_valid(raise_exception=True)
            serializer.save()
            dict_response = {"error": False, "message": "Product updated Successfully"}

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

        queryset = Products.objects.all()
        news = get_object_or_404(queryset, pk=pk)
        news.delete()
        return Response({"error": False, "message": "Product Deleted"})


class DashboardApi(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def list(self, request):
        users = UserAccount.objects.all()
        users_serializer = UserAccountSerializer(users, many=True, context={"request": request})

        news = News.objects.all()
        news_serializer = NewsSerializer(news, many=True, context={"request": request})

        adusums = Adusums.objects.filter(status=1)
        adusums_serializer = AdusumsSerializer(adusums, many=True, context={"request": request})

        products = EventCategory.objects.all()
        products_serializer = EventCategorySerializer(products, many=True, context={"request": request})

        dict_response = {
            "error": False,
            "message": "Home page data",
            "all_users": len(users_serializer.data),
            "all_news": len(news_serializer.data),
            "adusums": len(adusums_serializer.data),
            "products": len(products_serializer.data),
        }
        return Response(dict_response)
