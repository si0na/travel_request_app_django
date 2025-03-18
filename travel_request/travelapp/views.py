from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User
from django.db.models import Case, When, IntegerField
from .models import TravelRequest, Admin, Manager, Employee
from .serializers import TravelRequestSerializer, EmployeeSerializer, ManagerSerializer, AdminSerializer,LoginSerializer 
from rest_framework.status import HTTP_200_OK, HTTP_400_BAD_REQUEST, HTTP_500_INTERNAL_SERVER_ERROR
import logging
from django.core.exceptions import ObjectDoesNotExist
# Configure logging
logger = logging.getLogger(__name__)

def authenticate_user(email: str, password: str) -> dict | None:
    """
    Authenticates the user based on their role (Admin, Manager, Employee).

    Returns a dictionary with user data if authentication is successful, otherwise None.
    """
    email = email.strip().lower()

    try:
        # Check Admin
        admin = Admin.objects.filter(admin_email=email).first()
        if admin and check_password(password, admin.admin_password):  # Ensure hashing for admin passwords
            return {
                "id": admin.admin_id,
                "name": admin.admin_name,
                "email": admin.admin_email,
                "role": "admin"
            }

        # Check Manager
        manager = Manager.objects.filter(manager_email=email).first()
        if manager and check_password(password, manager.manager_password):
            return {
                "id": manager.manager_id,
                "name": manager.manager_name,
                "email": manager.manager_email,
                "role": "manager",
                "status": manager.status
            }

        # Check Employee
        employee = Employee.objects.filter(employee_email=email).first()
        if employee and check_password(password, employee.password):
            return {
                "id": employee.employee_id,
                "name": employee.employee_name,
                "email": employee.employee_email,
                "role": "employee",
                "status": employee.status
            }

    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")  # Log the error
        return None

    return None


@api_view(["POST"])
@permission_classes([AllowAny])
def login_view(request):
    """
    Handles user login for Admin, Manager, and Employee roles.

    Returns an authentication token and user details upon successful login.
    """
    serializer = LoginSerializer(data=request.data)
    
    if not serializer.is_valid():
        return Response({"message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    email = serializer.validated_data["email"]
    password = serializer.validated_data["password"]

    user_data = authenticate_user(email, password)

    if user_data:
        django_user, _ = User.objects.get_or_create(username=email)
        token, _ = Token.objects.get_or_create(user=django_user)
        return Response({"token": token.key, "user": user_data}, status=status.HTTP_200_OK)

    logger.warning(f"Failed login attempt for email: {email}")
    return Response({"message": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def admin_add_manager(request):
    """
    API endpoint for admins to add a new manager.

    Request Body:
    {
        "manager_name": "John Doe",
        "manager_email": "john@example.com",
        "manager_password": "securepassword"
    }
    """
    try:
        data = request.data.copy()
        if "manager_password" not in data or not data["manager_password"]:
            return Response({"error": "Password is required"}, status=status.HTTP_400_BAD_REQUEST)

        data["manager_password"] = make_password(data["manager_password"])
        serializer = ManagerSerializer(data=data)

        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Manager added successfully", "data": serializer.data},
                status=status.HTTP_201_CREATED,
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        logger.error(f"Error adding manager: {str(e)}")
        return Response({"error": "An error occurred while adding the manager"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def admin_add_employee(request):
    """
    API endpoint for admins to add a new employee.

    Request Body:
    {
        "employee_name": "Jane Doe",
        "employee_email": "jane@example.com",
        "password": "securepassword"
    }
    """
    try:
        data = request.data.copy()

        if "password" not in data or not data["password"]:
            return Response({"error": "Password is required"}, status=status.HTTP_400_BAD_REQUEST)

        data["password"] = make_password(data["password"])
        serializer = EmployeeSerializer(data=data)

        if serializer.is_valid():
            employee = serializer.save()

            # Exclude password from response for security
            response_data = serializer.data.copy()
            response_data.pop("password", None)

            return Response(
                {"message": "Employee added successfully", "data": response_data},
                status=status.HTTP_201_CREATED,
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        logger.error(f"Error adding employee: {str(e)}")
        return Response({"error": "An error occurred while adding the employee"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(["GET"])
@permission_classes([AllowAny])
def employee_past_requests(request):
    """Retrieve past travel requests for the authenticated employee"""
    try:
        employee = get_object_or_404(Employee, employee_email=request.user.username)
        past_requests = TravelRequest.objects.filter(employee=employee).order_by("-created_at")        
        serializer = TravelRequestSerializer(past_requests, many=True)
        return Response(serializer.data if past_requests else {"message": "No past travel requests found."}, status=status.HTTP_200_OK)

    except ObjectDoesNotExist:
        return Response({"error": "Employee not found."}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"error": f"Internal Server Error: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_travel_requests(request):
    """Retrieve travel requests based on Admin/Manager roles"""
    try:
        user_email = request.user.username
        is_admin = Admin.objects.filter(admin_email=user_email).exists()
        is_manager = Manager.objects.filter(manager_email=user_email).exists()

        if not (is_admin or is_manager):
            return Response({"error": "Unauthorized access."}, status=status.HTTP_403_FORBIDDEN)

        # Fetch travel requests
        travel_requests = TravelRequest.objects.filter(manager=Manager.objects.get(manager_email=user_email)) if is_manager else TravelRequest.objects.all()

        # Apply filters
        filters = {
            "employee__employee_name__icontains": request.query_params.get("employee_name"),
            "departure_date__gte": request.query_params.get("start_date"),
            "departure_date__lte": request.query_params.get("end_date"),
        }
        filters = {k: v for k, v in filters.items() if v}
        travel_requests = travel_requests.filter(**filters)

        # Sorting by status order: approved > pending > denied > additional_info_requested
        status_priority = {"approved": 1, "pending": 2, "denied": 3, "additional_info_requested": 4}
        travel_requests = sorted(travel_requests, key=lambda x: (status_priority.get(x.status, 5), -x.created_at.timestamp()))

        serializer = TravelRequestSerializer(travel_requests, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    except ObjectDoesNotExist:
        return Response({"error": "Requested data not found."}, status=status.HTTP_404_NOT_FOUND)
    except ValueError:
        return Response({"error": "Invalid input provided."}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({"error": f"Internal Server Error: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def admin_view_employees(request):
    """Retrieve a list of all employees (Admin access only)."""
    try:
        # Ensure only Admins can access this endpoint
        if not Admin.objects.filter(admin_email=request.user.username).exists():
            return Response({"error": "Unauthorized access."}, status=status.HTTP_403_FORBIDDEN)

        # Fetch and serialize employee data
        employees = Employee.objects.all()
        serializer = EmployeeSerializer(employees, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error fetching employees: {str(e)}")
        return Response({"error": "An error occurred while retrieving employees."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def update_travel_request_status(request, travel_request_id):
    """Update the status of a travel request (Admin/Manager access only)."""
    try:
        # Get the travel request
        travel_request = get_object_or_404(TravelRequest, id=travel_request_id)

        # Get the logged-in user and check if they are an Admin or Manager
        user_email = request.user.username
        admin = Admin.objects.filter(admin_email=user_email).first()
        manager = Manager.objects.filter(manager_email=user_email).first()

        # Ensure the user is either an Admin or Manager
        if not admin and not manager:
            return Response({"error": "Unauthorized access."}, status=status.HTTP_403_FORBIDDEN)

        # Get the new status from the request data
        new_status = request.data.get("status")
        valid_statuses = ["approved", "rejected", "additional_info_requested"]  # Standardized "denied" instead of "rejected"

        if new_status not in valid_statuses:
            return Response({"error": "Invalid status update."}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the status is already set to the same value
        if travel_request.status == new_status:
            return Response({"message": "No changes made. The status is already up-to-date."}, status=status.HTTP_200_OK)

        # If additional_info_requested, get the respective note
        if new_status == "additional_info_requested":
            note = request.data.get("note", "").strip()
            if not note:
                return Response({"error": "Note is required for additional info requests."},
                                status=status.HTTP_400_BAD_REQUEST)
            
            if admin:
                travel_request.admin_note = note  # Admin-specific note
            elif manager:
                travel_request.manager_note = note  # Manager-specific note

        # Update the travel request status
        travel_request.status = new_status
        travel_request.save()

        logger.info(f"Travel request {travel_request_id} updated to '{new_status}' by {user_email}")

        return Response({"message": "Travel request status updated successfully."}, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error updating travel request {travel_request_id}: {str(e)}")
        return Response({"error": "An error occurred while updating the status."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def close_travel_request(request, travel_request_id):
    """Allows an Admin to close an approved travel request."""
    try:
        # Ensure the requester is an Admin, not a Manager
        admin = get_object_or_404(Admin, admin_email=request.user.username)

        # Retrieve the travel request
        travel_request = get_object_or_404(TravelRequest, id=travel_request_id)

        # Ensure this travel request belongs to a manager under the admin
        manager_admin = getattr(travel_request.manager, "admin", None)  # Avoid attribute errors

        if manager_admin != admin:
            return Response({"error": "You are not authorized to close this travel request."},
                            status=status.HTTP_403_FORBIDDEN)

        # Ensure the request is in a valid state to be closed
        valid_closable_statuses = ["approved"]  # Modify this list if needed
        if travel_request.status not in valid_closable_statuses:
            return Response({"error": "Only approved travel requests can be closed."},
                            status=status.HTTP_400_BAD_REQUEST)

        if travel_request.is_closed:
            return Response({"error": "This travel request is already closed."},
                            status=status.HTTP_400_BAD_REQUEST)

        # Close the request
        travel_request.is_closed = True
        travel_request.save()

        logger.info(f"Admin {admin.admin_email} closed travel request {travel_request_id}")

        return Response({"message": f"Travel request {travel_request_id} has been closed by the Admin."},
                        status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error closing travel request {travel_request_id}: {str(e)}")
        return Response({"error": "An error occurred while closing the travel request."},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST', 'PUT'])
@permission_classes([IsAuthenticated])
def create_resubmit_notify(request, request_id=None):
    """
    Handles creation and updating of travel requests.

    - POST: Creates a new request.
    - PUT: Updates an existing request.
    """
    employee = get_object_or_404(Employee.objects.select_related('manager__admin'), employee_email=request.user.username)

    if not employee.manager:
        return Response({"message": "Employee does not have an assigned manager."}, status=status.HTTP_400_BAD_REQUEST)

    manager, admin = employee.manager, employee.manager.admin
    manager_email, admin_email = manager.manager_email, admin.admin_email

    if request.method == 'POST':
        serializer = TravelRequestSerializer(data=request.data)
        if serializer.is_valid():
            travel_request = serializer.save(employee=employee, manager=manager, status="pending")
            action = "created"
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'PUT':
        if not request_id:
            return Response({"message": "Request ID is required for updating."}, status=status.HTTP_400_BAD_REQUEST)

        travel_request = get_object_or_404(TravelRequest, id=request_id)
        serializer = TravelRequestSerializer(travel_request, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            action = "updated"
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # Email Notification
    subject = f"Travel Request {action}: ID {travel_request.id}"
    message = f"A travel request has been {action}. Details: {serializer.data}"

    try:
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [admin_email, manager_email], fail_silently=False)
    except Exception as e:
        logger.error(f"Email sending failed: {e}")
        return Response({"message": f"Travel request {action}, but email failed."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return Response({"message": f"Travel request {action} successfully."}, status=status.HTTP_200_OK)


def send_travel_request_email(travel_request, action, admin_email, manager_email):
    """
    Sends an email notification for travel request actions.

    Args:
        travel_request (TravelRequest): The travel request object.
        action (str): Action performed (created/updated).
        admin_email (str): Email of the admin.
        manager_email (str): Email of the manager.

    Raises:
        Exception: If email sending fails.
    """

    subject = f"Travel Request {action}: ID {travel_request.id}"
    message = (
        f"Dear Admin & Manager,\n\n"
        f"A travel request (ID: {travel_request.id}) has been {action}.\n\n"
        f"Requester: {travel_request.employee.get_full_name()}\n"
        f"Status: {travel_request.status}\n"
        f"Origin: {travel_request.origin}\n"
        f"Destination: {travel_request.destination}\n"
        f"Mode of Travel: {travel_request.mode_of_travel}\n"
        f"Departure Date: {travel_request.departure_date}\n"
        f"Return Date: {travel_request.return_date}\n"
        f"Needs Lodging: {travel_request.needs_lodging}\n\n"
        f"Please review the request at your earliest convenience.\n\n"
        f"Best Regards,\nYour Travel Support Team"
    )

    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [admin_email, manager_email], fail_silently=False)