from django.urls import path, include
from .views import admin_registration,login_view
from . import views 

urlpatterns = [
path('adminreg/', admin_registration, name='admin_registration'),
path('login/', views.login_view, name='login'),
path('create_employee/', views.create_employee, name='create_employee'),
path('set_employee_password/', views.set_employee_password, name='set_employee_password/'),
path('data-entitlements/', views.get_data_entitlements, name='get_data_entitlements'),
path('get_data_departments/', views.get_data_departments, name='get_data_departments'),
path('get_data_designation/', views.get_data_designation, name='get_data_designation'),
path('getprimaryandadditionalrole/', views.getprimaryandadditionalrole, name='getprimaryandadditionalrole'),
path('update_department/<str:department_code>/', views.update_department, name='update_department'),
path('update_designation/<str:designation_code>/', views.update_designation, name='update_designation'),
]
