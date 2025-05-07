from django.urls import path

from web import views

urlpatterns = [
    path('', views.index),
    path('index/', views.index),
    path('firewall_log/', views.firewallLog),
    path('ids_log/', views.idsLog),
    path('admin_log/', views.adminLog),
    path('firewall_rule/', views.firewallRule),
    path('ids_rule/', views.idsRule),
    path('traffic_statistic/', views.trafficStatistic),
    path('node_state/', views.nodeState),
    path('system_test/', views.systemTest),

    path('submit/firewall_rule/', views.submitFirewallRule),
    path('submit/ids_rule/', views.submitIDSRule),

    path('test/<int:test_id>/', views.test),
    path('reset/', views.reset),
]
