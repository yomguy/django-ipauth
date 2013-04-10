from django.dispatch import Signal
included_ip_found = Signal(providing_args=["request", "ip"])
