from django.http import JsonResponse
from django.shortcuts import render
from django.views import View


def custom_server_error(request):
    return JsonResponse(
        {"status": "error", "message": "Internal server error"},
        status=500
    )

def custom_not_found_error(request, exception):
    return JsonResponse(
        {"status": "error", "message": "Internal server error"},
        status=404
    )

class IndexView(View):
    def get(self, request):
        return render(request, 'index.html')
