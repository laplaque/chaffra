from django.views import View
from django.views.generic import ListView, DetailView
from django.http import HttpResponse, JsonResponse


class IndexView(View):
    def get(self, request):
        return HttpResponse("index page")


class ArticleList(ListView):
    model = None  # Would be Article in real code
    template_name = "articles/list.html"


class ArticleDetail(DetailView):
    model = None
    template_name = "articles/detail.html"


def about_view(request):
    return HttpResponse("about page")


def contact_view(request):
    return JsonResponse({"email": "test@example.com"})
