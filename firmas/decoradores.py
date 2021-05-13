from django.shortcuts import redirect

def esta_logueado(view):
        def interna(request, *args, **kwargs):
                if request.session.get('logueado', False):
                        return view(request, *args, **kwargs)
                else:
                        return redirect('/logeo')
        return interna
