from eventlet import wsgi
from hello import create_app

app = create_app()
wsgi.server(eventlet.listen(("0.0.0.0", 5000)), app)

