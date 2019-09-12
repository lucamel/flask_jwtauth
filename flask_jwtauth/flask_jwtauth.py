from flask import current_app, _app_ctx_stack

class JWTAuth(object):
    def __init__(self, app=None):

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        auth_url_rule = "/test"
        auth_url_options = app.config.get('JWT_AUTH_URL_OPTIONS', {'methods': ['POST']})
        auth_url_options.setdefault('view_func', self.test_callback)
        app.add_url_rule(auth_url_rule, **auth_url_options)

    def test_callback():
        return "OK it works!"