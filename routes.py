from views import index, post_handler, delete_handler


def setup_routes(app):
    app.router.add_get('/', index)
    app.router.add_post('/', post_handler)
    app.router.add_delete('/', delete_handler)