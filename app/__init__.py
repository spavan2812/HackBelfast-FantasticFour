from flask import Flask

# Import database models here in the future
# from app.db import models

def create_app():
    app = Flask(__name__)

    # Import and register blueprints
    from .routes import main
    app.register_blueprint(main)

    # Register other blueprints, database, etc. here

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
