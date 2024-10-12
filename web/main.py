from flask import Flask
from blueprints.routes import web
from datetime import timedelta


app = Flask(__name__)
app.permanent_session_lifetime = timedelta(minutes=5)
app.secret_key =  "jdfkfkkigkjgjkjg"

# Register your blueprints
app.register_blueprint(web, url_prefix='/')




if __name__ == "__main__": 
    app.run(host="0.0.0.0", port=1234, debug=True)
