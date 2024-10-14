from flask import Flask
from blueprints.routes import web
from datetime import timedelta
import base64


def b64encode_img(img):
    return base64.b64encode(img.getvalue()).decode('utf-8')



app = Flask(__name__)
app.permanent_session_lifetime = timedelta(minutes=5)
app.secret_key =  "jdfkfkkigkjgjkjg"
app.add_template_filter(b64encode_img, 'b64encode')

# Register your blueprints
app.register_blueprint(web, url_prefix='/')




if __name__ == "__main__": 
    app.run(host="0.0.0.0", port=1234, debug=True)
