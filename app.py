import os

from flask import Flask
from flask import render_template
from flask import redirect
from flask import request

from flask_login import LoginManager
from flask_login import login_required
from flask_login import login_user
from flask_login import logout_user

from werkzeug.security import generate_password_hash # 暗号化
from werkzeug.security import check_password_hash    # パスワードに戻す


from database import User

app = Flask(__name__)

app.config["SECRET_KEY"] = os.urandom(24) #決まり事
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(id):
    return User.get(id=int(id))           # ここまで   

@login_manager.unauthorized_handler
def unauthorized():
    return redirect("/login")

@app.route("/")
@login_required
def index():
    return render_template("index.html")

@app.route("/login")
def login():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login_post():
    name = request.form["name"]
    password = request.form["password"]
    user = User.get(name=name)
    if check_password_hash(user.password, password): # database の password と一致していたら
        login_user(user) # flask_login の機能         # check_password_hash 暗号化したものの解凍 
        return redirect("/")
    return redirect("/login")

@app.route("/signup") # methods を書かないと["GET"]になる
def signup():
    return render_template("signup.html")

@app.route("/signup", methods=["POST"])
def register():
    name = request.form["name"]
    password = request.form["password"]
    User.create(
        name=name,
        password=generate_password_hash(password, method="sha256") # method="sha256" 暗号化の方式
    )
    return redirect("/login")

@app.route("/logout", methods=["POST"])
def logout():
    logout_user()
    return redirect("/login")

if __name__ == "__main__":
    app.run(debug=True)
