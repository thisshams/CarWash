from flask import Flask, render_template, url_for, redirect,request,session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField,DateField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from sqlalchemy import or_,and_

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'secretkey'
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id=db.Column(db.Integer,primary_key=True)
    email = db.Column(db.String(30), unique=True)
    name = db.Column(db.String(30), nullable=False)
    password = db.Column(db.String(80), nullable=False)

class Admin(db.Model, UserMixin):
    id=db.Column(db.Integer,primary_key=True)
    email = db.Column(db.String(30), unique=True)
    name = db.Column(db.String(30), nullable=False)
    password = db.Column(db.String(80), nullable=False)

class Booking(db.Model, UserMixin):
    id=db.Column(db.Integer,primary_key=True)
    email = db.Column(db.String(30))
    place = db.Column(db.String(50), nullable=False)
    address = db.Column(db.String(50), nullable=False)
    date=db.Column(db.String(20),nullable=False)
    bookingStatus = db.Column(db.String(20), nullable=False)

class CarWash(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    place = db.Column(db.String(30), nullable=False)
    address = db.Column(db.String(50), nullable=False, unique=True)
    services = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    name = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Name"})
    email = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Email"})                           
    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('SignUp')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')



class LoginForm(FlaskForm):
    email = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Email"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


class Place(FlaskForm):
    place = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Place"})
    address = StringField(validators=[
                           InputRequired(), Length(min=4, max=50)], render_kw={"placeholder": "Address"})
    services = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Services"})                           

    submit = SubmitField('Done')

class searchPlaceForm(FlaskForm):
    place = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Place"})                        
    submit = SubmitField('Done')

class bookForm(FlaskForm):
    place = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Place"})
    date = DateField('DatePicker', format='%Y-%m-%d')                    
    submit = SubmitField('Done')

class servicesForm(FlaskForm):
    services = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Services"})                        
    submit = SubmitField('Done')


with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    print("'''''''''''''''''''''''''''''''''''''''''''''''''")
    # if form.validate_on_submit():
    if request.method=="POST":
        user = User.query.filter_by(email=form.email.data).first()
        print(user)
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                session['email'] = request.form['email']
                return redirect(url_for('userPanel'))
    return render_template('login.html', form=form)

@app.route('/userPanel',methods=['get','post'])
@login_required
def userPanel():
    return render_template("user.html")


@app.route('/adminlogin', methods=['GET', 'POST'])
def adminlogin():
    form = LoginForm()
    # if form.validate_on_submit():
    if request.method=="POST":
        user = Admin.query.filter_by(email=form.email.data).first()
        print(user)
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                session['email'] = request.form['email']
                return redirect(url_for('adminPanel'))
    return render_template('adminlogin.html', form=form)


@app.route('/adminPanel',methods=['get','post'])
@login_required
def adminPanel():
    return render_template("admin.html")






@app.route("/searchPlace",methods=['GET','POST'])
def searchPlace():
    form = searchPlaceForm()
    # if form.validate_on_submit():
    if request.method=="POST":
        data = CarWash.query.filter_by(place=form.place.data).all()
        print(data)
        if data:
            return render_template('searchPlace.html', form=form,data=data)
    return render_template('searchPlace.html', form=form,data=None)

@app.route("/book",methods=['GET','POST'])
def book():
    form = bookForm()
    # if form.validate_on_submit():
    if request.method=="POST":
        washdata = CarWash.query.filter_by(place=form.place.data).all()
        bookdata=[]
        for i in washdata:
            print(i.address,form.date.data)
            c=Booking.query.filter(and_(Booking.address==f'{i.address}',Booking.date == form.date.data)).all()
            cn=0
            for i in c:
                cn+=1
            print("-------------------------------------------------------------",cn)
            bookdata.append(5-cn)
        if washdata:
            print(bookdata)
            return render_template('book.html', form=form,washdata=washdata,bookdata=bookdata)
    return render_template('book.html', form=form,data=None)

@app.route("/bookwash",methods=['POST'])
def bookwash():
    # form = bookForm()
    # # if form.validate_on_submit():
    if request.method=="POST":
        new_place = Booking(email=session['email'],place=request.form.get('place'),address=request.form.get('address'),date=request.form.get('date'),bookingStatus='Pending')
        db.session.add(new_place)
        db.session.commit()
        return redirect(url_for('userPanel'))

@app.route("/bookingStatusCheck",methods=['GET','POST'])
def bookingStatusCheck():
    # if request.method=="POST":
    data = Booking.query.filter_by(email=session['email']).all()
    if data:
        return render_template('bookingStatusCheck.html',data=data)
    # return render_template('bookingStatusCheck.html', data=None)







@app.route("/addServices",methods=['GET','POST'])
def addServices():
    form = searchPlaceForm()
    form2=servicesForm()
    # if form.validate_on_submit():
    if request.method=="POST":
        washdata = CarWash.query.filter_by(place=form.place.data).all()
        bookdata=[]
        if washdata:
            return render_template('addServices.html', form=form,washdata=washdata,form2=form2)
    return render_template('addServices.html', form=form,data=None)

@app.route("/updateServices",methods=['POST'])
def updateServices():
    # form = bookForm()
    # # if form.validate_on_submit():
    if request.method=="POST":
        print(request.form.get('services'),request.form.get('address'))
        updated = CarWash.query.filter_by(address=request.form.get('address')).update(dict(services=request.form.get("services")))
        db.session.commit()
        return redirect(url_for('adminPanel'))



# @app.route('/dashboard', methods=['GET', 'POST'])
# @login_required
# def dashboard():
#     return render_template('dashboard.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    session.pop('email', None)
    return redirect(url_for('home'))




@ app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    # if form.validate_on_submit():
    print("signup inside")
    if request.method=='POST':
        print("post inside")
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        print("\33[32m SignUp\33[m",form.name.data,form.email.data)
        new_user = User(name=form.name.data,email=form.email.data, password=hashed_password)
        print(new_user)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('signup.html', form=form)


@ app.route('/addPlace', methods=['GET', 'POST'])
@login_required
def addPlace():
    form = Place()
    # if form.validate_on_submit():
    if request.method=='POST':
        new_place = CarWash(place=form.place.data,address=form.address.data,services=form.services.data)
        db.session.add(new_place)
        db.session.commit()
        return redirect(url_for('adminPanel'))

    return render_template('addPlace.html', form=form)


@app.route("/allBookings",methods=['GET','POST'])
def allBookings():
    form = bookForm()
    # if form.validate_on_submit():
    if request.method=="POST":
        data = Booking.query.filter(and_(Booking.place == form.place.data ,Booking.date == form.date.data)).all()
        # data = Booking.query.filter_by( (place=form.place.data) & (date=form.date.data) ).all()
        # if data:
        return render_template('allBookings.html', form=form,data=data)
    data = Booking.query.all()
    return render_template('allBookings.html', form=form,data=data)

@app.route("/acceptReject",methods=['GET','POST'])
def acceptReject():
    if request.method=="POST":
        data = Booking.query.filter(Booking.bookingStatus =='Pending').all()
        return render_template('acceptReject.html',data=data)
    data = Booking.query.all()
    return render_template('acceptReject.html',data=data)

@app.route("/updateacceptReject",methods=['POST'])
def updateacceptReject():
    if request.method=="POST":
        updated = Booking.query.filter(and_(Booking.address == request.form.get('address') ,Booking.email == request.form.get('email'))).update(dict(bookingStatus=request.form.get("bookingStatus")))
        db.session.commit()
        return redirect(url_for('adminPanel'))


if __name__ == "__main__":
    app.run(debug=True)