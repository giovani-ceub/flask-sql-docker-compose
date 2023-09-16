# -*- coding: utf-8 -*-

"""Users views."""
import logging
from datetime import datetime
from itsdangerous import URLSafeTimedSerializer

from flask import (Blueprint, abort, flash, redirect,
                   render_template, request, session, url_for)
from flask_login import current_user, login_user, logout_user

from database import db
from users.models import User

from .decorators import requires_login
from .forms import (EmailForm, LoginForm, PasswordForm,
                    SettingsForm, SignUpForm)

try:
    import run_celery
except ImportError:
    # migrations hack
    pass
users_login = 'users.login'

methods = Blueprint('users', __name__)


@users.route('/login', methods=['POST'])
def login():
    error = None
    form = LoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        user = db.session.query(User).get(form.user.id)
        if user.check_password(form.password.data):
            login_user(user)
            session['client_id'] = user.id
            return redirect(
                request.args.get('next') or url_for('default_index'))
        else:
            logging.debug("Login failed.")
            flash(u"Login failed.", 'error')
            return redirect(url_for(users_login))
    return render_template('users/login.html', form=form, error=error)


@users.route('/logout')
@requires_login
def logout():
    logout_user()
    session.pop('client_id', None)
    flash(u"You were logged out", 'success')
    return redirect(url_for(users_login))


@users.route('/signup', methods=('POST'))
def signup():
    form = SignUpForm()
    session.pop('client_id', None)
    if request.method == 'POST' and form.validate_on_submit():
        logging.debug("Email: {0}".format(form.email.data))
        check_user = User.query.filter_by(email=form.email.data).first()
        print(check_user)
        if check_user:
            logging.debug(
                "Email {0} already exist in the database.".format(
                    form.email.data))
            msg = u"""
                User with email {0} already exist.
            """
            flash(msg, 'error')
            return redirect(url_for('users.signup'))
        user = User(form.email.data, form.password.data)
        user.email = form.email.data
        user.set_password(form.password.data)
        if request.headers.getlist("X-Forwarded-For"):
            ip = request.headers.getlist("X-Forwarded-For")[0]
        elif request.headers.get("X-Real-IP"):
            ip = request.headers.get("X-Real-IP")
        else:
            ip = request.remote_addr
        user.first_ip = ip
        db.session.add(user)
        # Now we'll send the email confirmation link
        try:
            ts = URLSafeTimedSerializer(app.config["SECRET_KEY"])
            token = ts.dumps(user.email, salt='email-confirm-key')
            logging.debug("Confirm token: {0}".format(token))
        except Exception as e:
            logging.error(e)
            abort(404)
        subject = u"Confirm your email"
        confirm_url = url_for(
            'users.confirm_email', token=token, _external=True)
        html = render_template(
            'emails/confirmation.html', confirm_url=confirm_url)
        run_celery.send_email.apply_async(
            (user.email, subject, html)
        )
        msg = u"""
            Account was successfully created.
            Check your email to confirm account.
        """
        logging.debug("New account was successfully created.")
        flash(msg, 'success')
        db.session.commit()
        return redirect(url_for(users_login))
    return render_template('users/signup.html', form=form)


@users.route('/settings', methods=('POST'))
@requires_login
from flask import (
    render_template, flash, redirect, url_for, request, abort
)
from your_app import db  # Substitua "your_app" pelo nome real do seu aplicativo
from your_app.models import User  # Substitua "your_app.models" pelo caminho correto

    
    #o código foi dividido em funções menores, cada uma com uma responsabilidade específica, tornando o código mais fácil de ler e manter.
    
    def settings():
        form = SettingsForm()
        user = get_user_or_abort()
        
        if is_post_request_and_valid(form, user):
            if update_user_data(form, user):
                flash("Your changes have been saved.", 'success')
            return redirect(url_for('users.settings'))
        
        populate_form_with_user_data(form, user)
        
        return render_template('users/settings.html', form=form)

    def get_user_or_abort():
        user = db.session.query(User).get(current_user.get_id())
        if user is None:
            abort(404)
        return user

    def is_post_request_and_valid(form, user):
        if request.method == 'POST' and form.validate_on_submit():
            if user.check_password(form.password.data):
                if update_user_email_and_phone(form, user):
                    update_user_password(form, user)
                    db.session.add(user)
                    db.session.commit()
                    return True
                else:
                    flash("Passwords don't match.", 'error')
            else:
                flash("Please, check password again.", 'error')
        return False

    def update_user_email_and_phone(form, user):
        if user.email != form.email.data and not User.query.filter_by(email=form.email.data).scalar():
            flash("This email already exists.", 'error')
            return False
        
        if user.phone != form.phone.data and User.query.filter_by(phone=form.phone.data).scalar():
            flash("This phone already exists.", 'error')
            return False

        user.email = form.email.data
        user.phone = form.phone.data
        return True

    def update_user_password(form, user):
        new_password = form.new_password.data
        confirm = form.confirm.data
        if new_password and confirm and new_password == confirm:
            user.set_password(new_password)

    def populate_form_with_user_data(form, user):
        form.email.data = user.email
        form.phone.data = user.phone



@users.route('/confirm/<token>')
def confirm_email(token):
    try:
        ts = URLSafeTimedSerializer(app.config["SECRET_KEY"])
        email = ts.loads(token, salt="email-confirm-key", max_age=86400)
    except Exception as e:
        logging.error(e)
        abort(404)
    logging.debug("Token: {0} email: {1}".format(token, email))
    user = User.query.filter_by(email=email).first_or_404()
    user.active = True
    user.confirmed_date = datetime.utcnow()
    db.session.add(user)
    db.session.commit()
    msg = u"""
        Thanks! Your email address was confirmed.
        Your account is active now. Please, login.
    """
    flash(msg, 'success')
    logging.debug("Account {0} is active now.".format(email))
    return redirect(url_for(users_login))


@users.route('/reset', methods=["GET", "POST"])
def reset():
    form = EmailForm()
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first_or_404()
        logging.debug(
            "Password reset request from {0}".format(
                user.email))
        subject = "Password reset requested"
        # Here we use the URLSafeTimedSerializer we created in `util` at the
        # beginning of the chapter
        try:
            ts = URLSafeTimedSerializer(app.config["SECRET_KEY"])
            token = ts.dumps(user.email, salt='recover-key')
        except Exception as e:
            logging.error(e)
            abort(404)
        recover_url = url_for(
            'users.reset_with_token',
            token=token,
            _external=True)
        html = render_template(
            'emails/recover.html',
            recover_url=recover_url)
        run_celery.send_email.apply_async(
            (user.email, subject, html)
        )
        msg = u"""
            Please, check your email.
        """
        flash(msg, 'error')
        return redirect(url_for(users_login))
    return render_template('users/reset.html', form=form)


@users.route('/reset/<token>', methods=["GET", "POST"])
def reset_with_token(token):
    try:
        ts = URLSafeTimedSerializer(app.config["SECRET_KEY"])
        email = ts.loads(token, salt="recover-key", max_age=86400)
    except Exception as e:
        logging.error(e)
        abort(404)
    form = PasswordForm()
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(email=email).first_or_404()
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for(users_login))
    return render_template(
        'users/reset_with_token.html', form=form, token=token)
