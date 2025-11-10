from __future__ import annotations

import os
import threading
from typing import Optional

from flask import (
    Flask,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from detoxify import Detoxify
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import func, inspect, text
from sqlalchemy.exc import IntegrityError, OperationalError
from uuid import uuid4


db = SQLAlchemy()


def create_app(test_config: Optional[dict] = None) -> Flask:
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-secret-key"),
        SQLALCHEMY_DATABASE_URI=os.environ.get(
            "DATABASE_URL", f"sqlite:///{os.path.join(app.instance_path, 'app.db')}"
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        UPLOAD_FOLDER=os.environ.get(
            "UPLOAD_FOLDER", os.path.join(app.static_folder, "uploads")
        ),
        ALLOWED_EXTENSIONS={"png", "jpg", "jpeg", "gif", "webp"},
        MAX_CONTENT_LENGTH=10 * 1024 * 1024,  # 10 MB uploads
        MODERATION_THRESHOLD=float(os.environ.get("MODERATION_THRESHOLD", "0.35")),
    )

    if test_config is not None:
        app.config.update(test_config)

    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    db.init_app(app)

    with app.app_context():
        db.create_all()
        apply_schema_fixes()
        ensure_admin_account()

    register_routes(app)

    return app


def allowed_file(filename: str) -> bool:
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in current_app.config["ALLOWED_EXTENSIONS"]


def save_uploaded_file(file_storage) -> Optional[str]:
    if not file_storage or not file_storage.filename:
        return None
    if not allowed_file(file_storage.filename):
        return None
    filename = secure_filename(file_storage.filename)
    _, ext = os.path.splitext(filename)
    unique_name = f"{uuid4().hex}{ext.lower()}"
    upload_folder = current_app.config["UPLOAD_FOLDER"]
    os.makedirs(upload_folder, exist_ok=True)
    destination = os.path.join(upload_folder, unique_name)
    file_storage.save(destination)
    relative_path = os.path.relpath(destination, start=current_app.static_folder)
    return relative_path.replace("\\", "/")


def delete_uploaded_file(relative_path: Optional[str]) -> None:
    if not relative_path:
        return
    absolute_path = os.path.join(current_app.static_folder, relative_path)
    try:
        if os.path.isfile(absolute_path):
            os.remove(absolute_path)
    except OSError:
        pass


_moderation_model = None
_moderation_lock = threading.Lock()


def get_moderation_model() -> Detoxify:
    global _moderation_model
    if _moderation_model is None:
        with _moderation_lock:
            if _moderation_model is None:
                _moderation_model = Detoxify("original")
    return _moderation_model


def is_message_allowed(text: str) -> bool:
    text = text.strip()
    if not text:
        return False
    try:
        model = get_moderation_model()
        scores = model.predict(text)
    except Exception:
        return True
    threshold = current_app.config.get("MODERATION_THRESHOLD", 0.35)
    for label, score in scores.items():
        if score is None:
            continue
        if score >= threshold:
            return False
    return True


def violation_level(count: Optional[int]) -> str:
    if count is None:
        count = 0
    if count >= 5:
        return "danger"
    if count >= 2:
        return "warning"
    return "success"


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    profile_image = db.Column(db.String(255), nullable=True)
    is_admin = db.Column(db.Boolean, nullable=False, default=False, server_default="0")
    is_frozen = db.Column(db.Boolean, nullable=False, default=False, server_default="0")
    violation_count = db.Column(
        db.Integer, nullable=False, default=0, server_default="0"
    )
    polls = db.relationship("Poll", backref="creator", lazy=True)
    votes = db.relationship("Vote", backref="voter", lazy=True)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Poll(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(
        db.DateTime, nullable=False, default=db.func.now(), server_default=db.func.now()
    )
    cover_image = db.Column(db.String(255), nullable=True)
    chat_enabled = db.Column(db.Boolean, nullable=False, default=True, server_default="1")
    options = db.relationship("Option", backref="poll", cascade="all, delete-orphan")
    votes = db.relationship("Vote", backref="poll", cascade="all, delete-orphan")
    messages = db.relationship("Message", backref="poll", cascade="all, delete-orphan")


class Option(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    poll_id = db.Column(db.Integer, db.ForeignKey("poll.id"), nullable=False)
    image_path = db.Column(db.String(255), nullable=True)
    votes = db.relationship("Vote", backref="option", cascade="all, delete-orphan")


class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    poll_id = db.Column(db.Integer, db.ForeignKey("poll.id"), nullable=False)
    option_id = db.Column(db.Integer, db.ForeignKey("option.id"), nullable=False)
    __table_args__ = (db.UniqueConstraint("user_id", "poll_id", name="unique_vote"),)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(
        db.DateTime, nullable=False, default=db.func.now(), server_default=db.func.now()
    )
    poll_id = db.Column(db.Integer, db.ForeignKey("poll.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    user = db.relationship("User")


def record_violation(user: Optional[User]) -> None:
    if user is None:
        return
    current = user.violation_count or 0
    user.violation_count = current + 1


def current_user() -> Optional[User]:
    user_id = session.get("user_id")
    if user_id is None:
        return None
    return User.query.get(user_id)


def apply_schema_fixes() -> None:
    inspector = inspect(db.engine)
    user_columns = {column["name"] for column in inspector.get_columns("user")}
    poll_columns = {column["name"] for column in inspector.get_columns("poll")}

    if "profile_image" not in user_columns:
        db.session.execute(text("ALTER TABLE user ADD COLUMN profile_image VARCHAR(255)"))
        db.session.commit()

    if "is_admin" not in user_columns:
        db.session.execute(text("ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT 0"))
        db.session.commit()
        db.session.execute(text("UPDATE user SET is_admin = 0 WHERE is_admin IS NULL"))
        db.session.commit()

    if "is_frozen" not in user_columns:
        db.session.execute(text("ALTER TABLE user ADD COLUMN is_frozen BOOLEAN DEFAULT 0"))
        db.session.commit()
        db.session.execute(text("UPDATE user SET is_frozen = 0 WHERE is_frozen IS NULL"))
        db.session.commit()

    if "violation_count" not in user_columns:
        db.session.execute(
            text("ALTER TABLE user ADD COLUMN violation_count INTEGER DEFAULT 0")
        )
        db.session.commit()
        db.session.execute(
            text("UPDATE user SET violation_count = 0 WHERE violation_count IS NULL")
        )
        db.session.commit()

    if "created_at" not in poll_columns:
        try:
            db.session.execute(
                text("ALTER TABLE poll ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP")
            )
        except OperationalError:
            db.session.rollback()
            db.session.execute(text("ALTER TABLE poll ADD COLUMN created_at DATETIME"))
        db.session.commit()

    db.session.execute(
        text("UPDATE poll SET created_at = COALESCE(created_at, CURRENT_TIMESTAMP)")
    )
    db.session.commit()

    if "cover_image" not in poll_columns:
        db.session.execute(text("ALTER TABLE poll ADD COLUMN cover_image VARCHAR(255)"))
        db.session.commit()

    if "chat_enabled" not in poll_columns:
        db.session.execute(text("ALTER TABLE poll ADD COLUMN chat_enabled BOOLEAN"))
        db.session.commit()
        db.session.execute(text("UPDATE poll SET chat_enabled = 1 WHERE chat_enabled IS NULL"))
        db.session.commit()

    option_columns = {column["name"] for column in inspector.get_columns("option")}
    if "image_path" not in option_columns:
        db.session.execute(text("ALTER TABLE option ADD COLUMN image_path VARCHAR(255)"))
        db.session.commit()

    existing_indexes = {index["name"] for index in inspector.get_indexes("poll")}
    if "idx_poll_title_unique" not in existing_indexes:
        try:
            db.session.execute(
                text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_poll_title_unique "
                    "ON poll (title COLLATE NOCASE)"
                )
            )
            db.session.commit()
        except Exception:
            db.session.rollback()

def ensure_admin_account() -> None:
    admin = User.query.filter_by(name="admin").first()
    if admin is None:
        admin = User(name="admin", is_admin=True, is_frozen=False, violation_count=0)
        admin.set_password("BIPH2025")
        db.session.add(admin)
        db.session.commit()
        return

    updated = False
    if not admin.is_admin:
        admin.is_admin = True
        updated = True
    if admin.is_frozen:
        admin.is_frozen = False
        updated = True
    if admin.violation_count is None or admin.violation_count != 0:
        admin.violation_count = 0
        updated = True
    if not admin.check_password("BIPH2025"):
        admin.set_password("BIPH2025")
        updated = True
    if updated:
        db.session.commit()

def login_required(func):
    from functools import wraps

    @wraps(func)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            flash("Please log in first.", "warning")
            return redirect(url_for("login", next=request.url))
        return func(*args, **kwargs)

    return wrapped


def admin_required(func):
    from functools import wraps

    @wraps(func)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            flash("Please log in first.", "warning")
            return redirect(url_for("login", next=request.url))
        if not user.is_admin:
            flash("Admin access required.", "danger")
            return redirect(url_for("index"))
        return func(*args, **kwargs)

    return wrapped


def register_routes(app: Flask) -> None:
    @app.context_processor
    def inject_user():
        user = current_user()
        return {
            "current_user": user,
            "current_user_is_admin": bool(user and user.is_admin),
            "current_user_is_frozen": bool(user and user.is_frozen),
            "violation_level": violation_level,
        }

    def build_poll_listing(base_query):
        sort_choice = request.args.get("sort", "recent")
        if sort_choice not in {"recent", "popular"}:
            sort_choice = "recent"
        page = request.args.get("page", 1, type=int)
        count_votes = func.count(Vote.id)
        polls_query = (
            base_query.outerjoin(Vote)
            .add_columns(count_votes.label("vote_count"))
            .group_by(Poll.id)
        )
        if sort_choice == "popular":
            polls_query = polls_query.order_by(count_votes.desc(), Poll.created_at.desc())
        else:
            polls_query = polls_query.order_by(Poll.created_at.desc())

        pagination = polls_query.paginate(page=page, per_page=6, error_out=False)
        polls = [
            {"poll": poll, "vote_count": vote_count}
            for poll, vote_count in pagination.items
        ]
        return polls, pagination, sort_choice

    @app.route("/admin")
    @login_required
    @admin_required
    def admin_dashboard():
        users = User.query.order_by(User.name.asc()).all()
        poll_rows = (
            Poll.query.outerjoin(Vote)
            .add_columns(func.count(Vote.id).label("vote_count"))
            .group_by(Poll.id)
            .order_by(Poll.created_at.desc())
            .all()
        )
        polls = [{"poll": poll, "vote_count": vote_count} for poll, vote_count in poll_rows]
        return render_template("admin_dashboard.html", users=users, polls=polls)

    @app.post("/admin/users/<int:user_id>/toggle-freeze")
    @login_required
    @admin_required
    def toggle_user_freeze(user_id: int):
        target = User.query.get_or_404(user_id)
        if target.is_admin:
            flash("You cannot freeze an admin account.", "warning")
            return redirect(url_for("admin_dashboard"))
        target.is_frozen = not target.is_frozen
        db.session.commit()
        state = "frozen" if target.is_frozen else "unfrozen"
        flash(f"{target.name} has been {state}.", "success")
        return redirect(url_for("admin_dashboard"))

    @app.post("/admin/polls/<int:poll_id>/delete")
    @login_required
    @admin_required
    def admin_delete_poll(poll_id: int):
        poll = Poll.query.get_or_404(poll_id)
        delete_uploaded_file(poll.cover_image)
        for option in poll.options:
            delete_uploaded_file(option.image_path)
        db.session.delete(poll)
        db.session.commit()
        flash(f'The voting "{poll.title}" was removed.', "info")
        return redirect(url_for("admin_dashboard"))

    def _is_safe_upload_path(path: str) -> bool:
        if not path:
            return False
        normalized = path.replace("\\", "/")
        if ".." in normalized or normalized.startswith("/"):
            return False
        return normalized.startswith("uploads/")

    @app.post("/uploads/cover")
    @login_required
    def upload_cover_image():
        file = request.files.get("cover_image")
        if file is None or not file.filename:
            return {"error": "No file provided."}, 400
        previous_path = request.form.get("previous_path", "").strip()
        saved_path = save_uploaded_file(file)
        if saved_path is None:
            return {"error": "Invalid image type. Use PNG, JPG, JPEG, GIF, or WEBP."}, 400
        if _is_safe_upload_path(previous_path):
            delete_uploaded_file(previous_path)
        return {
            "path": saved_path,
            "url": url_for("static", filename=saved_path),
        }

    @app.post("/uploads/cover/delete")
    @login_required
    def delete_cover_image():
        data = request.get_json(silent=True) or {}
        path = data.get("path", "").strip()
        if not _is_safe_upload_path(path):
            return {"error": "Invalid path."}, 400
        delete_uploaded_file(path)
        return {"status": "ok"}

    @app.route("/")
    def index():
        base_query = Poll.query
        user = current_user()
        if user:
            base_query = base_query.filter(Poll.created_by != user.id)
        polls, pagination, sort_choice = build_poll_listing(base_query)
        return render_template(
            "index.html",
            polls=polls,
            pagination=pagination,
            sort_choice=sort_choice,
        )

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            password = request.form.get("password", "").strip()
            if not name or not password:
                flash("Name and password are required.", "danger")
            elif User.query.filter_by(name=name).first():
                flash("That name is already taken.", "danger")
            else:
                user = User(name=name)
                user.set_password(password)
                db.session.add(user)
                db.session.commit()
                flash("Registration successful. Please log in.", "success")
                return redirect(url_for("login"))
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            password = request.form.get("password", "").strip()
            user = User.query.filter_by(name=name).first()
            if user and user.check_password(password):
                session["user_id"] = user.id
                flash(f"Welcome back, {user.name}!", "success")
                next_url = request.args.get("next")
                return redirect(next_url or url_for("index"))
            flash("Invalid credentials. Try again.", "danger")
        return render_template("login.html")

    @app.route("/logout")
    @login_required
    def logout():
        session.pop("user_id", None)
        flash("Logged out successfully.", "info")
        return redirect(url_for("index"))

    @app.route("/profile", methods=["GET", "POST"])
    @login_required
    def profile():
        user = current_user()
        if request.method == "POST":
            profile_image_file = request.files.get("profile_image")
            if not profile_image_file or not profile_image_file.filename:
                flash("Please choose an image to upload.", "warning")
            else:
                image_path = save_uploaded_file(profile_image_file)
                if image_path is None:
                    flash(
                        "Profile image must be a PNG, JPG, JPEG, GIF, or WEBP file.",
                        "danger",
                    )
                else:
                    old_image = user.profile_image
                    user.profile_image = image_path
                    db.session.commit()
                    if old_image and old_image != image_path:
                        delete_uploaded_file(old_image)
                    flash("Profile updated successfully.", "success")
                    return redirect(url_for("profile"))
        return render_template("profile.html", user=user)

    @app.route("/polls/new", methods=["GET", "POST"])
    @login_required
    def new_poll():
        prefill_title = ""
        prefill_description = ""
        prefill_options = ["", ""]
        prefill_chat_enabled = True
        prefill_cover_image = ""

        if request.method == "POST":
            title = request.form.get("title", "").strip()
            description = request.form.get("description", "").strip()
            chat_enabled = request.form.get("chat_enabled") == "on"
            option_names = [
                opt.strip()
                for opt in request.form.getlist("options[]")
                if opt and opt.strip()
            ]
            if not option_names:
                # Fallback for legacy textarea submissions if any
                raw_options = request.form.get("options", "")
                option_names = [
                    opt.strip() for opt in raw_options.splitlines() if opt.strip()
                ]

            prefill_title = title
            prefill_description = description
            prefill_options = option_names or ["", ""]
            prefill_chat_enabled = chat_enabled
            while len(prefill_options) < 2:
                prefill_options.append("")

            cover_image_file = request.files.get("cover_image")
            uploaded_path = request.form.get("cover_image_path", "").strip()
            cover_image_path = ""
            if cover_image_file and cover_image_file.filename:
                cover_image_path = save_uploaded_file(cover_image_file)
                if cover_image_path is None:
                    prefill_cover_image = uploaded_path if _is_safe_upload_path(uploaded_path) else ""
                    flash(
                        "Cover image must be a PNG, JPG, JPEG, GIF, or WEBP file.",
                        "danger",
                    )
                    return render_template(
                        "new_poll.html",
                        prefill_title=prefill_title,
                        prefill_description=prefill_description,
                        prefill_options=prefill_options,
                        prefill_chat_enabled=prefill_chat_enabled,
                        prefill_cover_image=prefill_cover_image,
                    )
            elif uploaded_path:
                if _is_safe_upload_path(uploaded_path):
                    cover_image_path = uploaded_path
                else:
                    flash("Cover image reference is invalid. Please re-upload.", "danger")
                    return render_template(
                        "new_poll.html",
                        prefill_title=prefill_title,
                        prefill_description=prefill_description,
                        prefill_options=prefill_options,
                        prefill_chat_enabled=prefill_chat_enabled,
                        prefill_cover_image="",
                    )
            prefill_cover_image = cover_image_path

            if not title:
                flash("A title is required.", "danger")
            elif Poll.query.filter(func.lower(Poll.title) == title.lower()).first():
                flash("A voting with that title already exists. Please choose another.", "danger")
            elif len(option_names) < 2:
                flash("Please provide at least two categories.", "danger")
            else:
                poll = Poll(
                    title=title,
                    description=description,
                    created_by=current_user().id,
                    cover_image=cover_image_path,
                    chat_enabled=chat_enabled,
                )
                db.session.add(poll)
                db.session.flush()  # get poll.id before adding options

                for option_name in option_names:
                    db.session.add(Option(name=option_name, poll_id=poll.id))

                try:
                    db.session.commit()
                except IntegrityError:
                    db.session.rollback()
                    flash(
                        "A voting with that title already exists. Please choose another.",
                        "danger",
                    )
                else:
                    flash("Your voting poll is live!", "success")
                    return redirect(url_for("poll_detail", poll_id=poll.id))

        return render_template(
            "new_poll.html",
            prefill_title=prefill_title,
            prefill_description=prefill_description,
            prefill_options=prefill_options,
            prefill_chat_enabled=prefill_chat_enabled,
            prefill_cover_image=prefill_cover_image,
        )

    @app.route("/my-polls")
    @login_required
    def my_polls():
        user = current_user()
        base_query = Poll.query.filter_by(created_by=user.id)
        polls, pagination, sort_choice = build_poll_listing(base_query)
        return render_template(
            "my_polls.html",
            polls=polls,
            pagination=pagination,
            sort_choice=sort_choice,
        )

    @app.route("/polls/<int:poll_id>", methods=["GET", "POST"])
    @login_required
    def poll_detail(poll_id: int):
        poll = Poll.query.get_or_404(poll_id)
        user = current_user()
        vote = Vote.query.filter_by(poll_id=poll.id, user_id=user.id).first()
        is_owner = poll.created_by == user.id
        user_is_frozen = user.is_frozen

        if request.method == "POST":
            if user_is_frozen:
                flash("Your account is frozen. You can view polls but cannot vote or comment.", "danger")
                return redirect(url_for("poll_detail", poll_id=poll.id))
            action = request.form.get("action", "vote")
            if action == "vote":
                if is_owner:
                    flash("You cannot vote on your own voting.", "info")
                    return redirect(url_for("poll_detail", poll_id=poll.id))

                if vote:
                    flash("You already voted on this poll.", "info")
                    return redirect(url_for("poll_detail", poll_id=poll.id))

                option_id = request.form.get("option")
                option = Option.query.filter_by(id=option_id, poll_id=poll.id).first()
                if option is None:
                    flash("Invalid selection.", "danger")
                else:
                    new_vote = Vote(user_id=user.id, poll_id=poll.id, option_id=option.id)
                    db.session.add(new_vote)
                    db.session.commit()
                    flash("Thanks for voting! Here are the latest results.", "success")
                    return redirect(url_for("poll_detail", poll_id=poll.id))
            elif action == "message" and poll.chat_enabled:
                message_text = request.form.get("message", "").strip()
                if not message_text:
                    flash("Message cannot be empty.", "warning")
                elif not (is_owner or vote):
                    flash("Chat unlocks after you vote.", "warning")
                elif not is_message_allowed(message_text):
                    record_violation(user)
                    try:
                        db.session.commit()
                    except Exception:
                        db.session.rollback()
                    flash(
                        "Your message was blocked. Please keep the discussion positive and respectful.",
                        "danger",
                    )
                else:
                    message = Message(content=message_text, poll_id=poll.id, user_id=user.id)
                    db.session.add(message)
                    db.session.commit()

                return redirect(url_for("poll_detail", poll_id=poll.id))

        total_votes = Vote.query.filter_by(poll_id=poll.id).count()
        options_with_counts = [
            {
                "option": option,
                "count": Vote.query.filter_by(poll_id=poll.id, option_id=option.id).count(),
                "percentage": (
                    round(
                        100
                        * Vote.query.filter_by(poll_id=poll.id, option_id=option.id).count()
                        / total_votes,
                        2,
                    )
                    if total_votes
                    else 0
                ),
            }
            for option in poll.options
        ]

        can_vote = not is_owner and vote is None and not user_is_frozen
        can_view_results = is_owner or vote is not None

        messages = []
        if poll.chat_enabled and (is_owner or vote):
            messages = (
                Message.query.filter_by(poll_id=poll.id)
                .order_by(Message.created_at.asc())
                .all()
            )

        return render_template(
            "poll_detail.html",
            poll=poll,
            vote=vote,
            options_with_counts=options_with_counts,
            total_votes=total_votes,
            can_vote=can_vote,
            can_view_results=can_view_results,
            is_owner=is_owner,
            messages=messages,
            user_is_frozen=user_is_frozen,
        )

    @app.post("/polls/<int:poll_id>/comments/<int:comment_id>/delete")
    @login_required
    @admin_required
    def delete_comment(poll_id: int, comment_id: int):
        poll = Poll.query.get_or_404(poll_id)
        message = (
            Message.query.filter_by(id=comment_id, poll_id=poll.id).first_or_404()
        )
        db.session.delete(message)
        db.session.commit()
        flash("Comment deleted.", "info")
        return redirect(url_for("poll_detail", poll_id=poll.id))


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
