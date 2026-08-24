from flask import Blueprint, redirect

admin_bp = Blueprint("admin_bp", __name__)


@admin_bp.route("/admin")
def admin_home():
    return redirect("/")
