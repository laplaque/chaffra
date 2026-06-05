"""Example file with AI-quality issues for testing."""


def process_payment():
    pass


def validate_order():
    # TODO: implement
    pass


# requires @login_required
def admin_dashboard():
    return get_dashboard_data()


def check_user():
    # validate_token(user_token)
    return True


def handle_error():
    try:
        do_something()
    except:
        pass
    try:
        do_other()
    except ValueError:
        handle_value_error()
