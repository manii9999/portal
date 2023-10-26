# myapp/models.py
from datetime import datetime
from sqlalchemy import event
from app.db import db
from flask_login import UserMixin
from sqlalchemy import Boolean, String
from sqlalchemy import Column, DateTime, func

class ShiftUpdate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime)
    shift_type = db.Column(db.String(255))
    done_in_shift = db.Column(db.String(255))
    update_to_next_shift = db.Column(db.String(255))
    alerts_handled = db.Column(db.String(255))
    actioned_alerts = db.Column(db.String(255))
    manual_restarts = db.Column(db.String(255))
    tasks = db.Column(db.String(255))
    resolved_tasks = db.Column(db.String(255))
    closed_tasks = db.Column(db.String(255))
    dev_requests_calls = db.Column(db.String(255))
    dev_requests_pi_calls = db.Column(db.String(255))
    dev_requests_debug_loggers = db.Column(db.String(255))
    dev_requests_noise = db.Column(db.String(255))
    dev_requests_jar_replace = db.Column(db.String(255))
    dev_requests_replicas = db.Column(db.String(255))
    dev_requests_threads = db.Column(db.String(255))
    db_queries_single = db.Column(db.String(255))
    db_queries_all_pods = db.Column(db.String(255))
    jira_so_tickets = db.Column(db.String(255))
    jira_ops_to_engg = db.Column(db.String(255))
    capacity_changes = db.Column(db.String(255))
    activity = db.Column(db.String(255))
    db_loads = db.Column(db.String(255))
    follow_ups = db.Column(db.String(255))
    shift_engineer = db.Column(db.String(255))

    def __init__(self, date, shift_type, done_in_shift, update_to_next_shift,
                 alerts_handled, actioned_alerts, manual_restarts, tasks, resolved_tasks, closed_tasks,
                 dev_requests_calls, dev_requests_pi_calls, dev_requests_debug_loggers, dev_requests_noise,
                 dev_requests_jar_replace, dev_requests_replicas, dev_requests_threads, db_queries_single,
                 db_queries_all_pods, jira_so_tickets, jira_ops_to_engg, capacity_changes, activity, db_loads,
                 follow_ups, shift_engineer):
        self.date = date
        self.shift_type = shift_type
        self.done_in_shift = done_in_shift
        self.update_to_next_shift = update_to_next_shift
        self.alerts_handled = alerts_handled
        self.actioned_alerts = actioned_alerts
        self.manual_restarts = manual_restarts
        self.tasks = tasks
        self.resolved_tasks = resolved_tasks
        self.closed_tasks = closed_tasks
        self.dev_requests_calls = dev_requests_calls
        self.dev_requests_pi_calls = dev_requests_pi_calls
        self.dev_requests_debug_loggers = dev_requests_debug_loggers
        self.dev_requests_noise = dev_requests_noise
        self.dev_requests_jar_replace = dev_requests_jar_replace
        self.dev_requests_replicas = dev_requests_replicas
        self.dev_requests_threads = dev_requests_threads
        self.db_queries_single = db_queries_single
        self.db_queries_all_pods = db_queries_all_pods
        self.jira_so_tickets = jira_so_tickets
        self.jira_ops_to_engg = jira_ops_to_engg
        self.capacity_changes = capacity_changes
        self.activity = activity
        self.db_loads = db_loads
        self.follow_ups = follow_ups
        self.shift_engineer = shift_engineer

    def __repr__(self):
        return f"ShiftUpdate('{self.date}', '{self.shift_type}')"


class CriticalUpdates(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False, default=datetime.today)
    duration = db.Column(db.String(50))
    category = db.Column(db.String(255))
    podname = db.Column(db.String(255))
    description = db.Column(db.Text)
    service_impacted = db.Column(db.String(255))
    reported_by = db.Column(db.String(255))
    updated_by = db.Column(db.String(255))


class User(UserMixin, db.Model):
#class User(db.Model):
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False)
    otp_secret = db.Column(db.String(16), nullable=True)
    login_time = db.Column(DateTime, server_default=func.now())

    def get_id(self):
        return str(self.id)



class Tracker(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date)
    shift = db.Column(db.String(255))
    count = db.Column(db.Integer)
    pod = db.Column(db.String(255))
    vm_host = db.Column(db.String(255))
    description = db.Column(db.String(255))
    application = db.Column(db.String(255))
    action_summary = db.Column(db.String(255))
    automation_manual = db.Column(db.String(255))
    shift_engineer = db.Column(db.String(255))

class InfraChanges(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pod = db.Column(db.String(50))
    node_names = db.Column(db.String(255))  # Store multiple node names as a comma-separated string
    change_description = db.Column(db.String(255))
    status = db.Column(db.String(20))
    jira = db.Column(db.String(20))
    date_of_change = db.Column(db.Date)
    approved_by = db.Column(db.String(50))
    category = db.Column(db.String(20))
    change_from = db.Column(db.String(20))
    change_to = db.Column(db.String(20))
    remarks = db.Column(db.Text)
class KnowledgeBase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(255), nullable=False)
    created_by = db.Column(db.String(255), nullable=False)
    created_on = db.Column(db.DateTime, default=datetime.utcnow)
    last_updated_by = db.Column(db.String(255), nullable=False)
    last_updated_on = db.Column(db.TIMESTAMP, server_default=db.func.now(), onupdate=db.func.now())

    def __init__(self, subject, description, category, created_by, last_updated_by, created_on, last_updated_on):
        self.subject = subject
        self.description = description
        self.category = category
        self.created_by = created_by
        self.created_on = created_on
        self.last_updated_by = last_updated_by
        self.last_updated_on = last_updated_on

class CommandCenter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date)
    category = db.Column(db.String(255))
    command = db.Column(db.Text)
    created_by = db.Column(db.String(255))
    usage = db.Column(db.String(255))

    def __init__(self, date, category, command, created_by, usage):
        self.date = date
        self.category = category
        self.command = command
        self.created_by = created_by
        self.usage = usage

class DebugLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    pod_name = db.Column(db.String(100), nullable=False)
    application = db.Column(db.String(100), nullable=False)
    node_names = db.Column(db.String(255), nullable=False)
    jira_id = db.Column(db.String(20), nullable=False)
    jira_status = db.Column(db.String(20), nullable=False)
    done_by = db.Column(db.String(100), nullable=False)
    closed_date = db.Column(db.Date, nullable=True)

    def __init__(self, date, pod_name, application, node_names, jira_id, jira_status, done_by, closed_date=closed_date):
        self.date = date
        self.pod_name = pod_name
        self.application = application
        self.node_names = node_names
        self.jira_id = jira_id
        self.jira_status = jira_status
        self.done_by = done_by
        self.closed_date = closed_date
    def on_changed_jira_status(target, value, oldvalue, initiator):
        if value == 'Closed' and value != oldvalue:
            target.closed_date = datetime.now().date()

event.listen(DebugLog.jira_status, 'set', DebugLog.on_changed_jira_status)

class Website(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    jira_id = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    expiry_date = db.Column(db.Date, nullable=False)
