from flask import Flask, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc
from flask_marshmallow import Marshmallow
from flask_restful import Api, Resource
import logging
import pdb

# Thanks rahmanfadhil. This is Based on https://github.com/rahmanfadhil/flask-rest-api/blob/master/main.py
# Migration:
#   (env) $ python3
#   >>> from pcontrol_api import DnsParentControlApi
#   >>> DnsParentControlApi.db.create_all()
#   >>> exit()

# Main Class
class DnsParentControlApi(object):
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/pcontrol.sqlite'
    db = SQLAlchemy(app)
    ma = Marshmallow(app)
    api = Api(app)
    msg_queue = None

    def __init__(self, queue):
        DnsParentControlApi.msg_queue = queue
        logging.info('[API][Info] Initialize: Starting %s', self.__class__.__name__)

    def run(self):
        # Do not run in debug=True
        # https://stackoverflow.com/questions/9449101/how-to-stop-flask-from-initialising-twice-in-debug-mode
        DnsParentControlApi.app.run(host='0.0.0.0', port='5000', debug=False)

# Database Models

class AccessLevel(DnsParentControlApi.db.Model):
    id = DnsParentControlApi.db.Column(DnsParentControlApi.db.Integer, primary_key=True)
    owner = DnsParentControlApi.db.Column(DnsParentControlApi.db.Text)
    device = DnsParentControlApi.db.Column(DnsParentControlApi.db.Text)
    ip_address = DnsParentControlApi.db.Column(DnsParentControlApi.db.Text)
    mac_address = DnsParentControlApi.db.Column(DnsParentControlApi.db.Text)
    level = DnsParentControlApi.db.Column(DnsParentControlApi.db.Integer, default=2)

    def __repr__(self):
        return '<AccessLevel %s>' % self.device

class AccessLevelSchema(DnsParentControlApi.ma.Schema):
    class Meta:
        fields = ("id", "owner", "device", "ip_address", "mac_address", "level")

access_level_schema = AccessLevelSchema()
access_levels_schema = AccessLevelSchema(many=True)

class DnsQuery(DnsParentControlApi.db.Model):
    id = DnsParentControlApi.db.Column(DnsParentControlApi.db.Integer, primary_key=True)
    dns_query_name = DnsParentControlApi.db.Column(DnsParentControlApi.db.Text)
    dns_query_ip = DnsParentControlApi.db.Column(DnsParentControlApi.db.Text)
    full_dns_alias_tree = DnsParentControlApi.db.Column(DnsParentControlApi.db.Text)
    level = DnsParentControlApi.db.Column(DnsParentControlApi.db.Integer, default=2)
    count = DnsParentControlApi.db.Column(DnsParentControlApi.db.Integer)
    DnsParentControlApi.db.UniqueConstraint(dns_query_name, dns_query_ip, name='uix_1')

    def __repr__(self):
        return '<DnsQuery %s>' % self.dns_query_name

class DnsQuerySchema(DnsParentControlApi.ma.Schema):
    class Meta:
        fields = ("id", "dns_query_name", "dns_query_ip", "full_dns_alias_tree", "level", "count")

dns_query_schema = DnsQuerySchema()
dns_queries_schema = DnsQuerySchema(many=True)

# API Controllers

class AcessLevelListResource(Resource):
    def get(self):
        levels = AccessLevel.query.all()
        return access_levels_schema.dump(levels)

    def post(self):
        new_level = AccessLevel(
            owner=request.json['owner'],
            device=request.json['device'],
            ip_address=request.json['ip_address'],
            mac_address=request.json['mac_address'],
            level=request.json['level']
        )
        DnsParentControlApi.db.session.add(new_level)
        DnsParentControlApi.db.session.commit()
        return access_level_schema.dump(new_level)

class AccessLevelResource(Resource):
    def get(self, id):
        level = AccessLevel.query.get_or_404(id)
        return access_level_schema.dump(level)

    def patch(self, id):
        level = AccessLevel.query.get_or_404(id)

        if 'owner' in request.json:
            level.owner = request.json['owner']
        if 'device' in request.json:
            level.device = request.json['device']    
        if 'ip_address' in request.json:
            level.ip_address = request.json['ip_address']
        if 'mac_address' in request.json:
            level.mac_address = request.json['mac_address']
        if 'level' in request.json:
            level.level = request.json['level']

        DnsParentControlApi.db.session.commit()

        if not (DnsParentControlApi.msg_queue is None):
            logging.info('[API][Info] access level modified <owner=%s,device=%s,level=%s>',
                level.owner,level.device,level.level)
            DnsParentControlApi.msg_queue.put({"action": "clean_access_level_cache"})
            DnsParentControlApi.msg_queue.put({"action": "clean_runtime_cache"})
                 
        return access_level_schema.dump(level)

    def delete(self, level_id):
        level = AccessLevel.query.get_or_404(level_id)
        DnsParentControlApi.db.session.delete(level)
        DnsParentControlApi.db.session.commit()
        return '', 204

class DnsQueryListResource(Resource):
    def get(self):
        dns_names = DnsQuery.query.all()
        return dns_queries_schema.dump(dns_names)

    def post(self):
        new_dns_name = DnsQuery(
            dns_query_name=request.json['dns_query_name'],
            dns_query_ip=request.json['dns_query_ip'],
            full_dns_alias_tree=request.json['full_dns_alias_tree'],
            level=request.json['level'],
            count=request.json['count']
        )
        # DnsParentControlApi.db.session.add(new_dns_name)
        # DnsParentControlApi.db.session.commit()
        # return dns_query_schema.dump(new_dns_name)
        try:
            DnsParentControlApi.db.session.add(new_dns_name)
            DnsParentControlApi.db.session.commit()
            return dns_query_schema.dump(new_dns_name)
        except exc.IntegrityError:
            # Record already exists
            return None

class DnsQueryResource(Resource):
    def delete(self, dns_query_ip):
        dns_name = DnsQuery.query.filter_by(dns_query_ip=dns_query_ip).first_or_404()
        DnsParentControlApi.db.session.delete(dns_name)
        DnsParentControlApi.db.session.commit()
        return '', 204

# Routes

# Got it from 
#   https://github.com/cabreraalex/svelte-flask-example/blob/master/server.py
#   https://medium.com/@cabreraalex/svelte-js-flask-combining-svelte-with-a-simple-backend-server-d1bc46190ab9
# Path for our main Svelte page
@DnsParentControlApi.app.route("/")
def base():
    return send_from_directory('client/public', 'index.html')

# Path for all the static files (compiled JS/CSS, etc.)
@DnsParentControlApi.app.route("/<path:path>")
def home(path):
    return send_from_directory('client/public', path)

DnsParentControlApi.api.add_resource(AcessLevelListResource, '/devices')
DnsParentControlApi.api.add_resource(AccessLevelResource, '/devices/<int:id>')
DnsParentControlApi.api.add_resource(DnsQueryListResource, '/dns-names')
DnsParentControlApi.api.add_resource(DnsQueryResource, '/dns-names/<string:dns_query_ip>')

# Main
# if __name__ == '__main__':
#     DnsParentControlApi(None).run()
