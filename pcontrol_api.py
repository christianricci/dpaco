from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_restful import Api, Resource

# Thanks rahmanfadhil. This is Based on https://github.com/rahmanfadhil/flask-rest-api/blob/master/main.py
# Migration:
#   (env) $ python3
#   >>> from pcontrol_api import DnsParentControlApi
#   >>> DnsParentControlApi.db.create_all()
#   >>> exit()

class DnsParentControlApi:
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/pcontrol.sqlite'
    db = SQLAlchemy(app)
    ma = Marshmallow(app)
    api = Api(app)

# Database Models

class AccessLevel(DnsParentControlApi.db.Model):
    id = DnsParentControlApi.db.Column(DnsParentControlApi.db.Integer, primary_key=True)
    owner = DnsParentControlApi.db.Column(DnsParentControlApi.db.Text)
    device = DnsParentControlApi.db.Column(DnsParentControlApi.db.Text)
    ip_address = DnsParentControlApi.db.Column(DnsParentControlApi.db.Text)
    mac_address = DnsParentControlApi.db.Column(DnsParentControlApi.db.Text)
    level = DnsParentControlApi.db.Column(DnsParentControlApi.db.Integer, default=2)

    def __repr__(self):
        return '<AccessLevel %s>' % self.description

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
    DnsParentControlApi.db.UniqueConstraint(dns_query_name, dns_query_ip, name='uix_1')

    def __repr__(self):
        return '<DnsQuery %s>' % self.description

class DnsQuerySchema(DnsParentControlApi.ma.Schema):
    class Meta:
        fields = ("id", "dns_query_name", "dns_query_ip", "full_dns_alias_tree", "level")

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
    def get(self, level_id):
        level = AccessLevel.query.get_or_404(level_id)
        return access_level_schema.dump(level)

    def patch(self, level_id):
        level = AccessLevel.query.get_or_404(level_id)

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
        return access_level_schema.dump(level)

    def delete(self, level_id):
        level = AccessLevel.query.get_or_404(level_id)
        level.delete()
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
            level=request.json['level']
        )
        DnsParentControlApi.db.session.add(new_dns_name)
        DnsParentControlApi.db.session.commit()
        return dns_query_schema.dump(new_dns_name)

# Routes

DnsParentControlApi.api.add_resource(AcessLevelListResource, '/devices')
DnsParentControlApi.api.add_resource(AccessLevelResource, '/devices/<int:host_id>')
DnsParentControlApi.api.add_resource(DnsQueryListResource, '/dns-names')

# main

if __name__ == '__main__':
    DnsParentControlApi.app.run(host='0.0.0.0',debug=True)