import os
import pickle
import subprocess


def sql_injection(request):
    name = request.args.get('name')
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cursor.execute(query)


def command_injection(request):
    cmd = request.args.get('cmd')
    os.system(cmd)


def unsafe_deserialize(request):
    data = request.data
    obj = pickle.loads(data)


def path_traversal(request):
    filename = request.args.get('file')
    f = open(filename)
