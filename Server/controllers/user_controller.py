__copyright__ = "Copyright 2017. DePaul University. "
__license__ =  "All rights reserved. This work is distributed pursuant to the Software License for Community Contribution of Academic Work, dated Oct. 1, 2016. For terms and conditions, please see the license file, which is included in this distribution."
__author__ = "Ayadullah Syed, Jose Palacios, David Gorelik, Joshua Smith, Jasmine Farley, Jessica Hua, Steve Saucedo, Serafin Balcazar"

from Server import verboseFunc
from . import db
from . import SUCCESS, FAILURE
import bcrypt
import os


@verboseFunc
def login_user(connection, login_info):
    username = login_info['username']
    password = login_info['password']
    hashedpw = db.gethashedpw(username)
    print("THIS IS THE HASHED PW")
    print(hashedpw)
    if bcrypt.checkpw(password.encode('utf-8'), hashedpw.encode('utf-8')):
        password = hashedpw
        repo_id = db.login(username, password)
    else:
        repo_id = None

@verboseFunc
def register_user(register_info):
    username = register_info['username']
    password = register_info['password']
    password.encode('utf-8')
    sec_question = register_info["sec_question"]
    sec_answer = register_info["sec_answer"]

    print("Leaving RegisterHandler")
    repo_id = db.register(username, password, sec_question, sec_answer)
    print(repo_id)
    if repo_id:
        os.makedirs(
            os.path.normpath(
                os.path.join(
                    os.getcwd(),
                    'FILE_REPO',
                    username + '_personal_repo')))
    return repo_id
